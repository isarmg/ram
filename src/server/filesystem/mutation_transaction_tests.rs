use super::{
    CandidateCleanup, DirectorySyncPoint, EntryExpectation, MutationOps, NodeKind, RootFs,
    WalkAction, drain_candidate_cleanup, post_publish_directory_lookup_error,
    sync_renamed_parents_with, unavailable_capability_entry,
};
use crate::server::error::{AdmissionError, DurabilityStage, FsError, MutationEndpointRole};
use crate::server::walk::RequestCancellation;
use crate::server::{MutationGuards, MutationIntent, is_internal_temp_name};
use anyhow::{Context, Result};
use assert_fs::TempDir;
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

fn empty_guards() -> MutationGuards {
    MutationGuards::new(Vec::new())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptedEvent {
    CandidateWrite,
    CandidateFlush,
    CandidateDataSync,
    NamespaceMkdir,
    NamespaceUnlink { directory: bool },
    NamespaceRename { no_replace: bool },
    PublishedChmod,
    PublishedFileSync,
    DirectorySync(DirectorySyncPoint),
}

#[derive(Default)]
struct ScriptedOps {
    events: Vec<ScriptedEvent>,
    fail: Option<ScriptedEvent>,
    probe_candidate_lock_on_rename_failure: bool,
    candidate_lock_was_held: bool,
}

impl ScriptedOps {
    fn failing(event: ScriptedEvent) -> Self {
        Self {
            events: Vec::new(),
            fail: Some(event),
            probe_candidate_lock_on_rename_failure: false,
            candidate_lock_was_held: false,
        }
    }

    fn failing_candidate_rename() -> Self {
        Self {
            probe_candidate_lock_on_rename_failure: true,
            ..Self::failing(ScriptedEvent::NamespaceRename { no_replace: true })
        }
    }

    fn before(&mut self, event: ScriptedEvent) -> std::result::Result<(), Errno> {
        self.events.push(event);
        if self.fail == Some(event) {
            Err(Errno::IO)
        } else {
            Ok(())
        }
    }

    fn before_io(&mut self, event: ScriptedEvent) -> io::Result<()> {
        self.before(event)
            .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))
    }
}

impl MutationOps for ScriptedOps {
    fn write_candidate(&mut self, file: &mut File, data: &[u8]) -> io::Result<()> {
        self.before_io(ScriptedEvent::CandidateWrite)?;
        file.write_all(data)
    }

    fn flush_candidate(&mut self, file: &mut File) -> io::Result<()> {
        self.before_io(ScriptedEvent::CandidateFlush)?;
        std::io::Write::flush(file)
    }

    fn sync_candidate_data(&mut self, file: &File) -> io::Result<()> {
        self.before_io(ScriptedEvent::CandidateDataSync)?;
        file.sync_data()
    }

    fn mkdir(&mut self, parent: &File, name: &OsStr, mode: Mode) -> std::result::Result<(), Errno> {
        self.before(ScriptedEvent::NamespaceMkdir)?;
        rustix::fs::mkdirat(parent, name, mode)
    }

    fn unlink(
        &mut self,
        parent: &File,
        name: &OsStr,
        flags: AtFlags,
    ) -> std::result::Result<(), Errno> {
        self.before(ScriptedEvent::NamespaceUnlink {
            directory: flags.contains(AtFlags::REMOVEDIR),
        })?;
        rustix::fs::unlinkat(parent, name, flags)
    }

    fn rename(
        &mut self,
        source_parent: &File,
        source_name: &OsStr,
        destination_parent: &File,
        destination_name: &OsStr,
        no_replace: bool,
    ) -> std::result::Result<(), Errno> {
        let before = self.before(ScriptedEvent::NamespaceRename { no_replace });
        if before.is_err() && self.probe_candidate_lock_on_rename_failure {
            let competing: File = rustix::fs::openat(
                source_parent,
                source_name,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            self.candidate_lock_was_held = matches!(
                flock(&competing, FlockOperation::NonBlockingLockExclusive),
                Err(Errno::WOULDBLOCK)
            );
        }
        before?;
        if no_replace {
            rustix::fs::renameat_with(
                source_parent,
                source_name,
                destination_parent,
                destination_name,
                RenameFlags::NOREPLACE,
            )
        } else {
            rustix::fs::renameat(
                source_parent,
                source_name,
                destination_parent,
                destination_name,
            )
        }
    }

    fn chmod_published(&mut self, file: &File, mode: Mode) -> std::result::Result<(), Errno> {
        self.before(ScriptedEvent::PublishedChmod)?;
        rustix::fs::fchmod(file, mode)
    }

    fn sync_published_file(&mut self, file: &File) -> io::Result<()> {
        self.before_io(ScriptedEvent::PublishedFileSync)?;
        file.sync_all()
    }

    fn sync_directory(
        &mut self,
        directory: &File,
        point: DirectorySyncPoint,
    ) -> std::result::Result<(), Errno> {
        self.before(ScriptedEvent::DirectorySync(point))?;
        rustix::fs::fsync(directory)
    }
}

fn assert_durability(error: &anyhow::Error, stage: DurabilityStage, published: bool) {
    assert!(
        matches!(
            FsError::in_anyhow_chain(error),
            Some(FsError::Durability {
                stage: actual_stage,
                published: actual_published,
                ..
            }) if *actual_stage == stage && *actual_published == published
        ),
        "unexpected durability classification: {error:#}"
    );
}

#[test]
fn scripted_put_commit_orders_real_publication() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
    let mut ops = ScriptedOps::default();
    candidate.write_all_with_ops(b"published content", &mut ops)?;
    candidate.commit_with_ops(
        EntryExpectation::Missing,
        0o640,
        &RequestCancellation::new(),
        &mut ops,
    )?;

    assert_eq!(
        std::fs::read(directory.path().join("target.bin"))?,
        b"published content"
    );
    assert_eq!(
        ops.events,
        vec![
            ScriptedEvent::CandidateWrite,
            ScriptedEvent::CandidateFlush,
            ScriptedEvent::CandidateDataSync,
            ScriptedEvent::NamespaceRename { no_replace: true },
            ScriptedEvent::PublishedChmod,
            ScriptedEvent::PublishedFileSync,
            ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
        ]
    );
    Ok(())
}

#[test]
fn scripted_put_prepublish_failures_clean_candidate_ancestors_with_lock_held() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
    let mut ops = ScriptedOps::failing(ScriptedEvent::CandidateWrite);
    let error = candidate
        .write_all_with_ops(b"candidate", &mut ops)
        .unwrap_err();
    assert_durability(&error, DurabilityStage::CandidateFile, false);
    drop(candidate);
    assert!(drain_candidate_cleanup(std::time::Duration::from_secs(2)));
    assert!(
        !directory.path().join("one").exists(),
        "candidate-write failure left a temporary file or auto-created parent"
    );

    for failure in [
        ScriptedEvent::CandidateFlush,
        ScriptedEvent::CandidateDataSync,
    ] {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
        candidate.write_all(b"candidate")?;
        let mut ops = ScriptedOps::failing(failure);
        let error = candidate
            .commit_with_ops(
                EntryExpectation::Missing,
                0o640,
                &RequestCancellation::new(),
                &mut ops,
            )
            .unwrap_err();
        assert_durability(&error, DurabilityStage::CandidateFile, false);
        assert!(!directory.path().join("one").exists());
    }

    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
    candidate.write_all(b"candidate")?;
    let mut ops = ScriptedOps::failing_candidate_rename();
    let error = candidate
        .commit_with_ops(
            EntryExpectation::Missing,
            0o640,
            &RequestCancellation::new(),
            &mut ops,
        )
        .unwrap_err();
    assert!(
        FsError::in_anyhow_chain(&error)
            .is_none_or(|error| !matches!(error, FsError::Durability { .. })),
        "prepublication rename failure was mislabeled as durability: {error:#}"
    );
    assert!(
        ops.candidate_lock_was_held,
        "candidate flock was released before the injected rename failure"
    );
    assert!(drain_candidate_cleanup(std::time::Duration::from_secs(2)));
    assert!(!directory.path().join("one").exists());
    Ok(())
}

#[test]
fn scripted_put_postpublish_failures_keep_visible_target_and_marker() -> Result<()> {
    for (failure, expected_stage) in [
        (
            ScriptedEvent::PublishedFileSync,
            DurabilityStage::PublishedFile,
        ),
        (
            ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
            DurabilityStage::DestinationParent,
        ),
    ] {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
        candidate.write_all(b"published despite sync failure")?;
        let mut ops = ScriptedOps::failing(failure);
        let error = candidate
            .commit_with_ops(
                EntryExpectation::Missing,
                0o640,
                &RequestCancellation::new(),
                &mut ops,
            )
            .unwrap_err();
        assert_durability(&error, expected_stage, true);
        assert_eq!(
            std::fs::read(directory.path().join("target.bin"))?,
            b"published despite sync failure"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())?.count(),
            1,
            "post-publication sync failure left a private candidate"
        );
    }
    Ok(())
}

fn expected_namespace_race(error: &anyhow::Error) -> bool {
    matches!(
        FsError::in_anyhow_chain(error),
        Some(
            FsError::NotFound { .. }
                | FsError::Conflict { .. }
                | FsError::OutsideRoot { .. }
                | FsError::Changed { .. }
        )
    )
}

/// 能力边界的有界并发回归：外部命名空间变更器反复重命名/替换服务名称并指向同级秘密，
/// 同时 RootFs 并发读取和原子写入。成功读取只能观察完整安全版本，任何写入都不得到达
/// 同级目标。
/// Bounded concurrency regression for the capability boundary. An external mutator repeatedly
/// replaces the served name with a sibling secret during RootFs reads/writes. Reads see only
/// complete safe generations and writes never reach the sibling.
#[test]
fn concurrent_rename_symlink_replace_reads_and_writes_stay_beneath_root() -> Result<()> {
    const MUTATIONS: usize = 160;
    const READS: usize = 320;
    const WRITES: usize = 160;
    const DEADLINE: Duration = Duration::from_secs(10);

    let sandbox = TempDir::new()?;
    let served = sandbox.path().join("served");
    std::fs::create_dir(&served)?;
    let slot = served.join("slot");
    let held = served.join("held");
    let outside = sandbox.path().join("outside-secret");
    std::fs::write(&slot, b"safe-initial")?;
    std::fs::write(&outside, b"outside-secret-must-never-be-read-or-written")?;

    let root = RootFs::new(&served, false, false)?;
    let barrier = Arc::new(Barrier::new(4));
    let stop = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel::<(&'static str, std::result::Result<(), String>)>();

    std::thread::scope(|scope| -> Result<()> {
        let mutator_barrier = barrier.clone();
        let mutator_stop = stop.clone();
        let mutator_done = done_tx.clone();
        let mutator_slot = slot.clone();
        let mutator_held = held.clone();
        let mutator_outside = outside.clone();
        let mutator_served = served.clone();
        let mutator = scope.spawn(move || {
            mutator_barrier.wait();
            let result = (|| -> Result<()> {
                for generation in 0..MUTATIONS {
                    if mutator_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let _ = std::fs::remove_file(&mutator_held);
                    let _ = std::fs::rename(&mutator_slot, &mutator_held);
                    match symlink(&mutator_outside, &mutator_slot) {
                        Ok(()) => std::thread::yield_now(),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::AlreadyExists | io::ErrorKind::NotFound
                            ) => {}
                        Err(error) => return Err(error.into()),
                    }
                    let _ = std::fs::remove_file(&mutator_slot);
                    if std::fs::rename(&mutator_held, &mutator_slot).is_err() {
                        let replacement = mutator_served.join(format!("replacement-{generation}"));
                        std::fs::write(&replacement, format!("safe-{generation:03}"))?;
                        let _ = std::fs::rename(&replacement, &mutator_slot);
                        let _ = std::fs::remove_file(replacement);
                    }
                }
                Ok(())
            })()
            .map_err(|error| format!("{error:#}"));
            let _ = mutator_done.send(("mutator", result));
        });

        let reader_barrier = barrier.clone();
        let reader_stop = stop.clone();
        let reader_done = done_tx.clone();
        let reader_root = root.clone();
        let reader = scope.spawn(move || {
            reader_barrier.wait();
            let result = (|| -> Result<()> {
                for _ in 0..READS {
                    if reader_stop.load(Ordering::Acquire) {
                        break;
                    }
                    match reader_root.open_raw(Path::new("slot"), NodeKind::File) {
                        Ok(mut file) => {
                            let mut body = Vec::new();
                            std::io::Read::by_ref(&mut file)
                                .take(128)
                                .read_to_end(&mut body)?;
                            assert!(
                                body == b"safe-initial"
                                    || body.starts_with(b"safe-")
                                    || body.starts_with(b"writer-"),
                                "capability read unexpected bytes: {:?}",
                                String::from_utf8_lossy(&body)
                            );
                        }
                        Err(error) if expected_namespace_race(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            })()
            .map_err(|error| format!("{error:#}"));
            let _ = reader_done.send(("reader", result));
        });

        let writer_barrier = barrier.clone();
        let writer_stop = stop.clone();
        let writer_done = done_tx.clone();
        let writer_root = root.clone();
        let writer = scope.spawn(move || {
            writer_barrier.wait();
            let result = (|| -> Result<()> {
                for generation in 0..WRITES {
                    if writer_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let expected = match writer_root.entry_expectation_sync(Path::new("slot")) {
                        Ok(expected) => expected,
                        Err(error) if expected_namespace_race(&error) => continue,
                        Err(error) => return Err(error),
                    };
                    let mut candidate = writer_root.create_blocking_temp("slot", false, 0o700)?;
                    candidate.write_all(format!("writer-{generation:03}").as_bytes())?;
                    if let Err(error) =
                        candidate.commit(expected, 0o600, &RequestCancellation::new())
                        && !expected_namespace_race(&error)
                    {
                        return Err(error);
                    }
                }
                Ok(())
            })()
            .map_err(|error| format!("{error:#}"));
            let _ = writer_done.send(("writer", result));
        });

        barrier.wait();
        drop(done_tx);
        let mut failures = Vec::new();
        for _ in 0..3 {
            match done_rx.recv_timeout(DEADLINE) {
                Ok((_name, Ok(()))) => {}
                Ok((name, Err(error))) => failures.push(format!("{name}: {error}")),
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    failures.push(format!("stress worker exceeded {DEADLINE:?}: {error}"));
                    break;
                }
            }
        }
        stop.store(true, Ordering::Release);
        for (name, result) in [
            ("mutator", mutator.join()),
            ("reader", reader.join()),
            ("writer", writer.join()),
        ] {
            if result.is_err() {
                failures.push(format!("{name} panicked"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
        Ok(())
    })?;

    assert!(drain_candidate_cleanup(Duration::from_secs(2)));
    assert_eq!(
        std::fs::read(&outside)?,
        b"outside-secret-must-never-be-read-or-written"
    );
    for entry in std::fs::read_dir(&served)? {
        let name = entry?.file_name();
        if let Some(name) = name.to_str() {
            assert!(!is_internal_temp_name(name), "leaked candidate {name}");
        }
    }
    Ok(())
}

#[test]
fn scripted_mkcol_sync_order_and_failures_preserve_rollback() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut ops = ScriptedOps::default();
    root.mkdir_sync_with_ops(Path::new("collection"), 0o710, &mut ops)?;
    assert!(directory.path().join("collection").is_dir());
    assert_eq!(
        ops.events,
        vec![
            ScriptedEvent::NamespaceMkdir,
            ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectory),
            ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectoryParent),
        ]
    );

    let failed_mkdir_root = TempDir::new()?;
    let root = RootFs::new(failed_mkdir_root.path(), false, false)?;
    let mut ops = ScriptedOps::failing(ScriptedEvent::NamespaceMkdir);
    let error = root
        .mkdir_sync_with_ops(Path::new("collection"), 0o710, &mut ops)
        .unwrap_err();
    assert!(FsError::in_anyhow_chain(&error).is_none());
    assert!(!failed_mkdir_root.path().join("collection").exists());

    for failure in [
        ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectory),
        ScriptedEvent::DirectorySync(DirectorySyncPoint::CreatedDirectoryParent),
    ] {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let mut ops = ScriptedOps::failing(failure);
        let error = root
            .mkdir_sync_with_ops(Path::new("collection"), 0o710, &mut ops)
            .unwrap_err();
        assert_durability(&error, DurabilityStage::CreatedDirectory, true);
        assert!(
            !directory.path().join("collection").exists(),
            "failed MKCOL did not roll back its exact new directory"
        );
    }
    Ok(())
}

#[test]
fn scripted_delete_syncs_file_and_directory_and_marks_postunlink_failure() -> Result<()> {
    for (name, directory_entry) in [("file", false), ("collection", true)] {
        let directory = TempDir::new()?;
        if directory_entry {
            std::fs::create_dir(directory.path().join(name))?;
        } else {
            std::fs::write(directory.path().join(name), b"content")?;
        }
        let root = RootFs::new(directory.path(), false, false)?;
        let expected = root.entry_expectation_sync(Path::new(name))?;
        let mut ops = ScriptedOps::default();
        root.remove_sync_with_ops(
            Path::new(name),
            false,
            expected,
            8,
            8,
            &RequestCancellation::new(),
            &mut ops,
            |_| {},
        )?;
        assert!(!directory.path().join(name).exists());
        assert_eq!(
            ops.events,
            vec![
                ScriptedEvent::NamespaceUnlink {
                    directory: directory_entry,
                },
                ScriptedEvent::DirectorySync(DirectorySyncPoint::RemovedEntryParent),
            ]
        );
    }

    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("file"), b"content")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected = root.entry_expectation_sync(Path::new("file"))?;
    let mut ops = ScriptedOps::failing(ScriptedEvent::NamespaceUnlink { directory: false });
    let error = root
        .remove_sync_with_ops(
            Path::new("file"),
            false,
            expected,
            8,
            8,
            &RequestCancellation::new(),
            &mut ops,
            |_| {},
        )
        .unwrap_err();
    assert!(FsError::in_anyhow_chain(&error).is_none());
    assert_eq!(std::fs::read(directory.path().join("file"))?, b"content");

    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("file"), b"content")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected = root.entry_expectation_sync(Path::new("file"))?;
    let mut ops = ScriptedOps::failing(ScriptedEvent::DirectorySync(
        DirectorySyncPoint::RemovedEntryParent,
    ));
    let error = root
        .remove_sync_with_ops(
            Path::new("file"),
            false,
            expected,
            8,
            8,
            &RequestCancellation::new(),
            &mut ops,
            |_| {},
        )
        .unwrap_err();
    assert_durability(&error, DurabilityStage::RemovedEntryParent, true);
    assert!(!directory.path().join("file").exists());
    Ok(())
}

#[test]
fn scripted_move_attempts_cross_parent_syncs_and_rolls_back_before_rename() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::create_dir(directory.path().join("source-parent"))?;
    std::fs::create_dir(directory.path().join("destination-parent"))?;
    std::fs::write(
        directory.path().join("source-parent/source"),
        b"move content",
    )?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected_source = root.entry_expectation_sync(Path::new("source-parent/source"))?;
    let mut ops = ScriptedOps::failing(ScriptedEvent::DirectorySync(
        DirectorySyncPoint::DestinationParent,
    ));
    let error = root
        .rename_sync_with_ops(
            Path::new("source-parent/source"),
            Path::new("destination-parent/destination"),
            false,
            expected_source,
            EntryExpectation::Missing,
            &mut ops,
        )
        .unwrap_err();
    assert_durability(&error, DurabilityStage::DestinationParent, true);
    assert_eq!(
        ops.events,
        vec![
            ScriptedEvent::NamespaceRename { no_replace: true },
            ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
            ScriptedEvent::DirectorySync(DirectorySyncPoint::SourceParent),
        ]
    );
    assert!(!directory.path().join("source-parent/source").exists());
    assert_eq!(
        std::fs::read(directory.path().join("destination-parent/destination"))?,
        b"move content"
    );

    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("source"), b"source remains")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected_source = root.entry_expectation_sync(Path::new("source"))?;
    let mut ops = ScriptedOps::failing(ScriptedEvent::NamespaceRename { no_replace: true });
    let error = root
        .rename_sync_with_ops(
            Path::new("source"),
            Path::new("new/parent/destination"),
            true,
            expected_source,
            EntryExpectation::Missing,
            &mut ops,
        )
        .unwrap_err();
    assert!(
        FsError::in_anyhow_chain(&error)
            .is_none_or(|error| !matches!(error, FsError::Durability { .. }))
    );
    assert_eq!(
        std::fs::read(directory.path().join("source"))?,
        b"source remains"
    );
    assert!(!directory.path().join("new").exists());

    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("source"), b"same parent")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected_source = root.entry_expectation_sync(Path::new("source"))?;
    let mut ops = ScriptedOps::default();
    root.rename_sync_with_ops(
        Path::new("source"),
        Path::new("destination"),
        false,
        expected_source,
        EntryExpectation::Missing,
        &mut ops,
    )?;
    assert_eq!(
        ops.events,
        vec![
            ScriptedEvent::NamespaceRename { no_replace: true },
            ScriptedEvent::DirectorySync(DirectorySyncPoint::DestinationParent),
        ]
    );
    Ok(())
}

#[test]
fn post_mkdir_lookup_failures_never_degrade_to_not_found_or_forbidden() {
    for errno in [
        rustix::io::Errno::NOENT,
        rustix::io::Errno::NOTDIR,
        rustix::io::Errno::LOOP,
        rustix::io::Errno::XDEV,
    ] {
        let error = post_publish_directory_lookup_error(
            Path::new("new/directory"),
            "published directory",
            "fault-injected lookup",
            errno,
        );
        assert!(
            matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::Changed {
                    role: MutationEndpointRole::Target,
                    ..
                })
            ),
            "namespace race errno {errno} was not Changed: {error:#}"
        );
    }

    for errno in [rustix::io::Errno::ACCESS, rustix::io::Errno::IO] {
        let error = post_publish_directory_lookup_error(
            Path::new("new/directory"),
            "published directory",
            "fault-injected lookup",
            errno,
        );
        assert!(
            matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::Durability {
                    published: true,
                    ..
                })
            ),
            "infrastructure errno {errno} was not published durability: {error:#}"
        );
    }
}

#[test]
fn mutation_helpers_preserve_closed_outside_root_and_changed_markers() -> Result<()> {
    let served = TempDir::new()?;
    let outside = TempDir::new()?;
    let root = RootFs::new(served.path(), false, true)?;
    symlink(outside.path(), served.path().join("escape"))?;

    for error in [
        root.entry_expectation_sync(Path::new("escape/new.bin"))
            .expect_err("escaping expectation parent must fail"),
        root.entry_size_nofollow(Path::new("escape/new.bin"))
            .expect_err("escaping size parent must fail"),
        root.ensure_dir_sync(Path::new("escape/new"), 0o700)
            .err()
            .expect("escaping ancestor creation must fail"),
        root.resolve_mutation_locks_sync(&[MutationIntent::write("escape/new.bin")])
            .expect_err("escaping lock prefix must fail"),
    ] {
        assert!(
            matches!(
                FsError::in_anyhow_chain(&error),
                Some(FsError::OutsideRoot { .. })
            ),
            "closed OutsideRoot marker was overwritten: {error:#}"
        );
    }
    assert!(
        !outside.path().join("new").exists(),
        "ensure_dir_sync created outside the served capability"
    );

    std::fs::create_dir(served.path().join("parent"))?;
    let parent = root.open_parent_sync(Path::new("parent/file.bin"), false)?;
    std::fs::rename(
        served.path().join("parent"),
        served.path().join("replaced-parent"),
    )?;
    symlink(outside.path(), served.path().join("parent"))?;
    let error = root
        .verify_parent_with_role(&parent, MutationEndpointRole::Destination)
        .expect_err("replaced mutation parent must fail");
    assert!(
        matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed {
                role: MutationEndpointRole::Destination,
                ..
            })
        ),
        "parent namespace replacement was reclassified: {error:#}"
    );
    Ok(())
}

#[test]
fn traversal_skips_only_closed_unavailable_names_not_permission_or_io_failures() {
    let not_found = anyhow::Error::new(FsError::from_anyhow(
        "opening traversal entry",
        anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound)),
    ));
    let outside = anyhow::Error::new(FsError::outside_root(
        "opening traversal entry",
        anyhow::anyhow!("link target is outside the authorized traversal root"),
    ));
    assert!(unavailable_capability_entry(&not_found));
    assert!(unavailable_capability_entry(&outside));

    let forbidden = anyhow::Error::new(FsError::from_anyhow(
        "opening traversal entry",
        anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
    ));
    let io = anyhow::Error::new(FsError::io(
        "opening traversal entry",
        std::io::Error::other("injected device failure"),
    ));
    assert!(
        !unavailable_capability_entry(&forbidden),
        "EACCES must abort search/archive instead of returning a partial 200"
    );
    assert!(
        !unavailable_capability_entry(&io),
        "I/O failures must abort search/archive instead of returning a partial 200"
    );
}

#[test]
fn real_traversal_io_failure_aborts_instead_of_returning_partial_success() -> Result<()> {
    let served = TempDir::new()?;
    std::fs::write(served.path().join("ordinary.txt"), b"visible")?;
    let socket_path = served.path().join("unopenable.sock");
    let _socket = UnixListener::bind(&socket_path).with_context(|| {
        let mode = std::fs::metadata(served.path())
            .map(|metadata| format!("{:04o}", metadata.mode() & 0o7777))
            .unwrap_or_else(|_| "unavailable".to_owned());
        let umask = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|line| line.starts_with("Umask:"))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "Umask: unavailable".to_owned());
        format!(
            "AF_UNIX traversal fixture bind failed for `{}` (parent mode {mode}; {umask})",
            socket_path.display()
        )
    })?;
    let root = RootFs::new(served.path(), false, false)?;
    let running = AtomicBool::new(true);
    let cancelled = AtomicBool::new(false);
    let error = root
        .walk(vec![PathBuf::new()], &running, &cancelled, 32, 4, |_| {
            Ok(WalkAction::Continue)
        })
        .expect_err("a Unix socket cannot be opened as file content");
    assert!(
        matches!(FsError::in_anyhow_chain(&error), Some(FsError::Io { .. })),
        "real traversal I/O failure was silently skipped or reclassified: {error:#}"
    );
    Ok(())
}

#[test]
fn candidate_parent_depth_cannot_exceed_recovery_scan_depth() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::create_dir_all(directory.path().join("one/two/three"))?;
    let identity = crate::identity::ServedPathIdentity::capture(directory.path(), false)?;
    let root = RootFs::from_verified_identity_with_candidate_cleanup(&identity, false, false, 2)?;

    let at_boundary = root.create_blocking_temp("one/two/file.bin", false, 0o700)?;
    drop(at_boundary);

    let error = match root.create_blocking_temp("one/two/three/file.bin", false, 0o700) {
        Ok(_) => panic!("candidate deeper than its recovery scan was accepted"),
        Err(error) => error,
    };
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::LimitExceeded {
            resource: crate::server::error::AdmissionResource::WalkDepth,
            ..
        })
    ));
    assert_eq!(
        std::fs::read_dir(directory.path().join("one/two/three"))?.count(),
        0
    );
    Ok(())
}

#[test]
fn move_attempts_both_parent_syncs_even_when_destination_sync_fails() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::create_dir(directory.path().join("source-parent"))?;
    std::fs::create_dir(directory.path().join("destination-parent"))?;
    let source = File::open(directory.path().join("source-parent"))?;
    let destination = File::open(directory.path().join("destination-parent"))?;
    let mut stages = Vec::new();
    let error = sync_renamed_parents_with(&destination, &source, false, |_parent, stage| {
        stages.push(stage);
        Err(rustix::io::Errno::IO)
    })
    .unwrap_err();
    assert_eq!(
        stages,
        vec![
            DurabilityStage::DestinationParent,
            DurabilityStage::SourceParent,
        ]
    );
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::Durability {
            published: true,
            ..
        })
    ));

    let mut same_parent_calls = 0;
    sync_renamed_parents_with(&destination, &destination, true, |_parent, _stage| {
        same_parent_calls += 1;
        Ok(())
    })?;
    assert_eq!(same_parent_calls, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn extreme_umask_subprocess_helper() -> Result<()> {
    let Some(root_path) = std::env::var_os("RAM_MODE_UMASK_TEST_ROOT") else {
        return Ok(());
    };
    assert!(
        !rustix::process::geteuid().is_root(),
        "extreme-umask helper must run without root permission"
    );
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
    let root_path = std::path::PathBuf::from(root_path);
    let root = RootFs::new(&root_path, false, false)?;
    root.mkdir("collection", 0o710, empty_guards()).await?;
    let mut candidate = root.create_blocking_temp("one/two/fresh.bin", true, 0o710)?;
    candidate.file_mut().write_all(b"content")?;
    candidate.commit(
        EntryExpectation::Missing,
        0o640,
        &RequestCancellation::new(),
    )?;
    assert_eq!(
        std::fs::metadata(root_path.join("collection"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(root_path.join("one"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(root_path.join("one/two"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(root_path.join("one/two/fresh.bin"))?.mode() & 0o7777,
        0o640
    );
    Ok(())
}

#[test]
fn configured_modes_ignore_an_extreme_process_umask() -> Result<()> {
    let directory = TempDir::new()?;
    let mut command = Command::new(std::env::current_exe()?);
    if rustix::process::geteuid().is_root() {
        let uid = rustix::fs::Uid::from_raw(65_534);
        let gid = rustix::fs::Gid::from_raw(65_534);
        if let Err(error) = rustix::fs::chown(directory.path(), Some(uid), Some(gid)) {
            if matches!(error, rustix::io::Errno::PERM | rustix::io::Errno::INVAL) {
                eprintln!(
                    "skipping non-root extreme-umask test: nobody uid is not mapped: {error}"
                );
                return Ok(());
            }
            return Err(error.into());
        }
        command.gid(gid.as_raw()).uid(uid.as_raw());
    }
    let output = command
        .arg("--exact")
        .arg("server::filesystem::mutation_transaction_tests::extreme_umask_subprocess_helper")
        .arg("--nocapture")
        .env("RAM_MODE_UMASK_TEST_ROOT", directory.path())
        .env("RUST_TEST_THREADS", "1")
        .output()?;
    assert!(
        output.status.success(),
        "umask helper failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(directory.path().join("collection"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(directory.path().join("one"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(directory.path().join("one/two"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(directory.path().join("one/two/fresh.bin"))?.mode() & 0o7777,
        0o640
    );
    Ok(())
}

#[test]
fn commit_rejects_present_and_missing_namespace_replacements() -> Result<()> {
    for initially_present in [true, false] {
        let directory = TempDir::new()?;
        let root = RootFs::new(directory.path(), false, false)?;
        let target = directory.path().join("target.bin");
        if initially_present {
            std::fs::write(&target, b"selected A")?;
        }
        let expected = root.entry_expectation_sync(Path::new("target.bin"))?;
        let mut candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
        candidate.file_mut().write_all(b"candidate")?;

        if initially_present {
            std::fs::rename(&target, directory.path().join("selected-a.bin"))?;
        }
        std::fs::write(&target, b"attacker B")?;
        let error = candidate
            .commit(expected, 0o640, &RequestCancellation::new())
            .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed { .. })
        ));
        assert_eq!(std::fs::read(&target)?, b"attacker B");
        assert_eq!(
            std::fs::read_dir(directory.path())?
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ram-upload-"))
                .count(),
            0
        );
    }
    Ok(())
}

#[test]
fn create_only_eexist_keeps_mkcol_upload_and_destination_race_roles() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let parent = root.open_parent_sync(Path::new("target.bin"), false)?;

    for role in [
        MutationEndpointRole::Target,
        MutationEndpointRole::Destination,
    ] {
        let error =
            parent.create_only_error(EntryExpectation::Missing, role, rustix::io::Errno::EXIST);
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed {
                role: actual_role,
                ..
            }) if *actual_role == role
        ));
    }
    Ok(())
}

#[test]
fn copy_source_revalidation_rejects_namespace_replacement() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("source.bin"), b"selected A")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let source = root.open_raw(Path::new("source.bin"), NodeKind::File)?;
    let expected = EntryExpectation::from_metadata(&source.metadata()?);
    std::fs::rename(
        directory.path().join("source.bin"),
        directory.path().join("selected-a.bin"),
    )?;
    std::fs::write(directory.path().join("source.bin"), b"attacker B")?;
    let error = root
        .verify_opened_entry_sync(
            Path::new("source.bin"),
            &source,
            expected,
            MutationEndpointRole::Source,
        )
        .unwrap_err();
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::Changed {
            role: MutationEndpointRole::Source,
            ..
        })
    ));
    assert_eq!(
        std::fs::read(directory.path().join("source.bin"))?,
        b"attacker B"
    );
    Ok(())
}

#[test]
fn publication_modes_are_exact_strip_special_bits_and_break_hardlinks() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;

    let mut fresh = root.create_blocking_temp("fresh.bin", false, 0o700)?;
    fresh.file_mut().write_all(b"fresh")?;
    fresh.commit(
        EntryExpectation::Missing,
        0o4_751,
        &RequestCancellation::new(),
    )?;
    assert_eq!(
        std::fs::metadata(directory.path().join("fresh.bin"))?.mode() & 0o7777,
        0o751
    );

    let target = directory.path().join("target.bin");
    let alias = directory.path().join("alias.bin");
    std::fs::write(&target, b"old inode")?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o674))?;
    std::fs::hard_link(&target, &alias)?;
    let expected = root.entry_expectation_sync(Path::new("target.bin"))?;
    let old_mode = std::fs::metadata(&target)?.mode() & 0o777;
    let old_inode = std::fs::metadata(&target)?.ino();
    let mut replacement = root.create_blocking_temp("target.bin", false, 0o700)?;
    replacement.file_mut().write_all(b"new inode")?;
    replacement.commit(expected, old_mode, &RequestCancellation::new())?;
    let metadata = std::fs::metadata(&target)?;
    assert_eq!(metadata.mode() & 0o7777, 0o674);
    assert_ne!(metadata.ino(), old_inode);
    assert_eq!(std::fs::read(&target)?, b"new inode");
    assert_eq!(std::fs::read(&alias)?, b"old inode");
    Ok(())
}

#[test]
fn failed_candidate_rolls_back_only_its_exact_empty_ancestors() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let candidate = root.create_blocking_temp("one/two/file.bin", true, 0o710)?;
    assert_eq!(
        std::fs::metadata(directory.path().join("one"))?.mode() & 0o7777,
        0o710
    );
    assert_eq!(
        std::fs::metadata(directory.path().join("one/two"))?.mode() & 0o7777,
        0o710
    );
    drop(candidate);
    assert!(!directory.path().join("one").exists());

    let candidate = root.create_blocking_temp("one/two/file.bin", true, 0o700)?;
    std::fs::rename(
        directory.path().join("one"),
        directory.path().join("original-one"),
    )?;
    std::fs::create_dir(directory.path().join("one"))?;
    std::fs::write(directory.path().join("one/replacement"), b"must survive")?;
    drop(candidate);
    assert_eq!(
        std::fs::read(directory.path().join("one/replacement"))?,
        b"must survive"
    );
    Ok(())
}

#[test]
fn failed_reaper_attempt_retains_ancestor_rollback_responsibility() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut candidate = root.create_blocking_temp("one/two/file.bin", true, 0o700)?;
    let cleanup = CandidateCleanup::candidate(
        Some(candidate.parent.fd.try_clone()?),
        candidate.temp_name.clone(),
        candidate.candidate_expectation,
        std::mem::take(&mut candidate.parent.created_ancestors),
        candidate.candidate_lock.take(),
        candidate.cleanup_guard.take(),
    );
    candidate.committed = true;
    drop(candidate);

    let cleanup = cleanup
        .run_with(|_parent, _name| Err(rustix::io::Errno::IO))
        .expect("failed unlink must retain the complete cleanup record");
    assert_eq!(cleanup.created_ancestors.len(), 2);
    assert!(
        directory
            .path()
            .join("one/two")
            .join(&cleanup.name)
            .exists()
    );
    assert!(directory.path().join("one/two").exists());

    assert!(cleanup.run().is_none());
    assert!(!directory.path().join("one").exists());
    Ok(())
}

#[test]
fn candidate_replacement_is_neither_published_nor_unlinked() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut candidate = root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
    let candidate_path = directory.path().join("one/two").join(&candidate.temp_name);
    let moved_path = directory.path().join("one/two/original-candidate");
    std::fs::rename(&candidate_path, &moved_path)?;
    std::fs::write(&candidate_path, b"attacker replacement B")?;

    let error = candidate
        .parent
        .verify_candidate_identity(&candidate.temp_name, candidate.candidate_expectation)
        .unwrap_err();
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::Changed { .. })
    ));
    assert!(!directory.path().join("one/two/target.bin").exists());

    let cleanup = CandidateCleanup::candidate(
        Some(candidate.parent.fd.try_clone()?),
        candidate.temp_name.clone(),
        candidate.candidate_expectation,
        std::mem::take(&mut candidate.parent.created_ancestors),
        candidate.candidate_lock.take(),
        candidate.cleanup_guard.take(),
    );
    candidate.committed = true;
    drop(candidate);
    let cleanup = cleanup
        .run()
        .expect("replacement identity must keep cleanup fail-closed");
    assert_eq!(std::fs::read(&candidate_path)?, b"attacker replacement B");

    std::fs::remove_file(&candidate_path)?;
    std::fs::remove_file(&moved_path)?;
    assert!(cleanup.run().is_none());
    assert!(!directory.path().join("one").exists());
    Ok(())
}

#[test]
fn delete_rejects_replacement_and_recursive_budgets_are_zero_mutation() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    std::fs::write(directory.path().join("target"), b"A")?;
    let expected = root.entry_expectation_sync(Path::new("target"))?;
    std::fs::rename(
        directory.path().join("target"),
        directory.path().join("selected-a"),
    )?;
    std::fs::write(directory.path().join("target"), b"B")?;
    let error = root
        .remove_sync(
            Path::new("target"),
            false,
            expected,
            10,
            10,
            &RequestCancellation::new(),
        )
        .unwrap_err();
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::Changed { .. })
    ));
    assert_eq!(std::fs::read(directory.path().join("target"))?, b"B");

    for (limit, succeeds) in [(2, false), (3, true), (4, true)] {
        let case = TempDir::new()?;
        std::fs::create_dir(case.path().join("tree"))?;
        for name in ["a", "b", "c"] {
            std::fs::write(case.path().join("tree").join(name), name)?;
        }
        let root = RootFs::new(case.path(), false, false)?;
        let expected = root.entry_expectation_sync(Path::new("tree"))?;
        let result = root.remove_sync(
            Path::new("tree"),
            true,
            expected,
            limit,
            8,
            &RequestCancellation::new(),
        );
        assert_eq!(result.is_ok(), succeeds, "entry limit {limit}");
        if succeeds {
            assert!(!case.path().join("tree").exists());
        } else {
            assert!(AdmissionError::in_anyhow_chain(&result.unwrap_err()).is_some());
            assert_eq!(std::fs::read_dir(case.path().join("tree"))?.count(), 3);
        }
    }

    for (limit, succeeds) in [(1, false), (2, true), (3, true)] {
        let case = TempDir::new()?;
        std::fs::create_dir_all(case.path().join("tree/one/two"))?;
        std::fs::write(case.path().join("tree/one/two/file"), b"x")?;
        let root = RootFs::new(case.path(), false, false)?;
        let expected = root.entry_expectation_sync(Path::new("tree"))?;
        let result = root.remove_sync(
            Path::new("tree"),
            true,
            expected,
            16,
            limit,
            &RequestCancellation::new(),
        );
        assert_eq!(result.is_ok(), succeeds, "depth limit {limit}");
        if !succeeds {
            assert!(case.path().join("tree/one/two/file").exists());
        }
    }
    Ok(())
}

#[test]
fn recursive_delete_cancellation_after_mutation_is_durably_partial() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::create_dir(directory.path().join("tree"))?;
    std::fs::write(directory.path().join("tree/a"), b"a")?;
    std::fs::write(directory.path().join("tree/b"), b"b")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected = root.entry_expectation_sync(Path::new("tree"))?;
    let cancellation = RequestCancellation::new();
    let cancel_from_hook = cancellation.clone();
    let error = root
        .remove_sync_with_observer(
            Path::new("tree"),
            true,
            expected,
            8,
            8,
            &cancellation,
            move |removed| {
                if removed == 1 {
                    cancel_from_hook.cancel();
                }
            },
        )
        .unwrap_err();
    assert!(AdmissionError::in_anyhow_chain(&error).is_some());
    assert!(directory.path().join("tree").exists());
    assert_eq!(std::fs::read_dir(directory.path().join("tree"))?.count(), 1);
    Ok(())
}

#[tokio::test]
async fn move_rechecks_both_source_and_destination_versions() -> Result<()> {
    for replace_source in [true, false] {
        let directory = TempDir::new()?;
        std::fs::write(directory.path().join("source"), b"source A")?;
        std::fs::write(directory.path().join("destination"), b"destination A")?;
        let root = RootFs::new(directory.path(), false, false)?;
        let expected_source = root.entry_expectation_sync(Path::new("source"))?;
        let expected_destination = root.entry_expectation_sync(Path::new("destination"))?;
        let replaced = if replace_source {
            "source"
        } else {
            "destination"
        };
        std::fs::rename(
            directory.path().join(replaced),
            directory.path().join(format!("{replaced}-a")),
        )?;
        std::fs::write(directory.path().join(replaced), b"attacker B")?;
        let error = root
            .rename(
                "source",
                "destination",
                false,
                expected_source,
                expected_destination,
                empty_guards(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            FsError::in_anyhow_chain(&error),
            Some(FsError::Changed { .. })
        ));
        assert_eq!(
            std::fs::read(directory.path().join(replaced))?,
            b"attacker B"
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_move_rolls_back_its_auto_created_destination_ancestors() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("source"), b"source A")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let expected_source = root.entry_expectation_sync(Path::new("source"))?;
    let expected_destination = root.entry_expectation_sync(Path::new("new/deep/destination"))?;

    std::fs::rename(
        directory.path().join("source"),
        directory.path().join("selected-source-a"),
    )?;
    std::fs::write(directory.path().join("source"), b"attacker B")?;
    let error = root
        .rename(
            "source",
            "new/deep/destination",
            true,
            expected_source,
            expected_destination,
            empty_guards(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::Changed {
            role: MutationEndpointRole::Source,
            ..
        })
    ));
    assert_eq!(
        std::fs::read(directory.path().join("source"))?,
        b"attacker B"
    );
    assert!(
        !directory.path().join("new").exists(),
        "failed MOVE leaked its auto-created destination ancestors"
    );
    Ok(())
}
