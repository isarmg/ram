use super::{
    CandidateCleanup, CandidateReaper, CleanupTracker, EntryExpectation, RootFs,
    STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES, STALE_CLEANUP_DIAGNOSTIC_LIMIT,
    STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES, StaleUploadCleanupLimits, StaleUploadCleanupReport,
    StaleUploadCleanupStage, StaleUploadCleanupState, TempCandidateKind,
    cleanup_created_candidate_after_failure_with, create_temp_in, create_temp_in_with_reaper,
    drain_candidate_cleanup, enqueue_candidate_cleanup, retain_degraded_cleanup,
    retry_retained_cleanups, secure_private_candidate, try_cleanup_stale_candidate_with,
};
use crate::server::error::{AdmissionError, AdmissionResource, DurabilityStage};
use crate::server::walk::spawn_supervised_blocking;
use anyhow::Result;
use assert_fs::TempDir;
use rustix::fs::{AtFlags, FlockOperation, ResolveFlags, flock};
use rustix::io::Errno;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{File, FileTimes, OpenOptions};
use std::os::unix::fs::{PermissionsExt, chown, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Semaphore;

const UPLOAD: &str = ".ram-upload-00000000-0000-4000-8000-000000000001.tmp";
const STAGING: &str = ".ram-staging-00000000-0000-4000-8000-000000000002.tmp";

struct DropProbe(Arc<AtomicBool>);

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn old_private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.set_times(
        FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(2 * 60 * 60)),
    )?;
    Ok(file)
}

fn limits() -> StaleUploadCleanupLimits {
    StaleUploadCleanupLimits {
        min_age: Duration::from_secs(60 * 60),
        max_entries: 1_000,
        max_depth: 16,
        max_deletions: 100,
        timeout: Duration::from_secs(2),
    }
}

fn cleanup_state() -> StaleUploadCleanupState {
    let limits = limits();
    StaleUploadCleanupState {
        limits,
        deadline: Instant::now() + limits.timeout,
        now: SystemTime::now(),
        service_uid: rustix::process::geteuid().as_raw(),
        resolve_flags: ResolveFlags::empty(),
        visited_directories: HashSet::new(),
        report: StaleUploadCleanupReport::default(),
    }
}

#[test]
fn candidate_creation_repairs_permissions_removed_by_extreme_umask() -> Result<()> {
    let directory = TempDir::new()?;
    let path = directory.path().join(UPLOAD);
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o000))?;
    let (file, lock_clone) = secure_private_candidate(file).map_err(|(err, _file)| err)?;
    assert_eq!(file.metadata()?.permissions().mode() & 0o7777, 0o600);
    let competing = OpenOptions::new().read(true).write(true).open(&path)?;
    assert!(
        flock(&competing, FlockOperation::NonBlockingLockExclusive).is_err(),
        "candidate lock was not retained"
    );
    drop(lock_clone);
    drop(file);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_create_worker_drops_and_unlinks_its_owned_candidate() -> Result<()> {
    let directory = TempDir::new()?;
    let parent = File::open(directory.path())?;
    let (created_tx, created_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let request = tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(move || -> Result<_> {
            let candidate = create_temp_in(&parent, TempCandidateKind::Upload, &mut Vec::new())?;
            created_tx.send(candidate.temp_name.clone())?;
            release_rx.recv()?;
            Ok(candidate)
        })
        .await;
    });
    let name = created_rx.recv_timeout(Duration::from_secs(1))?;
    assert!(directory.path().join(&name).exists());
    request.abort();
    release_tx.send(())?;
    let _ = request.await;

    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while directory.path().join(&name).exists() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !directory.path().join(&name).exists(),
        "cancelled create worker leaked a named private candidate"
    );
    Ok(())
}

#[test]
fn global_reaper_drain_waits_until_queued_candidate_is_durable_absent() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
    let private_path = directory.path().join(&candidate.temp_name);
    let async_candidate = candidate.into_async_temp()?;
    assert!(private_path.exists());
    drop(async_candidate);

    assert!(
        drain_candidate_cleanup(Duration::from_secs(2)),
        "cleanup tracker did not drain before its deadline"
    );
    assert!(
        !private_path.exists(),
        "drain returned before candidate unlink and parent fsync completed"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_reaper_never_unlinks_on_tokio_and_fails_future_creation_closed() -> Result<()> {
    let directory = TempDir::new()?;
    let name = std::ffi::OsString::from(UPLOAD);
    let path = directory.path().join(&name);
    std::fs::write(&path, b"private candidate")?;
    let (sender, receiver) = mpsc::sync_channel(0);
    let retained = Arc::new(Mutex::new(Vec::new()));
    let reaper = CandidateReaper {
        sender,
        healthy: Arc::new(AtomicBool::new(true)),
        retained: retained.clone(),
        tracker: Arc::new(CleanupTracker::default()),
    };
    let guard_dropped = Arc::new(AtomicBool::new(false));

    let started = std::time::Instant::now();
    enqueue_candidate_cleanup(
        &reaper,
        CandidateCleanup::candidate(
            Some(File::open(directory.path())?),
            name,
            EntryExpectation::from_metadata(&std::fs::metadata(&path)?),
            Vec::new(),
            None,
            Some(Box::new(DropProbe(guard_dropped.clone()))),
        ),
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(
        path.exists(),
        "queue saturation performed a synchronous unlink"
    );
    assert!(!reaper.healthy.load(Ordering::Acquire));
    assert!(
        !guard_dropped.load(Ordering::Acquire),
        "queue saturation released admission before cleanup"
    );
    assert_eq!(retained.lock().unwrap().len(), 1);

    let parent = File::open(directory.path())?;
    let result =
        create_temp_in_with_reaper(&parent, TempCandidateKind::Upload, &reaper, &mut Vec::new());
    let error = match result {
        Ok(_) => panic!("degraded reaper allowed a new private candidate"),
        Err(error) => error,
    };
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::Uploads
        })
    ));
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
    drop(receiver);
    Ok(())
}

#[test]
fn unlink_failure_and_missing_parent_retain_cleanup_guards_fail_closed() -> Result<()> {
    let directory = TempDir::new()?;
    // 不带 REMOVEDIR 的 unlinkat 对目录必然失败。
    // unlinkat without REMOVEDIR deterministically fails for a directory.
    std::fs::create_dir(directory.path().join(UPLOAD))?;
    let healthy = AtomicBool::new(true);
    let retained = Mutex::new(Vec::new());
    let unlink_guard_dropped = Arc::new(AtomicBool::new(false));
    let cleanup = CandidateCleanup::candidate(
        Some(File::open(directory.path())?),
        UPLOAD.into(),
        EntryExpectation::from_metadata(&std::fs::symlink_metadata(directory.path().join(UPLOAD))?),
        Vec::new(),
        None,
        Some(Box::new(DropProbe(unlink_guard_dropped.clone()))),
    )
    .run()
    .expect("directory candidate must fail plain unlink");
    retain_degraded_cleanup(&healthy, &retained, cleanup);

    let clone_guard_dropped = Arc::new(AtomicBool::new(false));
    let cleanup = CandidateCleanup::candidate(
        None,
        STAGING.into(),
        EntryExpectation::Missing,
        Vec::new(),
        None,
        Some(Box::new(DropProbe(clone_guard_dropped.clone()))),
    )
    .run()
    .expect("a missing cleanup parent cannot confirm unlink");
    retain_degraded_cleanup(&healthy, &retained, cleanup);

    assert!(!healthy.load(Ordering::Acquire));
    assert_eq!(retained.lock().unwrap().len(), 2);
    assert!(!unlink_guard_dropped.load(Ordering::Acquire));
    assert!(!clone_guard_dropped.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn o_excl_candidate_failure_path_retains_full_record_when_unlink_fails() -> Result<()> {
    let directory = TempDir::new()?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let retained = Arc::new(Mutex::new(Vec::new()));
    let reaper = CandidateReaper {
        sender,
        healthy: Arc::new(AtomicBool::new(true)),
        retained: retained.clone(),
        tracker: Arc::new(CleanupTracker::default()),
    };
    let parent = File::open(directory.path())?;
    let candidate =
        create_temp_in_with_reaper(&parent, TempCandidateKind::Upload, &reaper, &mut Vec::new())?;
    let (name, file, candidate_lock, expectation, _ancestors) = candidate.into_parts()?;
    drop(file);
    let path = directory.path().join(&name);
    assert!(path.exists(), "O_EXCL candidate was not created");
    let guard_dropped = Arc::new(AtomicBool::new(false));

    cleanup_created_candidate_after_failure_with(
        &reaper,
        CandidateCleanup::candidate(
            Some(File::open(directory.path())?),
            name,
            expectation,
            Vec::new(),
            Some(candidate_lock),
            Some(Box::new(DropProbe(guard_dropped.clone()))),
        ),
        |_parent, _name| Err(Errno::IO),
    );

    assert!(
        path.exists(),
        "injected unlink failure removed the candidate"
    );
    assert!(!reaper.healthy.load(Ordering::Acquire));
    assert_eq!(retained.lock().unwrap().len(), 1);
    assert!(
        !guard_dropped.load(Ordering::Acquire),
        "failed O_EXCL cleanup released its admission guard"
    );
    let error = match create_temp_in_with_reaper(
        &parent,
        TempCandidateKind::Upload,
        &reaper,
        &mut Vec::new(),
    ) {
        Ok(_) => panic!("degraded reaper allowed another O_EXCL candidate"),
        Err(error) => error,
    };
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::Uploads
        })
    ));
    drop(receiver);
    Ok(())
}

#[test]
fn executor_retry_path_releases_cleanup_only_after_real_success() -> Result<()> {
    let directory = TempDir::new()?;
    let parent = File::open(directory.path())?;
    let candidate = create_temp_in(&parent, TempCandidateKind::Upload, &mut Vec::new())?;
    let (name, file, candidate_lock, expectation, ancestors) = candidate.into_parts()?;
    drop(file);
    let path = directory.path().join(&name);
    let cleanup = CandidateCleanup::candidate(
        Some(parent),
        name,
        expectation,
        ancestors,
        Some(candidate_lock),
        None,
    )
    .run_with(|_, _| Err(Errno::IO))
    .expect("first injected unlink failure must retain responsibility");
    let retained = Mutex::new(vec![cleanup]);

    retry_retained_cleanups(&retained);
    assert!(retained.lock().unwrap().is_empty());
    assert!(!path.exists());
    Ok(())
}

#[test]
fn noent_cleanup_requires_parent_sync_before_releasing_responsibility() -> Result<()> {
    let directory = TempDir::new()?;
    let missing_path = directory.path().join(UPLOAD);
    std::fs::write(&missing_path, b"candidate")?;
    let expectation = EntryExpectation::from_metadata(&std::fs::metadata(&missing_path)?);
    std::fs::remove_file(&missing_path)?;
    let guard_dropped = Arc::new(AtomicBool::new(false));
    let mut sync_attempts = 0;
    let cleanup = CandidateCleanup::candidate(
        Some(File::open(directory.path())?),
        UPLOAD.into(),
        expectation,
        Vec::new(),
        None,
        Some(Box::new(DropProbe(guard_dropped.clone()))),
    )
    .run_with_ops(
        |_, _| panic!("statat NOENT must not attempt unlink"),
        |_| {
            sync_attempts += 1;
            Err(Errno::IO)
        },
    )
    .expect("failed parent sync must retain a missing-name cleanup record");
    assert_eq!(sync_attempts, 1);
    assert!(!guard_dropped.load(Ordering::Acquire));

    let mut retry_syncs = 0;
    assert!(
        cleanup
            .run_with_ops(
                |_, _| panic!("parent-sync retry must not attempt unlink"),
                |_| {
                    retry_syncs += 1;
                    Ok(())
                },
            )
            .is_none()
    );
    assert_eq!(retry_syncs, 1);
    assert!(guard_dropped.load(Ordering::Acquire));

    let raced_path = directory.path().join(STAGING);
    std::fs::write(&raced_path, b"candidate")?;
    let expectation = EntryExpectation::from_metadata(&std::fs::metadata(&raced_path)?);
    let mut raced_syncs = 0;
    assert!(
        CandidateCleanup::candidate(
            Some(File::open(directory.path())?),
            STAGING.into(),
            expectation,
            Vec::new(),
            None,
            None,
        )
        .run_with_ops(
            |_, _| {
                std::fs::remove_file(&raced_path).unwrap();
                Err(Errno::NOENT)
            },
            |_| {
                raced_syncs += 1;
                Ok(())
            },
        )
        .is_none()
    );
    assert_eq!(raced_syncs, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timed_out_worker_owns_candidate_and_permit_until_cleanup_finishes() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let limiter = Arc::new(Semaphore::new(1));
    let permit = limiter.clone().acquire_owned().await?;
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = release.clone();
    let (started_tx, started_rx) = mpsc::channel();

    let operation = spawn_supervised_blocking(permit, move |_cancellation| {
        let candidate = root.create_blocking_temp("target.bin", false, 0o700)?;
        started_tx.send(())?;
        let (lock, wake) = &*worker_release;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = wake
                .wait_timeout(released, Duration::from_millis(10))
                .unwrap()
                .0;
        }
        drop(candidate);
        Ok(())
    });
    let state = operation.cancellation();
    started_rx.recv_timeout(Duration::from_secs(1))?;

    assert!(
        operation
            .wait_until(tokio::time::Instant::now() + Duration::from_millis(20))
            .await
            .is_err()
    );
    assert!(!state.worker_exited());
    assert!(limiter.clone().try_acquire_owned().is_err());
    assert_eq!(
        std::fs::read_dir(directory.path())?
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".ram-upload-"))
            .count(),
        1
    );

    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !state.worker_exited() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(limiter.try_acquire_owned().is_ok());
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicked_worker_cleans_real_candidate_ancestors_and_guard() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let worker_root = root.clone();
    let guard_dropped = Arc::new(AtomicBool::new(false));
    let worker_guard_dropped = guard_dropped.clone();
    let (candidate_tx, candidate_rx) = mpsc::channel();

    let worker = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut candidate = worker_root.create_blocking_temp("one/two/target.bin", true, 0o700)?;
        candidate_tx.send(candidate.temp_name.clone())?;
        candidate.attach_cleanup_guard(DropProbe(worker_guard_dropped))?;
        panic!("injected worker panic after candidate ownership");
    });
    let join_error = worker
        .await
        .expect_err("worker panic unexpectedly returned");
    assert!(join_error.is_panic());
    let candidate_name = candidate_rx.recv_timeout(Duration::from_secs(1))?;

    assert!(
        drain_candidate_cleanup(Duration::from_secs(2)),
        "candidate cleanup did not drain after worker panic"
    );
    assert!(
        guard_dropped.load(Ordering::Acquire),
        "worker panic released neither the candidate nor its attached guard"
    );
    assert!(
        !directory
            .path()
            .join("one/two")
            .join(candidate_name)
            .exists(),
        "worker panic leaked its private candidate"
    );
    assert!(
        !directory.path().join("one").exists(),
        "worker panic leaked auto-created candidate ancestors"
    );
    Ok(())
}

#[test]
fn cleanup_removes_only_old_private_unlocked_regular_candidates() -> Result<()> {
    let directory = TempDir::new()?;
    drop(old_private_file(&directory.path().join(UPLOAD))?);
    drop(old_private_file(&directory.path().join(STAGING))?);

    let young = directory
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000003.tmp");
    std::fs::write(&young, b"young")?;
    std::fs::set_permissions(&young, std::fs::Permissions::from_mode(0o600))?;

    let public_mode = directory
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000004.tmp");
    drop(old_private_file(&public_mode)?);
    std::fs::set_permissions(&public_mode, std::fs::Permissions::from_mode(0o640))?;

    let hard_link = directory
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000005.tmp");
    drop(old_private_file(&hard_link)?);
    std::fs::hard_link(&hard_link, directory.path().join("hard-link-alias"))?;

    let symlink_target = directory.path().join("symlink-target");
    std::fs::write(&symlink_target, b"must survive")?;
    let candidate_symlink = directory
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000006.tmp");
    symlink(&symlink_target, &candidate_symlink)?;

    let candidate_directory = directory
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000007.tmp");
    std::fs::create_dir(&candidate_directory)?;

    let active = directory
        .path()
        .join(".ram-upload-00000000-0000-4000-8000-000000000008.tmp");
    let active_file = old_private_file(&active)?;
    flock(&active_file, FlockOperation::NonBlockingLockExclusive)?;

    let malformed_names = [
        ".ram-upload-not-a-uuid.tmp",
        ".ram-upload-00000000000040008000000000000000.tmp",
        ".ram-upload-00000000-0000-4000-8000-00000000000A.tmp",
        ".ram-upload-urn:uuid:00000000-0000-4000-8000-00000000000a.tmp",
        ".ram-upload-{00000000-0000-4000-8000-00000000000a}.tmp",
        ".ram-upload-00000000-0000-4000-8000-00000000000a-extra.tmp",
    ];
    let malformed = malformed_names
        .into_iter()
        .map(|name| directory.path().join(name))
        .collect::<Vec<_>>();
    for path in &malformed {
        drop(old_private_file(path)?);
    }
    let ordinary = directory.path().join("ordinary.txt");
    drop(old_private_file(&ordinary)?);

    let foreign = if rustix::process::geteuid().is_root() {
        let foreign = directory
            .path()
            .join(".ram-upload-00000000-0000-4000-8000-000000000009.tmp");
        drop(old_private_file(&foreign)?);
        match chown(&foreign, Some(65_534), None) {
            Ok(()) => Some(foreign),
            // 非特权用户命名空间内的 root 可能没有传统 nobody uid 映射。此时只是该环境
            // 无法测试所有权分支，并非清理失败。
            // Root in an unprivileged user namespace may lack a conventional nobody-uid mapping.
            // The ownership branch is untestable there, not a cleanup failure.
            Err(err)
                if matches!(
                    err.raw_os_error(),
                    Some(code)
                        if code == Errno::INVAL.raw_os_error()
                            || code == Errno::PERM.raw_os_error()
                ) =>
            {
                std::fs::remove_file(foreign)?;
                None
            }
            Err(err) => return Err(err.into()),
        }
    } else {
        None
    };

    let root = RootFs::new(directory.path(), false, false)?;
    let report = root.cleanup_stale_uploads(limits())?;
    assert_eq!(report.deleted, 2);
    assert_eq!(report.skipped_active, 1);
    assert_eq!(report.skipped_young, 1);
    assert!(
        !report.is_complete(),
        "unsafe reserved-name entries must make admission fail closed"
    );
    assert!(!directory.path().join(UPLOAD).exists());
    assert!(!directory.path().join(STAGING).exists());
    for path in [
        &young,
        &public_mode,
        &hard_link,
        &candidate_symlink,
        &candidate_directory,
        &active,
        &ordinary,
    ] {
        assert!(
            path.symlink_metadata().is_ok(),
            "cleanup removed an ineligible path: {path:?}"
        );
    }
    for path in malformed.iter().chain(foreign.iter()) {
        assert!(
            path.symlink_metadata().is_ok(),
            "cleanup removed an ineligible strict-name/owner path: {path:?}"
        );
    }
    assert_eq!(std::fs::read(&symlink_target)?, b"must survive");
    drop(active_file);
    Ok(())
}

#[test]
fn young_candidate_is_revisited_after_aging_without_closing_admission() -> Result<()> {
    let directory = TempDir::new()?;
    let candidate = directory.path().join(UPLOAD);
    std::fs::write(&candidate, b"young candidate")?;
    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?;
    let root = RootFs::new(directory.path(), false, false)?;
    let mut scan_limits = limits();
    scan_limits.min_age = Duration::from_millis(100);

    let young_report = root.cleanup_stale_uploads(scan_limits)?;
    assert_eq!(young_report.deleted, 0);
    assert_eq!(young_report.skipped_young, 1);
    assert!(young_report.is_complete());
    root.ensure_candidate_recovery_healthy()?;
    assert!(candidate.exists());

    std::thread::sleep(Duration::from_millis(150));
    let mature_report = root.cleanup_stale_uploads(scan_limits)?;
    assert_eq!(mature_report.deleted, 1);
    assert_eq!(mature_report.skipped_young, 0);
    assert!(mature_report.is_complete());
    root.ensure_candidate_recovery_healthy()?;
    assert!(!candidate.exists());
    Ok(())
}

#[test]
fn entry_budget_starvation_stickily_closes_candidate_admission() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    assert!(root.cleanup_stale_uploads(limits())?.is_complete());

    // 普通目录本身消耗唯一条目预算。递归时上限已耗尽，因此无论 getdents 顺序如何，其
    // 子候选都确定不可达。
    // The ordinary directory consumes the sole entry budget. Recursion is already exhausted, so
    // its child candidate is unreachable regardless of getdents ordering.
    std::fs::create_dir(directory.path().join("ordinary-directory"))?;
    let candidate = directory.path().join("ordinary-directory").join(UPLOAD);
    drop(old_private_file(&candidate)?);

    let mut starved_limits = limits();
    starved_limits.max_entries = 1;
    let report = root.cleanup_stale_uploads(starved_limits)?;
    assert!(report.entry_limit_reached);
    assert_eq!(report.deleted, 0);
    assert!(!report.is_complete());
    assert!(candidate.exists());

    let error = match root.create_blocking_temp("new-upload.bin", false, 0o700) {
        Ok(_) => panic!("an incomplete recovery scan admitted a new candidate"),
        Err(error) => error,
    };
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::Uploads
        })
    ));

    // 之后完整扫描可能回收旧候选，但进程级闸门有意保持粘性：修正恢复预算或文件系统
    // 故障后，运维人员必须重启。
    // A later complete pass may reclaim the old candidate, but the process gate is deliberately
    // sticky: operators must restart after correcting recovery-budget/filesystem failure.
    let complete_report = root.cleanup_stale_uploads(limits())?;
    assert_eq!(complete_report.deleted, 1);
    assert!(complete_report.is_complete());
    assert!(root.ensure_candidate_recovery_healthy().is_err());
    Ok(())
}

#[test]
fn cleanup_io_error_closes_candidate_admission_before_returning() -> Result<()> {
    let directory = TempDir::new()?;
    let root = RootFs::new(directory.path(), false, false)?;
    let injected = root.record_stale_upload_cleanup_result(Err(anyhow::anyhow!(
        "injected directory iteration failure"
    )));
    assert!(injected.is_err());

    let error = match root.create_blocking_temp("new-upload.bin", false, 0o700) {
        Ok(_) => panic!("a failed recovery scan admitted a new candidate"),
        Err(error) => error,
    };
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::Uploads
        })
    ));
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[test]
fn cleanup_failure_diagnostics_distinguish_unlink_and_parent_sync() -> Result<()> {
    let unlink_root = TempDir::new()?;
    let unlink_path = unlink_root.path().join(UPLOAD);
    drop(old_private_file(&unlink_path)?);
    let unlink_parent = File::open(unlink_root.path())?;
    let mut unlink_state = cleanup_state();
    try_cleanup_stale_candidate_with(
        &unlink_parent,
        OsStr::new(UPLOAD),
        Path::new(UPLOAD),
        &mut unlink_state,
        |_parent, _name| Err(Errno::IO),
        |_parent| panic!("an unlink failure must not attempt parent fsync"),
    );
    assert!(unlink_path.exists());
    assert_eq!(unlink_state.report.deleted, 0);
    assert_eq!(unlink_state.report.failures, 1);
    assert_eq!(unlink_state.report.failure_diagnostics.len(), 1);
    assert_eq!(
        unlink_state.report.failure_diagnostics[0].stage,
        StaleUploadCleanupStage::UnlinkCandidate
    );
    assert_eq!(
        unlink_state.report.failure_diagnostics[0].relative_path,
        UPLOAD
    );
    assert!(
        unlink_state.report.failure_diagnostics[0]
            .cause
            .contains("unlinking a stale private candidate")
    );
    assert!(!unlink_state.report.is_complete());

    let sync_root = TempDir::new()?;
    let sync_path = sync_root.path().join(STAGING);
    drop(old_private_file(&sync_path)?);
    let sync_parent = File::open(sync_root.path())?;
    let mut sync_state = cleanup_state();
    try_cleanup_stale_candidate_with(
        &sync_parent,
        OsStr::new(STAGING),
        Path::new(STAGING),
        &mut sync_state,
        |parent, name| rustix::fs::unlinkat(parent, name, AtFlags::empty()),
        |_parent| Err(Errno::IO),
    );
    assert!(!sync_path.exists());
    assert_eq!(sync_state.report.deleted, 1);
    assert_eq!(sync_state.report.failures, 1);
    assert_eq!(sync_state.report.failure_diagnostics.len(), 1);
    assert_eq!(
        sync_state.report.failure_diagnostics[0].stage,
        StaleUploadCleanupStage::SyncParent(DurabilityStage::RemovedEntryParent)
    );
    assert!(
        sync_state.report.failure_diagnostics[0]
            .cause
            .contains("durability")
    );
    assert!(!sync_state.report.is_complete());
    Ok(())
}

#[test]
fn cleanup_failure_diagnostics_are_bounded_relative_and_suppress_the_rest() {
    let mut state = cleanup_state();
    let long_relative = PathBuf::from("x".repeat(STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES * 2));
    for index in 0..(STALE_CLEANUP_DIAGNOSTIC_LIMIT + 2) {
        state.record_failure(
            StaleUploadCleanupStage::InspectEntry,
            &long_relative,
            anyhow::anyhow!(
                "injected cause {index}\n{}",
                "y".repeat(STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES * 2)
            ),
        );
    }
    assert_eq!(state.report.failures, STALE_CLEANUP_DIAGNOSTIC_LIMIT + 2);
    assert_eq!(
        state.report.failure_diagnostics.len(),
        STALE_CLEANUP_DIAGNOSTIC_LIMIT
    );
    assert_eq!(state.report.suppressed_failures, 2);
    for diagnostic in &state.report.failure_diagnostics {
        assert!(diagnostic.relative_path.len() <= STALE_CLEANUP_DIAGNOSTIC_PATH_MAX_BYTES);
        assert!(diagnostic.cause.len() <= STALE_CLEANUP_DIAGNOSTIC_CAUSE_MAX_BYTES);
        assert!(!diagnostic.relative_path.starts_with('/'));
        assert!(!diagnostic.relative_path.chars().any(char::is_control));
        assert!(!diagnostic.cause.chars().any(char::is_control));
    }

    let mut absolute_state = cleanup_state();
    absolute_state.record_failure(
        StaleUploadCleanupStage::InspectEntry,
        Path::new("/outside/secret"),
        anyhow::anyhow!("injected absolute-path test"),
    );
    assert_eq!(
        absolute_state.report.failure_diagnostics[0].relative_path,
        "<invalid-capability-relative-path>"
    );
}

#[test]
fn cleanup_honors_deletion_entry_depth_and_deadline_budgets() -> Result<()> {
    let deletion_root = TempDir::new()?;
    for index in 10..13 {
        let path = deletion_root.path().join(format!(
            ".ram-upload-00000000-0000-4000-8000-{index:012}.tmp"
        ));
        drop(old_private_file(&path)?);
    }
    let root = RootFs::new(deletion_root.path(), false, false)?;
    let mut deletion_limits = limits();
    deletion_limits.max_deletions = 1;
    let report = root.cleanup_stale_uploads(deletion_limits)?;
    assert_eq!(report.deleted, 1);
    assert!(report.deletion_limit_reached);
    assert_eq!(
        std::fs::read_dir(deletion_root.path())?.count(),
        2,
        "deletion budget was exceeded"
    );

    let entry_root = TempDir::new()?;
    for index in 0..3 {
        std::fs::write(entry_root.path().join(format!("ordinary-{index}")), b"x")?;
    }
    let root = RootFs::new(entry_root.path(), false, false)?;
    let mut entry_limits = limits();
    entry_limits.max_entries = 1;
    let report = root.cleanup_stale_uploads(entry_limits)?;
    assert_eq!(report.scanned_entries, 1);
    assert!(report.entry_limit_reached);

    let depth_root = TempDir::new()?;
    std::fs::create_dir_all(depth_root.path().join("one/two"))?;
    let deep_candidate = depth_root.path().join(format!("one/two/{UPLOAD}"));
    drop(old_private_file(&deep_candidate)?);
    let root = RootFs::new(depth_root.path(), false, false)?;
    let mut depth_limits = limits();
    depth_limits.max_depth = 1;
    let report = root.cleanup_stale_uploads(depth_limits)?;
    assert!(report.depth_limit_reached);
    assert!(deep_candidate.exists());

    let deadline_root = TempDir::new()?;
    let deadline_candidate = deadline_root.path().join(UPLOAD);
    drop(old_private_file(&deadline_candidate)?);
    let root = RootFs::new(deadline_root.path(), false, false)?;
    let mut deadline_limits = limits();
    deadline_limits.timeout = Duration::ZERO;
    let report = root.cleanup_stale_uploads(deadline_limits)?;
    assert!(report.deadline_reached);
    assert!(deadline_candidate.exists());
    Ok(())
}
