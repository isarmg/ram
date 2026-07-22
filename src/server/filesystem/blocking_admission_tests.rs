use super::{FilesystemBlockingAdmission, GuardedBlockingFile, NodeKind, RootFs};
use crate::server::error::{AdmissionError, AdmissionResource};
use anyhow::Result;
use assert_fs::TempDir;
use std::io::SeekFrom;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

fn single_blocking_worker_runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()?)
}

async fn wait_for_permits(admission: &FilesystemBlockingAdmission, expected: usize) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while admission.available_permits() != expected {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn assert_filesystem_admission_timeout(error: &anyhow::Error) {
    assert!(matches!(
        AdmissionError::in_anyhow_chain(error),
        Some(AdmissionError::Timeout {
            resource: AdmissionResource::FilesystemTasks,
            ..
        })
    ));
}

/// 中文：即使被取消任务尚在 Tokio blocking queue，闭包捕获的唯一许可仍封住队列；
/// worker 最终弹出 abort 任务时不得执行用户闭包，并在那之后才归还容量。
/// English: A cancelled task queued behind Tokio's only blocking worker keeps the sole permit,
/// bounding the queue. Dequeuing the aborted task must not execute user work and only then frees capacity.
#[test]
fn queued_cancellation_keeps_admission_bounded_until_dequeue() -> Result<()> {
    let runtime = single_blocking_worker_runtime()?;
    let admission = FilesystemBlockingAdmission::new(1, Duration::from_millis(50));
    let (blocker_started_tx, blocker_started_rx) = mpsc::sync_channel(1);
    let (release_blocker_tx, release_blocker_rx) = mpsc::sync_channel(1);
    let blocker = runtime.spawn_blocking(move || {
        blocker_started_tx.send(()).expect("test is listening");
        release_blocker_rx.recv().expect("test releases blocker");
    });
    blocker_started_rx.recv_timeout(Duration::from_secs(2))?;

    let executed = Arc::new(AtomicBool::new(false));
    let queued_executed = executed.clone();
    let queued_admission = admission.clone();
    let queued = runtime.spawn(async move {
        queued_admission
            .run(move || {
                queued_executed.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
    });
    runtime.block_on(wait_for_permits(&admission, 0))?;
    queued.abort();
    let cancellation = runtime
        .block_on(queued)
        .expect_err("request task is cancelled");
    assert!(cancellation.is_cancelled());
    assert_eq!(admission.available_permits(), 0);

    let timeout = runtime
        .block_on(admission.run(|| Ok(())))
        .expect_err("the queued aborted closure still owns the sole permit");
    assert_filesystem_admission_timeout(&timeout);

    release_blocker_tx.send(())?;
    runtime.block_on(blocker)?;
    runtime.block_on(wait_for_permits(&admission, 1))?;
    assert!(!executed.load(Ordering::SeqCst));
    Ok(())
}

/// 中文：`spawn_blocking` 已开始后 abort 无法停止 syscall；许可必须由真实闭包保留到
/// 返回，不能因 HTTP/request future 被丢弃而提前允许第二个文件系统任务进入。
/// English: Once `spawn_blocking` starts, abort cannot stop a syscall. The real closure must keep
/// admission until return instead of admitting a second filesystem task when its request future drops.
#[test]
fn running_cancellation_keeps_permit_until_worker_returns() -> Result<()> {
    let runtime = single_blocking_worker_runtime()?;
    let admission = FilesystemBlockingAdmission::new(1, Duration::from_millis(50));
    let (worker_started_tx, worker_started_rx) = mpsc::sync_channel(1);
    let (release_worker_tx, release_worker_rx) = mpsc::sync_channel(1);
    let worker_admission = admission.clone();
    let request = runtime.spawn(async move {
        worker_admission
            .run(move || {
                worker_started_tx.send(()).expect("test is listening");
                release_worker_rx.recv().expect("test releases worker");
                Ok(())
            })
            .await
    });
    worker_started_rx.recv_timeout(Duration::from_secs(2))?;
    request.abort();
    let cancellation = runtime
        .block_on(request)
        .expect_err("request task is cancelled");
    assert!(cancellation.is_cancelled());
    assert_eq!(admission.available_permits(), 0);

    let timeout = runtime
        .block_on(admission.run(|| Ok(())))
        .expect_err("the running closure still owns the sole permit");
    assert_filesystem_admission_timeout(&timeout);

    release_worker_tx.send(())?;
    runtime.block_on(wait_for_permits(&admission, 1))?;
    Ok(())
}

/// 中文：准入状态机不改变普通下载的游标语义；每个 read/seek 独立获取许可并能连续复用。
/// English: Per-operation admission preserves normal download cursor semantics across repeated reads and seeks.
#[tokio::test]
async fn guarded_file_reads_and_seeks_across_independent_leases() -> Result<()> {
    let directory = TempDir::new()?;
    std::fs::write(directory.path().join("sample.txt"), b"abcdef")?;
    let root = RootFs::new(directory.path(), false, false)?;
    let opened = root.open("sample.txt", NodeKind::File).await?;
    let mut file: GuardedBlockingFile = opened.file;

    let mut prefix = [0_u8; 3];
    file.read_exact(&mut prefix).await?;
    assert_eq!(&prefix, b"abc");
    assert_eq!(file.seek(SeekFrom::Start(1)).await?, 1);
    let mut suffix = String::new();
    file.read_to_string(&mut suffix).await?;
    assert_eq!(suffix, "bcdef");
    assert_eq!(root.blocking_admission().available_permits(), 32);
    Ok(())
}
