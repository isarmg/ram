use super::{
    BLOCKING_POOL_SHUTDOWN_TIMEOUT, build_runtime, connection_lifetime_deadline,
    http1_request_head_semantic_size, response_has_wire_body,
};
use crate::http::body_full;
use crate::server::Response;
use anyhow::Result;
use hyper::{Method, Request, StatusCode, Version};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[test]
fn blocking_pool_has_a_hard_global_running_worker_limit() -> Result<()> {
    let runtime = build_runtime(1)?;
    let (first_started_tx, first_started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first = runtime.handle().spawn_blocking(move || {
        first_started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    first_started_rx.recv_timeout(Duration::from_secs(1))?;

    let (second_started_tx, second_started_rx) = mpsc::channel();
    let second = runtime.handle().spawn_blocking(move || {
        second_started_tx.send(()).unwrap();
    });
    assert!(
        second_started_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "a second blocking worker ran above the configured hard limit"
    );

    release_tx.send(())?;
    runtime.block_on(async {
        first.await.unwrap();
        second.await.unwrap();
    });
    second_started_rx.recv_timeout(Duration::from_secs(1))?;
    runtime.shutdown_timeout(BLOCKING_POOL_SHUTDOWN_TIMEOUT);
    Ok(())
}

#[test]
fn runtime_shutdown_timeout_does_not_claim_to_terminate_stuck_syscall() -> Result<()> {
    let runtime = build_runtime(1)?;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (exited_tx, exited_rx) = mpsc::channel();
    runtime.handle().spawn_blocking(move || {
        started_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        exited_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1))?;

    let started = Instant::now();
    runtime.shutdown_timeout(Duration::from_millis(20));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "runtime shutdown waited indefinitely for a stuck blocking worker"
    );
    assert!(exited_rx.try_recv().is_err());

    release_tx.send(())?;
    exited_rx.recv_timeout(Duration::from_secs(1))?;
    Ok(())
}

#[test]
fn connection_lifetime_deadline_is_anchored_to_accept_time() {
    let observed_now = tokio::time::Instant::now();
    let accepted_at = observed_now - Duration::from_secs(9);
    let deadline = connection_lifetime_deadline(accepted_at, Duration::from_secs(10));
    assert_eq!(deadline - accepted_at, Duration::from_secs(10));
    assert!(
        deadline <= observed_now + Duration::from_secs(1),
        "time spent before HTTP service incorrectly extended the absolute lifetime"
    );
}

#[test]
fn response_idle_monitor_is_skipped_for_head_and_bodyless_responses() {
    let response = Response::new(body_full("payload"));
    assert!(response_has_wire_body(&Method::GET, &response));
    assert!(!response_has_wire_body(&Method::HEAD, &response));

    let empty = Response::new(body_full(""));
    assert!(!response_has_wire_body(&Method::GET, &empty));

    for status in [
        StatusCode::NO_CONTENT,
        StatusCode::RESET_CONTENT,
        StatusCode::NOT_MODIFIED,
    ] {
        let mut response = Response::new(body_full("must not reach the wire"));
        *response.status_mut() = status;
        assert!(!response_has_wire_body(&Method::GET, &response));
    }
}

#[test]
fn http1_semantic_head_size_matches_its_canonical_wire_form() -> Result<()> {
    let wire =
        "CUSTOM http://example.test/path?q=1 HTTP/1.0\r\nHost: example.test\r\nX-Test: abc\r\n\r\n";
    let request = Request::builder()
        .method("CUSTOM")
        .uri("http://example.test/path?q=1")
        .version(Version::HTTP_10)
        .header("host", "example.test")
        .header("x-test", "abc")
        .body(())?;
    assert_eq!(http1_request_head_semantic_size(&request), Some(wire.len()));

    Ok(())
}
