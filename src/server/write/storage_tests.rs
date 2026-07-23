use super::*;
use assert_fs::TempDir;
use hyper::header::RETRY_AFTER;
use std::fs::OpenOptions;

#[test]
fn destination_accepts_only_relative_or_same_host_http_family_uris() {
    for (destination, host, expected) in [
        ("dir/child.txt", None, Some("dir/child.txt")),
        ("/dir/child.txt", None, Some("/dir/child.txt")),
        (
            "http://example.test/child.txt",
            Some("example.test"),
            Some("/child.txt"),
        ),
        (
            "https://example.test:8443/child.txt",
            Some("example.test:8443"),
            Some("/child.txt"),
        ),
    ] {
        assert_eq!(
            parse_destination_uri(destination, host).as_deref(),
            expected
        );
    }

    for destination in [
        "http:/child.txt",
        "urn:example:child",
        "ftp://example.test/child.txt",
        "//example.test/child.txt",
        "https://other.test/child.txt",
        "https://example.test/child.txt?download",
        "https://example.test/child.txt#section",
    ] {
        assert_eq!(
            parse_destination_uri(destination, Some("example.test")),
            None,
            "{destination}"
        );
    }
}

#[test]
fn upload_size_limit_covers_boundaries() {
    assert!(upload_size_allowed(7, 8));
    assert!(upload_size_allowed(8, 8));
    assert!(!upload_size_allowed(9, 8));
    assert!(!upload_size_allowed(1, 0));
}

#[test]
fn upload_body_transport_failure_has_a_stable_typed_400() {
    let error = upload_body_transport_error(anyhow::Error::new(io::Error::new(
        io::ErrorKind::ConnectionReset,
        "private transport detail",
    )));
    assert!(matches!(
        HttpError::in_anyhow_chain(&error),
        Some(HttpError::BadRequest { .. })
    ));
    let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
        .expect("upload transport failure remains typed under context");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn staging_fallback_accepts_only_a_typed_missing_parent() {
    let missing = anyhow::Error::new(FsError::from_anyhow(
        "opening upload parent",
        anyhow::Error::new(io::Error::from(io::ErrorKind::NotFound)),
    ))
    .context("resolving initial upload candidate");
    let missing = ensure_typed_filesystem_error("creating upload staging candidate", missing);
    assert!(upload_target_parent_is_missing(&missing));

    // 内部 ENOENT 是刻意误导项：封闭 OutsideRoot 标记必须穿过附加上下文，绝不能触发根暂存回退。
    // The inner ENOENT is deliberately misleading: the closed OutsideRoot marker must survive
    // added context and never trigger root-staging fallback.
    let outside = anyhow::Error::new(FsError::outside_root(
        "resolving upload parent",
        io::Error::from(io::ErrorKind::NotFound),
    ))
    .context("resolving initial upload candidate");
    let outside = ensure_typed_filesystem_error("creating upload staging candidate", outside);
    assert!(!upload_target_parent_is_missing(&outside));
    assert!(matches!(
        FsError::in_anyhow_chain(&outside),
        Some(FsError::OutsideRoot { .. })
    ));

    let cancelled = anyhow::Error::new(AdmissionError::cancelled(AdmissionResource::Uploads))
        .context("resolving initial upload candidate");
    let cancelled = ensure_typed_filesystem_error("creating upload staging candidate", cancelled);
    assert!(!upload_target_parent_is_missing(&cancelled));
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&cancelled),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::Uploads
        })
    ));
}

#[tokio::test]
async fn validator_truncation_maps_to_changed_precondition_412() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("target.bin");
    std::fs::write(&path, b"original bytes").unwrap();
    let root = RootFs::new(dir.path(), false, false).unwrap();
    let mut opened = root.open("target.bin", NodeKind::File).await.unwrap();
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let mut response = Response::default();

    let validators = write_cache_validators(&mut opened, &mut response)
        .await
        .unwrap();
    assert!(validators.is_none());
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
}

#[test]
fn put_fallback_copy_preserves_recorded_content() {
    let dir = TempDir::new().unwrap();
    let source_path = dir.path().join("source");
    let destination_path = dir.path().join("destination");
    std::fs::write(&source_path, b"abcdef").unwrap();
    let mut source = OpenOptions::new().read(true).open(&source_path).unwrap();
    let mut destination = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&destination_path)
        .unwrap();

    copy_exact_at_current(
        &mut source,
        &mut destination,
        6,
        &RequestCancellation::new(),
    )
    .unwrap();
    assert_eq!(std::fs::read(destination_path).unwrap(), b"abcdef");
}

#[test]
fn put_fallback_copy_observes_preexisting_cancellation() {
    let dir = TempDir::new().unwrap();
    let source_path = dir.path().join("source");
    let destination_path = dir.path().join("destination");
    std::fs::write(&source_path, b"abcdef").unwrap();
    let mut source = OpenOptions::new().read(true).open(&source_path).unwrap();
    let mut destination = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(destination_path)
        .unwrap();
    let cancellation = RequestCancellation::new();
    cancellation.cancel();

    let error = copy_exact_at_current(&mut source, &mut destination, 6, &cancellation).unwrap_err();
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::Uploads,
        })
    ));
    assert_eq!(destination.metadata().unwrap().len(), 0);
}

#[test]
fn storage_errno_classification_survives_anyhow_context() {
    for errno in [rustix::io::Errno::NOSPC, rustix::io::Errno::DQUOT] {
        let error = anyhow::Error::new(io::Error::from_raw_os_error(errno.raw_os_error()))
            .context("candidate sync failed");
        assert!(matches!(
            FsError::from_anyhow("writing candidate", error),
            FsError::NoSpace { .. }
        ));
    }
    assert!(matches!(
        FsError::from_anyhow("writing candidate", anyhow!("unrelated internal failure")),
        FsError::Io { .. }
    ));
}

#[test]
fn actual_dev_full_enospc_is_classified_when_available() {
    let Ok(mut full) = OpenOptions::new().write(true).open("/dev/full") else {
        return;
    };
    let error = full.write_all(b"x").unwrap_err();
    let error = anyhow::Error::new(error).context("fault-injected candidate write");
    assert!(matches!(
        FsError::from_anyhow("writing candidate", error),
        FsError::NoSpace { .. }
    ));
}

#[test]
fn storage_denials_map_to_507_but_internal_errors_do_not() {
    let mut response = Response::default();
    map_local_mutation_error(
        "PUT",
        Path::new("dest.bin"),
        Some("alice"),
        anyhow::Error::new(io::Error::from_raw_os_error(
            rustix::io::Errno::DQUOT.raw_os_error(),
        )),
        ChangedStatus::Conflict,
        &mut response,
    )
    .unwrap();
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);

    let mut response = Response::default();
    map_local_mutation_error(
        "PUT",
        Path::new("dest.bin"),
        Some("alice"),
        anyhow!("internal invariant failed"),
        ChangedStatus::Conflict,
        &mut response,
    )
    .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn move_raced_endpoint_roles_select_412_or_409_without_path_inference() {
    let cases = [
        (
            MutationEndpointRole::Source,
            ChangedStatus::PreconditionFailed,
            true,
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            MutationEndpointRole::Source,
            ChangedStatus::Conflict,
            false,
            StatusCode::CONFLICT,
        ),
        (
            MutationEndpointRole::Destination,
            ChangedStatus::PreconditionFailed,
            true,
            StatusCode::CONFLICT,
        ),
        (
            MutationEndpointRole::Destination,
            ChangedStatus::Conflict,
            false,
            StatusCode::PRECONDITION_FAILED,
        ),
    ];
    for (role, source_status, overwrite, expected_status) in cases {
        let error = anyhow::Error::new(FsError::changed(role, "diagnostic/path", "A", "B"));
        let changed_status = move_changed_status(&error, source_status, overwrite);
        let mut response = Response::default();
        map_local_mutation_error(
            "MOVE",
            Path::new("unrelated/display/path"),
            Some("alice"),
            error,
            changed_status,
            &mut response,
        )
        .unwrap();
        assert_eq!(response.status(), expected_status);
    }
}

#[test]
fn upload_and_mkcol_target_races_keep_conditional_statuses() {
    for operation in ["PUT", "MKCOL"] {
        for (changed_status, expected_status) in [
            (
                ChangedStatus::PreconditionFailed,
                StatusCode::PRECONDITION_FAILED,
            ),
            (ChangedStatus::Conflict, StatusCode::CONFLICT),
        ] {
            let error = anyhow::Error::new(FsError::changed(
                MutationEndpointRole::Target,
                "target",
                "Missing",
                "appeared",
            ));
            let mut response = Response::default();
            map_local_mutation_error(
                operation,
                Path::new("target"),
                Some("alice"),
                error,
                changed_status,
                &mut response,
            )
            .unwrap();
            assert_eq!(response.status(), expected_status);
        }
    }
}

#[test]
fn recursive_delete_budget_cancel_and_deadline_have_stable_http_statuses() {
    for (error, expected) in [
        (
            AdmissionError::limit_exceeded(
                AdmissionResource::WalkEntries,
                super::super::error::LimitKind::Semantic,
                3,
                Some(4),
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            AdmissionError::cancelled(AdmissionResource::WalkEntries),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AdmissionError::execution_timeout(
                AdmissionResource::ExpensiveTasks,
                Duration::from_secs(5),
            ),
            StatusCode::GATEWAY_TIMEOUT,
        ),
    ] {
        let mut response = Response::default();
        map_local_mutation_error(
            "DELETE",
            Path::new("tree"),
            Some("alice"),
            anyhow::Error::new(error),
            ChangedStatus::Conflict,
            &mut response,
        )
        .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[test]
fn candidate_and_post_publish_durability_failures_are_stable_500() {
    for errno in [rustix::io::Errno::NOSPC, rustix::io::Errno::DQUOT] {
        for published in [false, true] {
            let stage = if published {
                super::super::error::DurabilityStage::DestinationParent
            } else {
                super::super::error::DurabilityStage::CandidateFile
            };
            let error = anyhow::Error::new(FsError::durability(
                stage,
                published,
                std::io::Error::from_raw_os_error(errno.raw_os_error()),
            ));
            assert_eq!(
                FsError::in_anyhow_chain(&error)
                    .is_some_and(FsError::is_published_durability_failure),
                published,
                "published marker"
            );
            let mut response = Response::default();
            map_local_mutation_error(
                "PUT",
                Path::new("dest.bin"),
                Some("alice"),
                error,
                ChangedStatus::Conflict,
                &mut response,
            )
            .unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.headers().contains_key(RETRY_AFTER));
        }
    }
}
