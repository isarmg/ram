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
fn quota_hook_subprocess_helper() {
    if std::env::var_os("RAM_QUOTA_HOOK_TEST_HELPER").is_none() {
        return;
    }
    let count = std::env::var("RAM_QUOTA_HOOK_TEST_ARG_COUNT")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let args = (0..count)
        .map(|index| {
            std::env::var_os(format!("RAM_QUOTA_HOOK_TEST_ARG_{index}"))
                .expect("quota-hook helper argument is missing")
        })
        .collect::<Vec<_>>();
    if run_storage_quota_hook_helper(args).is_err() {
        std::process::exit(STORAGE_QUOTA_HOOK_HELPER_FAILURE_EXIT_CODE);
    }
}

#[test]
fn projected_upload_size_covers_limit_boundaries_for_put_and_patch() {
    for (incoming, expected) in [(7, Ok(7)), (8, Ok(8)), (9, Err(UploadSizeExceeded))] {
        assert_eq!(projected_upload_size(99, None, incoming, 8), expected);
    }

    for (incoming, expected) in [(2, Ok(7)), (3, Ok(8)), (4, Err(UploadSizeExceeded))] {
        assert_eq!(projected_upload_size(5, Some(5), incoming, 8), expected);
    }
    assert_eq!(projected_upload_size(8, Some(8), 0, 8), Ok(8));
    assert_eq!(
        projected_upload_size(9, Some(9), 0, 8),
        Err(UploadSizeExceeded)
    );
}

#[test]
fn projected_upload_size_rejects_overflow_even_when_unlimited() {
    assert_eq!(
        projected_upload_size(0, Some(u64::MAX), 1, 0),
        Err(UploadSizeExceeded)
    );
    assert_eq!(
        projected_upload_size(u64::MAX, Some(u64::MAX - 1), 1, 0),
        Ok(u64::MAX)
    );
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

#[test]
fn quota_hook_infrastructure_is_500_but_policy_denial_is_507() {
    let infrastructure = quota_hook_infrastructure_error(
        "opening quota hook",
        io::Error::from(io::ErrorKind::PermissionDenied),
    );
    assert!(matches!(
        FsError::in_anyhow_chain(&infrastructure),
        Some(FsError::Io { .. })
    ));
    let infrastructure =
        ResponseErrorRef::from_anyhow_typed(&infrastructure, ChangedStatus::Conflict)
            .expect("quota infrastructure error is typed");
    assert_eq!(infrastructure.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let denial = quota_hook_policy_denial(Some("alice"), "COPY", Path::new("dest.bin"), Some(23));
    assert!(matches!(
        FsError::in_anyhow_chain(&denial),
        Some(FsError::NoSpace { .. })
    ));
    let denial = ResponseErrorRef::from_anyhow_typed(&denial, ChangedStatus::Conflict)
        .expect("quota policy denial is typed");
    assert_eq!(denial.status(), StatusCode::INSUFFICIENT_STORAGE);
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

fn open_pair(source: &Path, destination: &Path) -> (File, File) {
    let source = OpenOptions::new().read(true).open(source).unwrap();
    let destination = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(destination)
        .unwrap();
    (source, destination)
}

fn executable_script(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("quota-hook.sh");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
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
fn copy_acceleration_keeps_safe_fallback_boundaries() {
    for errno in [
        rustix::io::Errno::XDEV,
        rustix::io::Errno::OPNOTSUPP,
        rustix::io::Errno::NOTTY,
        rustix::io::Errno::INVAL,
    ] {
        assert!(reflink_fallback_error(errno));
    }
    for errno in [
        rustix::io::Errno::NOSPC,
        rustix::io::Errno::DQUOT,
        rustix::io::Errno::IO,
    ] {
        assert!(!reflink_fallback_error(errno));
        assert!(!copy_file_range_fallback_error(errno, true));
    }
    assert!(copy_file_range_fallback_error(
        rustix::io::Errno::INVAL,
        true
    ));
    assert!(!copy_file_range_fallback_error(
        rustix::io::Errno::INVAL,
        false
    ));
}

#[test]
fn cooperative_copy_preserves_content_and_reports_policy_overrun() {
    let dir = TempDir::new().unwrap();
    let source_path = dir.path().join("source");
    std::fs::write(&source_path, b"abcdef").unwrap();

    let (mut source, mut destination) = open_pair(&source_path, &dir.path().join("copy"));
    let outcome = copy_regular_file_cooperatively(
        &mut source,
        &mut destination,
        None,
        &RequestCancellation::new(),
    )
    .unwrap();
    assert_eq!(outcome.bytes, 6);
    assert_eq!(std::fs::read(dir.path().join("copy")).unwrap(), b"abcdef");

    let (mut source, mut destination) = open_pair(&source_path, &dir.path().join("limited-copy"));
    let outcome = copy_regular_file_cooperatively(
        &mut source,
        &mut destination,
        Some(3),
        &RequestCancellation::new(),
    )
    .unwrap();
    assert!(
        outcome.bytes > 3,
        "caller must observe limit + 1/full reflink"
    );
}

#[test]
fn cooperative_copy_observes_preexisting_cancellation() {
    let dir = TempDir::new().unwrap();
    let source_path = dir.path().join("source");
    std::fs::write(&source_path, b"abcdef").unwrap();
    let (mut source, mut destination) = open_pair(&source_path, &dir.path().join("cancelled-copy"));
    let cancellation = RequestCancellation::new();
    cancellation.cancel();
    let error = copy_regular_file_cooperatively(&mut source, &mut destination, None, &cancellation)
        .unwrap_err();
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Cancelled {
            resource: AdmissionResource::CopyBytes,
        })
    ));
    let response = ResponseErrorRef::from_anyhow_typed(&error, ChangedStatus::Conflict)
        .expect("copy cancellation remains typed under context");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(destination.metadata().unwrap().len(), 0);
}

#[test]
fn quota_hook_receives_identity_and_sizes_and_denies_fail_closed() {
    let dir = TempDir::new().unwrap();
    let allow_path = executable_script(
        &dir,
        r#"test "$1" = "--user" && test "$2" = "alice" &&
test "$3" = "--operation" && test "$4" = "COPY" &&
test "$5" = "--path" && test "$6" = "dest.bin" &&
test "$7" = "--current-bytes" && test "$8" = "12" &&
test "$9" = "--final-bytes" && test "${10}" = "34""#,
    );
    let allow = PathIdentity::capture(&allow_path).unwrap();
    run_storage_quota_hook(
        Some(&allow),
        Duration::from_secs(1),
        Some("alice"),
        "COPY",
        Path::new("dest.bin"),
        12,
        34,
        &RequestCancellation::new(),
    )
    .unwrap();

    let deny_path = executable_script(&dir, "exit 17");
    let deny = PathIdentity::capture(&deny_path).unwrap();
    let error = run_storage_quota_hook(
        Some(&deny),
        Duration::from_secs(1),
        Some("alice"),
        "COPY",
        Path::new("dest.bin"),
        0,
        1,
        &RequestCancellation::new(),
    )
    .unwrap_err();
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::NoSpace { .. })
    ));

    let error = run_storage_quota_hook(
        Some(&allow),
        Duration::from_secs(1),
        None,
        "COPY",
        Path::new("dest.bin"),
        0,
        1,
        &RequestCancellation::new(),
    )
    .unwrap_err();
    assert!(matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::NoSpace { .. })
    ));
}

#[test]
fn quota_hook_timeout_kills_descendants_and_is_distinct_from_quota_denial() {
    let dir = TempDir::new().unwrap();
    let child_pid = dir.path().join("child.pid");
    let hook_path = executable_script(
        &dir,
        &format!(
            r#"
/bin/sleep 30 &
echo $! > "{}"
wait"#,
            child_pid.display()
        ),
    );
    let hook = PathIdentity::capture(&hook_path).unwrap();
    let error = run_storage_quota_hook(
        Some(&hook),
        Duration::from_millis(200),
        Some("alice"),
        "PATCH",
        Path::new("dest.bin"),
        1,
        2,
        &RequestCancellation::new(),
    )
    .unwrap_err();
    assert!(matches!(
        AdmissionError::in_anyhow_chain(&error),
        Some(AdmissionError::Timeout {
            kind: super::super::error::AdmissionTimeoutKind::Execution,
            ..
        })
    ));
    assert!(FsError::in_anyhow_chain(&error).is_none());

    let pid: u32 = std::fs::read_to_string(&child_pid)
        .expect("quota hook did not start its descendant")
        .trim()
        .parse()
        .unwrap();
    let descendant_is_running = || {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        stat.rsplit_once(") ")
            .is_some_and(|(_, fields)| !fields.starts_with("Z "))
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    while descendant_is_running() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !descendant_is_running(),
        "quota-hook timeout left descendant pid {pid} running"
    );
}

#[test]
fn quota_hook_executes_pinned_shebang_after_parent_namespace_replacement() {
    let dir = TempDir::new().unwrap();
    let trusted_parent = dir.path().join("trusted");
    std::fs::create_dir(&trusted_parent).unwrap();
    let marker = dir.path().join("marker");
    let trusted_hook = trusted_parent.join("quota-hook.sh");
    std::fs::write(
        &trusted_hook,
        format!("#!/bin/sh\nprintf trusted > \"{}\"\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&trusted_hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    let identity = PathIdentity::capture(&trusted_hook).unwrap();

    let moved_parent = dir.path().join("trusted-before-replacement");
    std::fs::rename(&trusted_parent, &moved_parent).unwrap();
    std::fs::create_dir(&trusted_parent).unwrap();
    let decoy_hook = trusted_parent.join("quota-hook.sh");
    std::fs::write(
        &decoy_hook,
        format!(
            "#!/bin/sh\nprintf decoy > \"{}\"\nexit 23\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&decoy_hook, std::fs::Permissions::from_mode(0o700)).unwrap();

    run_storage_quota_hook(
        Some(&identity),
        Duration::from_secs(1),
        Some("alice"),
        "PUT",
        Path::new("dest.bin"),
        0,
        1,
        &RequestCancellation::new(),
    )
    .unwrap();
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "trusted");
}

#[test]
fn quota_hook_helper_exec_failure_is_not_a_policy_denial() {
    let dir = TempDir::new().unwrap();
    let invalid_hook = dir.path().join("invalid-hook");
    std::fs::write(
        &invalid_hook,
        b"#!/definitely/missing/ram-quota-hook-interpreter\n",
    )
    .unwrap();
    std::fs::set_permissions(&invalid_hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    let identity = PathIdentity::capture(&invalid_hook).unwrap();

    let error = run_storage_quota_hook(
        Some(&identity),
        // cargo-llvm-cov 下辅助进程是插桩 libtest 可执行文件；即使无效 shebang 立即失败，
        // 进程启动和 profile 刷新也可能超过一秒。此分类测试应独立于工具开销。
        // Under cargo-llvm-cov the helper is instrumented libtest; startup/profile flushing may
        // exceed one second although invalid shebang fails immediately. Keep classification independent.
        Duration::from_secs(10),
        Some("alice"),
        "PUT",
        Path::new("dest.bin"),
        0,
        1,
        &RequestCancellation::new(),
    )
    .unwrap_err();
    assert!(!matches!(
        FsError::in_anyhow_chain(&error),
        Some(FsError::NoSpace { .. })
    ));
    assert!(
        error
            .to_string()
            .contains("failed before executing pinned hook"),
        "unexpected quota-hook infrastructure error: {error:#}"
    );
}

#[test]
fn storage_denials_map_to_507_but_internal_errors_do_not() {
    let mut response = Response::default();
    map_local_mutation_error(
        "COPY",
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
        "COPY",
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
fn raced_endpoint_roles_select_412_or_409_without_path_inference() {
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
        let changed_status = copy_move_changed_status(&error, source_status, overwrite);
        let mut response = Response::default();
        map_local_mutation_error(
            "COPY/MOVE",
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
