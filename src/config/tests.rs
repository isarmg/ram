use super::*;
use assert_fs::TempDir;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

fn private_write(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn parse_yaml(extra_yaml: &str, cli: &[&str]) -> (TempDir, Args) {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("share")).unwrap();
    let config = temp.path().join("config.yaml");
    private_write(
        &config,
        format!("serve-path: share\nauth:\n  - user:password@/:rw\n{extra_yaml}\n").as_bytes(),
    );
    let argv = std::iter::once("ram").chain(cli.iter().copied());
    let matches = build_cli().try_get_matches_from(argv).unwrap();
    let args = Args::parse_with_config(matches, Some(&config)).unwrap();
    (temp, args)
}

#[test]
fn personal_intranet_defaults_are_bounded() {
    let args = Args::default();
    assert_eq!(args.max_connections, 64);
    assert_eq!(args.max_concurrent_requests, 32);
    assert_eq!(args.max_concurrent_requests_per_source, 32);
    assert_eq!(args.max_concurrent_requests_per_user, 32);
    assert_eq!(args.max_request_queue, 32);
    assert_eq!(args.max_blocking_threads, 12);
    assert_eq!(args.max_expensive_tasks, 2);
    assert_eq!(args.max_concurrent_uploads, 4);
    assert_eq!(args.max_concurrent_uploads_per_user, 2);
    assert_eq!(args.max_concurrent_uploads_per_source, 3);
    assert_eq!(args.max_search_results, 5_000);
    assert_eq!(args.max_directory_entries, 10_000);
    assert!(args.storage_space_check);
    assert_eq!(args.storage_reserve, 5 * 1024 * 1024 * 1024);
    assert!(args.max_upload_size > 0);
    assert!(args.max_archive_size > 0);
    validate_resource_limits(&args).unwrap();
}

#[test]
fn request_and_upload_limits_reject_unbounded_values() {
    let mut args = Args {
        max_request_queue: KEYED_REQUEST_LIMIT_HARD_MAX,
        ..Args::default()
    };
    validate_resource_limits(&args).unwrap();
    args.max_request_queue += 1;
    assert!(validate_resource_limits(&args).is_err());

    for value in [0, KEYED_REQUEST_LIMIT_HARD_MAX + 1] {
        let args = Args {
            max_concurrent_requests_per_source: value,
            ..Args::default()
        };
        assert!(validate_resource_limits(&args).is_err());
    }
    for value in [0, KEYED_UPLOAD_LIMIT_HARD_MAX + 1] {
        let args = Args {
            max_concurrent_uploads_per_user: value,
            ..Args::default()
        };
        assert!(validate_resource_limits(&args).is_err());
    }
    assert!(
        validate_resource_limits(&Args {
            max_upload_size: 0,
            ..Args::default()
        })
        .is_err()
    );
}

#[test]
fn connection_limit_matches_tokio_semaphore_bounds() {
    let args = Args {
        max_connections: tokio::sync::Semaphore::MAX_PERMITS as u64,
        ..Args::default()
    };
    validate_resource_limits(&args).unwrap();

    for value in [0, tokio::sync::Semaphore::MAX_PERMITS as u64 + 1] {
        let args = Args {
            max_connections: value,
            ..Args::default()
        };
        assert!(validate_resource_limits(&args).is_err());
    }
}

#[test]
fn network_timeouts_are_finite() {
    const MAX: u64 = 7 * 24 * 60 * 60;
    for value in [1, MAX] {
        let args = Args {
            header_read_timeout: value,
            connection_idle_timeout: value,
            connection_max_lifetime: value,
            response_write_idle_timeout: value,
            ..Args::default()
        };
        validate_resource_limits(&args).unwrap();
    }
    for value in [0, MAX + 1] {
        let args = Args {
            header_read_timeout: value,
            ..Args::default()
        };
        assert!(validate_resource_limits(&args).is_err());
    }
}

#[test]
fn upload_modes_parse_as_exact_permission_bits() {
    let yaml: Args =
        serde_yaml_ng::from_str("upload-file-mode: \"0640\"\nupload-dir-mode: \"0750\"\n").unwrap();
    assert_eq!(yaml.upload_file_mode, 0o640);
    assert_eq!(yaml.upload_dir_mode, 0o750);
    assert!(serde_yaml_ng::from_str::<Args>("upload-file-mode: 600\n").is_err());
    assert!(serde_yaml_ng::from_str::<Args>("upload-dir-mode: \"1000\"\n").is_err());

    for upload_dir_mode in [0o000, 0o300, 0o500, 0o677] {
        assert!(
            validate_resource_limits(&Args {
                upload_dir_mode,
                ..Args::default()
            })
            .is_err()
        );
    }
}

#[test]
fn bind_accepts_only_ip_addresses() {
    assert!(BindAddr::parse_addrs(&["127.0.0.1", "::1"]).is_ok());
    assert!(BindAddr::parse_addrs(&["/run/ram.sock"]).is_err());
    assert!(BindAddr::parse_addrs(&["@ram"]).is_err());
}

#[test]
fn path_prefix_is_canonical_or_rejected() {
    for (input, expected) in [
        ("", ""),
        ("/", ""),
        ("/api/files/", "api/files"),
        ("文档/共享", "文档/共享"),
    ] {
        assert_eq!(normalize_path_prefix(input).unwrap(), expected);
    }
    for invalid in [
        "//api/files",
        "api/files//",
        "api//files",
        "api/./files",
        "api/../files",
        "api\\files",
        "api/line\nfeed",
    ] {
        assert!(normalize_path_prefix(invalid).is_err());
    }
}

#[test]
fn removed_options_are_rejected_by_yaml_and_cli() {
    for key in [
        "allow-h2c",
        "trusted-proxy",
        "unix-socket-mode",
        "tls-cert",
        "hsts-max-age",
        "enable-cors",
        "render-spa",
        "assets",
        "allow-hash",
        "max-webdav-properties",
        "max-copy-size",
        "storage-quota-hook",
        "log-file",
    ] {
        assert!(
            serde_yaml_ng::from_str::<Args>(&format!("{key}: true\n")).is_err(),
            "removed YAML key {key} was accepted"
        );
        assert!(
            build_cli()
                .try_get_matches_from(["ram", &format!("--{key}")])
                .is_err(),
            "removed CLI option {key} was accepted"
        );
    }
}

#[test]
fn capability_sources_keep_specific_overrides() {
    struct Case<'a> {
        yaml: &'a str,
        cli: &'a [&'a str],
        expected: [bool; 5],
    }
    let cases = [
        Case {
            yaml: "allow-all: true\nallow-upload: false",
            cli: &[],
            expected: [false, true, true, true, true],
        },
        Case {
            yaml: "allow-upload: true",
            cli: &["--allow-upload=false"],
            expected: [false, false, false, false, false],
        },
        Case {
            yaml: "allow-all: false\nallow-upload: false",
            cli: &["--allow-all", "--allow-delete=false"],
            expected: [true, false, true, true, true],
        },
    ];

    for case in cases {
        let (_temp, args) = parse_yaml(case.yaml, case.cli);
        assert_eq!(
            [
                args.allow_upload,
                args.allow_delete,
                args.allow_search,
                args.allow_symlink,
                args.allow_archive,
            ],
            case.expected
        );
    }
}

#[test]
fn boolean_switches_accept_bare_true_and_explicit_false() {
    for id in [
        "allow-insecure-http",
        "allow-filesystem-root",
        "allow-all",
        "allow-upload",
        "allow-delete",
        "allow-search",
        "allow-symlink",
        "allow-archive",
        "storage-space-check",
    ] {
        let bare = format!("--{id}");
        let matches = build_cli()
            .try_get_matches_from(["ram", bare.as_str()])
            .unwrap();
        assert_eq!(explicit_bool(&matches, id), Some(true));

        let disabled = format!("--{id}=false");
        let matches = build_cli()
            .try_get_matches_from(["ram", disabled.as_str()])
            .unwrap();
        assert_eq!(explicit_bool(&matches, id), Some(false));
    }
}

#[test]
fn auth_file_is_private_bounded_and_unambiguous() {
    let temp = TempDir::new().unwrap();
    let auth = temp.path().join("auth.rules");
    private_write(&auth, b"user:password@/:rw\nreader:password@/public:ro\n");
    assert!(load_auth_file(&auth).unwrap().has_users());

    private_write(&auth, b"user:first@/:rw\nuser:second@/public:ro\n");
    assert!(load_auth_file(&auth).is_err());
    private_write(&auth, &vec![b'x'; AUTH_FILE_MAX_BYTES as usize + 1]);
    assert!(load_auth_file(&auth).is_err());

    private_write(&auth, b"user:password@/:rw\n");
    let link = temp.path().join("auth.link");
    symlink(&auth, &link).unwrap();
    assert!(load_auth_file(&link).is_err());
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_auth_file(&auth).is_err());
}

#[test]
fn pinned_configuration_and_auth_inputs_survive_parent_replacement() {
    fn capture_then_replace(
        file_name: &str,
        original: &[u8],
        decoy: &[u8],
    ) -> (TempDir, PathIdentity) {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().join("inputs");
        let moved = temp.path().join("inputs-pinned");
        fs::create_dir(&parent).unwrap();
        let path = parent.join(file_name);
        private_write(&path, original);
        let identity = PathIdentity::capture(&path).unwrap();
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        private_write(&parent.join(file_name), decoy);
        (temp, identity)
    }

    let (_config_temp, config) =
        capture_then_replace("config.yaml", b"port: 5101\n", b"port: 6202\n");
    let bytes = read_private_file_from_identity(
        &config,
        "configuration",
        PRIVATE_CONFIG_MAX_BYTES,
        PrivateFileAccess::IntegrityOnly,
    )
    .unwrap();
    let parsed: Args = serde_yaml_ng::from_slice(&bytes).unwrap();
    assert_eq!(parsed.port, 5101);

    let (_auth_temp, auth) =
        capture_then_replace("auth.rules", b"user:password@/:rw\n", b"invalid decoy\n");
    assert!(load_auth_file_from_identity(&auth).unwrap().has_users());
}

#[test]
fn configuration_and_auth_cannot_be_served() {
    for authentication in [false, true] {
        let temp = TempDir::new().unwrap();
        let served = temp.path().join("served");
        fs::create_dir(&served).unwrap();
        let sensitive = served.join("sensitive");
        private_write(&sensitive, b"user:password@/:rw\n");

        let mut args = Args {
            serve_path: served,
            ..Args::default()
        };
        let config = if authentication {
            args.auth_file = Some(sensitive);
            None
        } else {
            Some(sensitive)
        };
        let error = validate_path_isolation(&args, config.as_deref()).unwrap_err();
        assert!(error.to_string().contains("served path"));
    }
}
