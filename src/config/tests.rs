use super::*;

#[cfg(test)]
mod network_identity_and_mode_config_tests {
    use super::*;

    #[test]
    fn request_queue_boundaries_are_zero_max_and_max_plus_one() {
        let mut args = Args {
            max_request_queue: 0,
            ..Args::default()
        };
        validate_resource_limits(&args).unwrap();
        args.max_request_queue = KEYED_REQUEST_LIMIT_HARD_MAX;
        validate_resource_limits(&args).unwrap();
        args.max_request_queue = KEYED_REQUEST_LIMIT_HARD_MAX + 1;
        assert!(validate_resource_limits(&args).is_err());
    }

    #[test]
    fn keyed_request_and_network_timeout_boundaries_are_explicit() {
        for value in [1, KEYED_REQUEST_LIMIT_HARD_MAX] {
            let args = Args {
                max_concurrent_requests_per_source: value,
                max_concurrent_requests_per_user: value,
                ..Args::default()
            };
            validate_resource_limits(&args).unwrap();
        }
        for (source, user) in [
            (0, 1),
            (KEYED_REQUEST_LIMIT_HARD_MAX + 1, 1),
            (1, 0),
            (1, KEYED_REQUEST_LIMIT_HARD_MAX + 1),
        ] {
            let args = Args {
                max_concurrent_requests_per_source: source,
                max_concurrent_requests_per_user: user,
                ..Args::default()
            };
            assert!(validate_resource_limits(&args).is_err());
        }

        for value in [1, 60] {
            let args = Args {
                request_queue_timeout: value,
                ..Args::default()
            };
            validate_resource_limits(&args).unwrap();
        }
        for value in [0, 61] {
            let args = Args {
                request_queue_timeout: value,
                ..Args::default()
            };
            assert!(validate_resource_limits(&args).is_err());
        }

        const MAX_NETWORK_TIMEOUT: u64 = 7 * 24 * 60 * 60;
        for value in [1, MAX_NETWORK_TIMEOUT] {
            let args = Args {
                header_read_timeout: value,
                connection_idle_timeout: value,
                connection_max_lifetime: value,
                response_write_idle_timeout: value,
                ..Args::default()
            };
            validate_resource_limits(&args).unwrap();
        }
        for value in [0, MAX_NETWORK_TIMEOUT + 1] {
            for field in 0..4 {
                let mut args = Args::default();
                match field {
                    0 => args.header_read_timeout = value,
                    1 => args.connection_idle_timeout = value,
                    2 => args.connection_max_lifetime = value,
                    3 => args.response_write_idle_timeout = value,
                    _ => unreachable!(),
                }
                assert!(validate_resource_limits(&args).is_err());
            }
        }
    }

    #[test]
    fn upload_modes_default_and_parse_as_exact_permission_bits() {
        let defaults = Args::default();
        assert_eq!(defaults.upload_file_mode, 0o600);
        assert_eq!(defaults.upload_dir_mode, 0o700);

        let yaml: Args =
            serde_yaml_ng::from_str("upload-file-mode: \"0640\"\nupload-dir-mode: \"0750\"\n")
                .unwrap();
        assert_eq!(yaml.upload_file_mode, 0o640);
        assert_eq!(yaml.upload_dir_mode, 0o750);
        assert!(serde_yaml_ng::from_str::<Args>("upload-file-mode: 600\n").is_err());
        assert!(serde_yaml_ng::from_str::<Args>("upload-dir-mode: \"1000\"\n").is_err());

        let matches = build_cli()
            .try_get_matches_from([
                "ram",
                "--upload-file-mode",
                "0000",
                "--upload-dir-mode",
                "0777",
            ])
            .unwrap();
        assert_eq!(matches.get_one::<u32>("upload-file-mode"), Some(&0));
        assert_eq!(matches.get_one::<u32>("upload-dir-mode"), Some(&0o777));

        let args = Args {
            upload_file_mode: 0o1000,
            ..Args::default()
        };
        assert!(validate_resource_limits(&args).is_err());

        for upload_dir_mode in [0o000, 0o300, 0o500, 0o677] {
            let args = Args {
                upload_dir_mode,
                ..Args::default()
            };
            assert!(
                validate_resource_limits(&args).is_err(),
                "owner-inaccessible upload directory mode {upload_dir_mode:04o} was accepted"
            );
        }
        for upload_dir_mode in [0o700, 0o750, 0o777] {
            let args = Args {
                upload_dir_mode,
                ..Args::default()
            };
            validate_resource_limits(&args).unwrap();
        }
    }

    #[test]
    fn trusted_proxy_requires_an_explicit_bounded_pair() {
        let mut args = Args {
            trusted_proxy: vec!["127.0.0.1/32".parse().unwrap()],
            ..Args::default()
        };
        assert!(validate_resource_limits(&args).is_err());

        args.trusted_proxy_header = Some(ForwardedHeader::XForwardedFor);
        validate_resource_limits(&args).unwrap();
        args.trusted_proxy.push("127.0.0.1/32".parse().unwrap());
        assert!(validate_resource_limits(&args).is_err());

        let header_without_proxy = Args {
            trusted_proxy_header: Some(ForwardedHeader::XRealIp),
            ..Args::default()
        };
        assert!(validate_resource_limits(&header_without_proxy).is_err());
    }

    #[test]
    fn trusted_proxy_allowlist_accepts_max_and_rejects_max_plus_one() {
        let proxies = (0..=TRUSTED_PROXY_MAX_ENTRIES)
            .map(|index| {
                format!("10.0.{}.{}/32", index / 256, index % 256)
                    .parse::<IpCidr>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut args = Args {
            trusted_proxy: proxies[..TRUSTED_PROXY_MAX_ENTRIES].to_vec(),
            trusted_proxy_header: Some(ForwardedHeader::XForwardedFor),
            ..Args::default()
        };
        validate_resource_limits(&args).unwrap();
        args.trusted_proxy.push(proxies[TRUSTED_PROXY_MAX_ENTRIES]);
        assert!(validate_resource_limits(&args).is_err());
    }

    #[test]
    fn abstract_socket_and_reserved_owner_ids_fail_closed() {
        let abstract_default = Args {
            addrs: vec![BindAddr::SocketPath("@ram-test".to_string())],
            ..Args::default()
        };
        assert!(validate_resource_limits(&abstract_default).is_err());

        let abstract_explicit = Args {
            allow_abstract_unix_socket: true,
            ..abstract_default
        };
        validate_resource_limits(&abstract_explicit).unwrap();

        let invalid_uid = Args {
            unix_socket_uid: Some(u32::MAX),
            ..Args::default()
        };
        assert!(validate_resource_limits(&invalid_uid).is_err());
    }

    #[test]
    fn path_prefix_is_canonical_or_rejected_at_startup() {
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
            assert!(
                normalize_path_prefix(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert!(normalize_path_prefix(&"x".repeat(PATH_PREFIX_MAX_BYTES)).is_ok());
        assert!(normalize_path_prefix(&"x".repeat(PATH_PREFIX_MAX_BYTES + 1)).is_err());
        assert!(normalize_path_prefix(&"/".repeat(PATH_PREFIX_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn bind_path_resolution_changes_only_relative_pathname_sockets() {
        let mut addrs = vec![
            BindAddr::IpAddr("127.0.0.1".parse().unwrap()),
            BindAddr::SocketPath("relative.sock".to_owned()),
            BindAddr::SocketPath("/run/ram/absolute.sock".to_owned()),
            BindAddr::SocketPath("@ram-abstract".to_owned()),
        ];
        resolve_pathname_bind_addrs(&mut addrs, Path::new("/etc/ram")).unwrap();
        assert_eq!(
            addrs,
            vec![
                BindAddr::IpAddr("127.0.0.1".parse().unwrap()),
                BindAddr::SocketPath("/etc/ram/relative.sock".to_owned()),
                BindAddr::SocketPath("/run/ram/absolute.sock".to_owned()),
                BindAddr::SocketPath("@ram-abstract".to_owned()),
            ]
        );
    }
}

/// 布尔开关使用值而非 `SetTrue` 标志，使每个 CLI/环境来源都有缺失、true、false 三种状态。
/// 缺省值仍按 true 处理以兼容 `--allow-upload`，运维人员也可用 `--allow-upload=false`
/// 显式覆盖 YAML。
/// Boolean switches are values rather than `SetTrue` flags so every CLI/environment source has
/// absent, true, and false states. A missing value stays true for compatibility, while false can
/// explicitly override YAML.
#[cfg(test)]
mod p0_upload_limit_tests {
    use super::{
        Args, KEYED_UPLOAD_LIMIT_HARD_MAX, STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX,
        STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX, STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX,
        STALE_UPLOAD_CLEANUP_TIMEOUT_HARD_MAX_SECS, validate_resource_limits,
    };

    #[test]
    fn upload_identity_and_cleanup_defaults_are_bounded() {
        let args = Args::default();
        assert_eq!(args.max_concurrent_uploads_per_user, 2);
        assert_eq!(args.max_concurrent_uploads_per_source, 2);
        assert_eq!(args.stale_upload_cleanup_age, 24 * 60 * 60);
        assert_eq!(args.stale_upload_cleanup_max_entries, 100_000);
        assert_eq!(args.stale_upload_cleanup_max_depth, 64);
        assert_eq!(args.stale_upload_cleanup_max_deletions, 1_000);
        assert_eq!(args.stale_upload_cleanup_timeout, 5);
        validate_resource_limits(&args).unwrap();
    }

    #[test]
    fn upload_identity_and_cleanup_hard_boundaries_are_enforced() {
        let mut args = Args {
            max_concurrent_uploads_per_user: KEYED_UPLOAD_LIMIT_HARD_MAX,
            max_concurrent_uploads_per_source: KEYED_UPLOAD_LIMIT_HARD_MAX,
            stale_upload_cleanup_max_entries: STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX,
            stale_upload_cleanup_max_depth: STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX,
            stale_upload_cleanup_max_deletions: STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX,
            stale_upload_cleanup_timeout: STALE_UPLOAD_CLEANUP_TIMEOUT_HARD_MAX_SECS,
            ..Args::default()
        };
        validate_resource_limits(&args).unwrap();

        args.max_concurrent_uploads_per_user = KEYED_UPLOAD_LIMIT_HARD_MAX + 1;
        assert!(validate_resource_limits(&args).is_err());
        args.max_concurrent_uploads_per_user = KEYED_UPLOAD_LIMIT_HARD_MAX;
        args.max_concurrent_uploads_per_source = 0;
        assert!(validate_resource_limits(&args).is_err());
        args.max_concurrent_uploads_per_source = KEYED_UPLOAD_LIMIT_HARD_MAX;
        args.stale_upload_cleanup_max_entries = STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX + 1;
        assert!(validate_resource_limits(&args).is_err());
        args.stale_upload_cleanup_max_entries = STALE_UPLOAD_CLEANUP_MAX_ENTRIES_HARD_MAX;
        args.stale_upload_cleanup_max_depth = STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX + 1;
        assert!(validate_resource_limits(&args).is_err());
        args.stale_upload_cleanup_max_depth = STALE_UPLOAD_CLEANUP_MAX_DEPTH_HARD_MAX;
        args.stale_upload_cleanup_max_deletions = STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX + 1;
        assert!(validate_resource_limits(&args).is_err());
        args.stale_upload_cleanup_max_deletions = STALE_UPLOAD_CLEANUP_MAX_DELETIONS_HARD_MAX;
        args.stale_upload_cleanup_timeout = STALE_UPLOAD_CLEANUP_TIMEOUT_HARD_MAX_SECS + 1;
        assert!(validate_resource_limits(&args).is_err());
    }
}

#[cfg(test)]
mod p1_config_source_tests {
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
    fn capability_sources_follow_documented_aggregate_then_specific_order() {
        struct Case<'a> {
            yaml: &'a str,
            cli: &'a [&'a str],
            expected: [bool; 6],
        }
        let cases = [
            Case {
                yaml: "allow-all: true\nallow-upload: false",
                cli: &[],
                expected: [false, true, true, true, true, true],
            },
            Case {
                yaml: "allow-upload: true",
                cli: &["--allow-upload=false"],
                expected: [false, false, false, false, false, false],
            },
            Case {
                yaml: "allow-all: false\nallow-upload: false",
                cli: &["--allow-all", "--allow-delete=false"],
                expected: [true, false, true, true, true, true],
            },
            Case {
                yaml: "allow-all: true\nallow-upload: true",
                cli: &["--allow-all=false", "--allow-search=true"],
                expected: [false, false, true, false, false, false],
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
                    args.allow_hash,
                ],
                case.expected,
                "yaml={} cli={:?}",
                case.yaml,
                case.cli
            );
        }
    }

    #[test]
    fn every_boolean_switch_accepts_bare_true_and_explicit_false() {
        let ids = [
            "allow-insecure-http",
            "allow-filesystem-root",
            "allow-active-content-risk",
            "allow-h2c",
            "allow-all",
            "allow-upload",
            "allow-delete",
            "allow-search",
            "allow-symlink",
            "allow-archive",
            "allow-hash",
            "enable-cors",
            "render-index",
            "render-try-index",
            "render-spa",
            "storage-space-check",
        ];
        for id in ids {
            let bare = format!("--{id}");
            let matches = build_cli()
                .try_get_matches_from(["ram", bare.as_str()])
                .unwrap();
            assert_eq!(explicit_bool(&matches, id), Some(true), "{id}");

            let disabled = format!("--{id}=false");
            let matches = build_cli()
                .try_get_matches_from(["ram", disabled.as_str()])
                .unwrap();
            assert_eq!(explicit_bool(&matches, id), Some(false), "{id}");
        }
    }

    #[test]
    fn non_capability_yaml_true_is_overridden_by_cli_false() {
        let (_temp, args) = parse_yaml(
            "enable-cors: true\nrender-index: true\nallow-active-content-risk: true\nstorage-space-check: true",
            &[
                "--enable-cors=false",
                "--render-index=false",
                "--allow-active-content-risk=false",
                "--storage-space-check=false",
            ],
        );
        assert!(!args.enable_cors);
        assert!(!args.render_index);
        assert!(!args.allow_active_content_risk);
        assert!(!args.storage_space_check);
    }

    #[test]
    fn auth_file_is_bounded_private_and_rejects_duplicate_users() {
        let temp = TempDir::new().unwrap();
        let auth = temp.path().join("auth.rules");
        private_write(
            &auth,
            b"# managed credential\nuser:password@/:rw\nreader:password@/public:ro\n",
        );
        assert!(load_auth_file(&auth).unwrap().has_users());

        private_write(&auth, b"user:first@/:rw\nuser:second@/public:ro\n");
        assert!(
            load_auth_file(&auth)
                .unwrap_err()
                .to_string()
                .contains("Failed to load")
        );

        private_write(&auth, &vec![b'x'; AUTH_FILE_MAX_BYTES as usize + 1]);
        assert!(
            load_auth_file(&auth)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );

        private_write(&auth, "\n".repeat(AUTH_FILE_MAX_LINES + 1).as_bytes());
        assert!(
            load_auth_file(&auth)
                .unwrap_err()
                .to_string()
                .contains("line limit")
        );

        private_write(&auth, &vec![b'x'; AUTH_FILE_MAX_LINE_BYTES + 1]);
        assert!(
            load_auth_file(&auth)
                .unwrap_err()
                .to_string()
                .contains("line 1 exceeds")
        );

        for ambiguous_rule in [" user:secret-value@/:rw\n", "user:secret-value@/:rw \n"] {
            private_write(&auth, ambiguous_rule.as_bytes());
            let error = load_auth_file(&auth).unwrap_err().to_string();
            assert!(error.contains("leading or trailing whitespace"));
            assert!(!error.contains("secret-value"));
        }

        private_write(
            &auth,
            b"   # indented comment is ignored\n\t\nuser:internal space@/:rw\n",
        );
        assert!(load_auth_file(&auth).is_ok());
    }

    #[test]
    fn auth_file_rejects_symlinks_and_every_non_private_secret_mode() {
        let temp = TempDir::new().unwrap();
        let auth = temp.path().join("auth.rules");
        private_write(&auth, b"user:password@/:rw\n");
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("auth.link");
        symlink(&auth, &link).unwrap();
        assert!(load_auth_file(&link).is_err());

        for rejected_mode in [
            0o000, 0o200, 0o500, 0o700, 0o640, 0o644, 0o1600, 0o2600, 0o4600,
        ] {
            fs::set_permissions(&auth, fs::Permissions::from_mode(rejected_mode)).unwrap();
            assert!(
                load_auth_file(&auth)
                    .unwrap_err()
                    .to_string()
                    .contains("must use mode 0400 or 0600"),
                "mode {rejected_mode:04o} must be rejected"
            );
        }

        for accepted_mode in [0o400, 0o600] {
            fs::set_permissions(&auth, fs::Permissions::from_mode(accepted_mode)).unwrap();
            assert!(
                load_auth_file(&auth).is_ok(),
                "mode {accepted_mode:04o} must be accepted"
            );
        }
    }

    #[test]
    fn private_file_read_rejects_in_place_change_and_truncation() {
        let temp = TempDir::new().unwrap();
        let secret = temp.path().join("credential");
        private_write(&secret, b"original-credential");
        let error = read_private_file_with(
            &secret,
            "test credential",
            1024,
            PrivateFileAccess::Secret,
            || {
                fs::write(&secret, b"changed--credential").unwrap();
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being read")
        );

        private_write(&secret, b"original-credential");
        let error = read_private_file_with(
            &secret,
            "test credential",
            1024,
            PrivateFileAccess::Secret,
            || {
                File::options()
                    .write(true)
                    .open(&secret)
                    .unwrap()
                    .set_len(4)
                    .unwrap();
            },
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being read")
        );
    }

    fn capture_then_replace_parent(
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

    #[test]
    fn configuration_auth_and_token_consumers_read_pinned_inputs_after_parent_replacement() {
        let (_config_temp, config) =
            capture_then_replace_parent("config.yaml", b"port: 5101\n", b"port: 6202\n");
        let config_bytes = read_private_file_from_identity(
            &config,
            "configuration",
            PRIVATE_CONFIG_MAX_BYTES,
            PrivateFileAccess::IntegrityOnly,
        )
        .unwrap();
        let parsed: Args = serde_yaml_ng::from_slice(&config_bytes).unwrap();
        assert_eq!(parsed.port, 5101);

        let (_auth_temp, auth) = capture_then_replace_parent(
            "auth.rules",
            b"user:password@/:rw\n",
            b"this decoy is not a valid auth rule\n",
        );
        assert!(load_auth_file_from_identity(&auth).unwrap().has_users());

        let original_secret = b"0123456789abcdef0123456789abcdef\n";
        let (_token_temp, token) =
            capture_then_replace_parent("token.secret", original_secret, b"decoy\n");
        assert_eq!(
            read_token_secret_from_identity(&token).unwrap(),
            &original_secret[..original_secret.len() - 1]
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_consumers_parse_pinned_certificate_and_key_after_parent_replacement() {
        use crate::utils::{load_certs_from_reader, load_private_key_from_reader};

        let (_cert_temp, cert) = capture_then_replace_parent(
            "server.crt",
            include_bytes!("../../tests/data/cert.pem"),
            b"not a certificate\n",
        );
        let certs =
            load_certs_from_reader(cert.open_regular_file_pinned().unwrap(), cert.canonical())
                .unwrap();
        assert!(!certs.is_empty());

        let (_key_temp, key) = capture_then_replace_parent(
            "server.key",
            include_bytes!("../../tests/data/key_pkcs8.pem"),
            b"not a private key\n",
        );
        load_private_key_from_reader(key.open_regular_file_pinned().unwrap(), key.canonical())
            .unwrap();
    }
}

#[cfg(test)]
mod p0_path_isolation_tests {
    use super::*;
    use assert_fs::TempDir;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Clone, Copy, Debug)]
    enum SensitiveKind {
        Configuration,
        TlsCertificate,
        TlsKey,
        Authentication,
        TokenSecret,
        TokenRevocation,
        AccessLog,
        QuotaHook,
    }

    fn apply_sensitive_path(args: &mut Args, kind: SensitiveKind, path: &Path) -> Option<PathBuf> {
        match kind {
            SensitiveKind::Configuration => Some(path.to_path_buf()),
            SensitiveKind::TlsCertificate => {
                args.tls_cert = Some(path.to_path_buf());
                None
            }
            SensitiveKind::TlsKey => {
                args.tls_key = Some(path.to_path_buf());
                None
            }
            SensitiveKind::Authentication => {
                args.auth_file = Some(path.to_path_buf());
                None
            }
            SensitiveKind::TokenSecret => {
                args.token_secret_file = Some(path.to_path_buf());
                None
            }
            SensitiveKind::TokenRevocation => {
                args.token_revocation_file = Some(path.to_path_buf());
                None
            }
            SensitiveKind::AccessLog => {
                args.log_file = Some(path.to_path_buf());
                None
            }
            SensitiveKind::QuotaHook => {
                args.storage_quota_hook = Some(path.to_path_buf());
                None
            }
        }
    }

    fn args_for(path: &Path, path_is_file: bool) -> Args {
        Args {
            serve_path: path.to_path_buf(),
            path_is_file,
            ..Args::default()
        }
    }

    #[test]
    fn every_sensitive_path_is_rejected_inside_directory_and_equal_single_file() {
        let kinds = [
            SensitiveKind::Configuration,
            SensitiveKind::TlsCertificate,
            SensitiveKind::TlsKey,
            SensitiveKind::Authentication,
            SensitiveKind::TokenSecret,
            SensitiveKind::TokenRevocation,
            SensitiveKind::AccessLog,
            SensitiveKind::QuotaHook,
        ];

        for kind in kinds {
            let temp = TempDir::new().unwrap();
            let served = temp.path().join("served");
            let outside = temp.path().join("outside");
            fs::create_dir(&served).unwrap();
            fs::create_dir(&outside).unwrap();
            let inside_path = served.join("sensitive");
            let outside_path = outside.join("sensitive");
            fs::write(&inside_path, b"sensitive").unwrap();
            fs::write(&outside_path, b"sensitive").unwrap();
            let mode = if matches!(kind, SensitiveKind::QuotaHook) {
                0o700
            } else {
                0o600
            };
            fs::set_permissions(&inside_path, fs::Permissions::from_mode(mode)).unwrap();
            fs::set_permissions(&outside_path, fs::Permissions::from_mode(mode)).unwrap();

            let mut inside_args = args_for(&served, false);
            let inside_config = apply_sensitive_path(&mut inside_args, kind, &inside_path);
            let error =
                validate_path_isolation(&inside_args, inside_config.as_deref()).unwrap_err();
            assert!(
                error.to_string().contains("served path"),
                "{kind:?}: {error:#}"
            );

            let mut outside_args = args_for(&served, false);
            let outside_config = apply_sensitive_path(&mut outside_args, kind, &outside_path);
            validate_path_isolation(&outside_args, outside_config.as_deref()).unwrap();

            let mut single_args = args_for(&outside_path, true);
            let single_config = apply_sensitive_path(&mut single_args, kind, &outside_path);
            let error =
                validate_path_isolation(&single_args, single_config.as_deref()).unwrap_err();
            assert!(
                error.to_string().contains("served path"),
                "{kind:?}: {error:#}"
            );
        }
    }

    #[test]
    fn every_sensitive_path_is_rejected_inside_unauthenticated_custom_assets() {
        let kinds = [
            SensitiveKind::Configuration,
            SensitiveKind::TlsCertificate,
            SensitiveKind::TlsKey,
            SensitiveKind::Authentication,
            SensitiveKind::TokenSecret,
            SensitiveKind::TokenRevocation,
            SensitiveKind::AccessLog,
            SensitiveKind::QuotaHook,
        ];

        for kind in kinds {
            let temp = TempDir::new().unwrap();
            let served = temp.path().join("served");
            let assets = temp.path().join("assets");
            fs::create_dir(&served).unwrap();
            fs::create_dir(&assets).unwrap();
            let sensitive = assets.join("sensitive");
            fs::write(&sensitive, b"sensitive").unwrap();
            let mode = if matches!(kind, SensitiveKind::QuotaHook) {
                0o700
            } else {
                0o600
            };
            fs::set_permissions(&sensitive, fs::Permissions::from_mode(mode)).unwrap();

            let mut args = args_for(&served, false);
            args.assets = Some(assets);
            let config = apply_sensitive_path(&mut args, kind, &sensitive);
            let error = validate_path_isolation(&args, config.as_deref()).unwrap_err();
            assert!(
                error.to_string().contains("custom assets"),
                "{kind:?}: {error:#}"
            );
        }
    }

    #[test]
    fn assets_overlap_is_directional_but_uses_object_identity() {
        let temp = TempDir::new().unwrap();
        let outer = temp.path().join("outer");
        let served = outer.join("served");
        let assets_child = served.join("assets");
        fs::create_dir_all(&assets_child).unwrap();

        let mut assets_contain_served = args_for(&served, false);
        assets_contain_served.assets = Some(outer.clone());
        assert!(
            validate_path_isolation(&assets_contain_served, None)
                .unwrap_err()
                .to_string()
                .contains("would bypass authentication")
        );

        let mut read_only_child = args_for(&served, false);
        read_only_child.assets = Some(assets_child.clone());
        validate_path_isolation(&read_only_child, None).unwrap();

        read_only_child.allow_upload = true;
        assert!(
            validate_path_isolation(&read_only_child, None)
                .unwrap_err()
                .to_string()
                .contains("writable assets directory")
        );
    }

    #[test]
    fn hard_link_aliases_are_rejected_by_input_and_output_integrity_policy() {
        let temp = TempDir::new().unwrap();
        let outside = temp.path().join("outside-secret");
        let served = temp.path().join("served");
        fs::create_dir(&served).unwrap();
        fs::write(&outside, b"secret").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&outside, served.join("alias")).unwrap();

        assert!(validate_private_input_file(&outside, "sensitive input").is_err());
        assert!(validate_private_output_if_exists(&outside, "sensitive output").is_err());
    }

    #[test]
    fn output_parent_symlink_into_served_tree_is_detected_by_parent_identity() {
        let temp = TempDir::new().unwrap();
        let served = temp.path().join("served");
        let control = temp.path().join("control");
        fs::create_dir(&served).unwrap();
        fs::create_dir(&control).unwrap();
        std::os::unix::fs::symlink(&served, control.join("served-alias")).unwrap();

        let mut args = args_for(&served, false);
        args.log_file = Some(control.join("served-alias/access.log"));
        let error = validate_path_isolation(&args, None).unwrap_err();
        assert!(error.to_string().contains("access log"));
        assert!(error.to_string().contains("served path"));
    }

    #[test]
    fn pathname_unix_socket_is_rejected_inside_served_or_custom_assets_trees() {
        let temp = TempDir::new().unwrap();
        let served = temp.path().join("served");
        let assets = temp.path().join("assets");
        let control = temp.path().join("control");
        fs::create_dir(&served).unwrap();
        fs::create_dir(&assets).unwrap();
        fs::create_dir(&control).unwrap();

        let mut served_args = args_for(&served, false);
        served_args.addrs = vec![BindAddr::SocketPath(
            served.join("ram.sock").to_string_lossy().into_owned(),
        )];
        let error = validate_path_isolation(&served_args, None).unwrap_err();
        assert!(error.to_string().contains("Unix socket"), "{error:#}");
        assert!(error.to_string().contains("served path"), "{error:#}");

        let mut assets_args = args_for(&served, false);
        assets_args.assets = Some(assets.clone());
        assets_args.addrs = vec![BindAddr::SocketPath(
            assets.join("ram.sock").to_string_lossy().into_owned(),
        )];
        let error = validate_path_isolation(&assets_args, None).unwrap_err();
        assert!(error.to_string().contains("Unix socket"), "{error:#}");
        assert!(error.to_string().contains("custom assets"), "{error:#}");

        let mut outside_args = args_for(&served, false);
        outside_args.assets = Some(assets);
        outside_args.addrs = vec![BindAddr::SocketPath(
            control.join("ram.sock").to_string_lossy().into_owned(),
        )];
        validate_path_isolation(&outside_args, None).unwrap();

        // 抽象套接字没有可暴露路径名；其独立 allow-abstract-unix-socket 启动策略仍为权威。
        // Abstract sockets have no pathname to expose; their separate startup policy remains authoritative.
        outside_args.addrs = vec![BindAddr::SocketPath("@ram-tests".to_owned())];
        validate_path_isolation(&outside_args, None).unwrap();
    }

    #[test]
    fn access_log_cannot_alias_any_existing_sensitive_input() {
        for kind in [
            SensitiveKind::Configuration,
            SensitiveKind::TlsCertificate,
            SensitiveKind::TlsKey,
            SensitiveKind::Authentication,
            SensitiveKind::TokenSecret,
            SensitiveKind::QuotaHook,
        ] {
            let temp = TempDir::new().unwrap();
            let served = temp.path().join("served");
            let control = temp.path().join("control");
            fs::create_dir(&served).unwrap();
            fs::create_dir(&control).unwrap();
            let shared = control.join("sensitive");
            fs::write(&shared, b"sensitive").unwrap();
            let mode = if matches!(kind, SensitiveKind::QuotaHook) {
                0o700
            } else {
                0o600
            };
            fs::set_permissions(&shared, fs::Permissions::from_mode(mode)).unwrap();

            let mut args = args_for(&served, false);
            let config = apply_sensitive_path(&mut args, kind, &shared);
            args.log_file = Some(shared.clone());
            let error = validate_path_isolation(&args, config.as_deref()).unwrap_err();
            assert!(
                error.to_string().contains("shares a filesystem object"),
                "{kind:?}: {error:#}"
            );
        }
    }

    #[test]
    fn log_and_revocation_outputs_cannot_share_absent_namespace_slots() {
        let temp = TempDir::new().unwrap();
        let served = temp.path().join("served");
        let control = temp.path().join("control");
        fs::create_dir(&served).unwrap();
        fs::create_dir(&control).unwrap();

        let state = control.join("revocations.json");
        let same_state = Args {
            serve_path: served.clone(),
            token_revocation_file: Some(state.clone()),
            log_file: Some(state.clone()),
            ..Args::default()
        };
        let error = validate_path_isolation(&same_state, None).unwrap_err();
        assert!(error.to_string().contains("shares a namespace slot"));

        let lock = PathBuf::from(format!("{}.lock", state.display()));
        let same_lock = Args {
            serve_path: served,
            token_revocation_file: Some(state),
            log_file: Some(lock),
            ..Args::default()
        };
        let error = validate_path_isolation(&same_lock, None).unwrap_err();
        assert!(error.to_string().contains("shares a namespace slot"));
    }

    #[test]
    fn every_log_rotation_slot_is_reserved_against_sensitive_capabilities() {
        let temp = TempDir::new().unwrap();
        let served = temp.path().join("served");
        let control = temp.path().join("control");
        fs::create_dir(&served).unwrap();
        fs::create_dir(&control).unwrap();
        let log = control.join("access.log");

        let first_backup = crate::logging::rotated_path(&log, 1);
        fs::write(&first_backup, b"user:password@/:rw\n").unwrap();
        fs::set_permissions(&first_backup, fs::Permissions::from_mode(0o600)).unwrap();
        let auth_collision = Args {
            serve_path: served.clone(),
            auth_file: Some(first_backup),
            log_file: Some(log.clone()),
            ..Args::default()
        };
        let error = validate_path_isolation(&auth_collision, None).unwrap_err();
        assert!(error.to_string().contains("shares a filesystem object"));

        let revocations = control.join("revocations.json");
        let revocation_lock = PathBuf::from(format!("{}.lock", revocations.display()));
        fs::write(&revocation_lock, b"lock").unwrap();
        fs::set_permissions(&revocation_lock, fs::Permissions::from_mode(0o600)).unwrap();
        let last_backup =
            crate::logging::rotated_path(&log, crate::logging::DEFAULT_ROTATE_BACKUPS);
        fs::hard_link(&revocation_lock, &last_backup).unwrap();
        let lock_alias_collision = Args {
            serve_path: served,
            token_revocation_file: Some(revocations),
            log_file: Some(log),
            ..Args::default()
        };
        let error = validate_path_isolation(&lock_alias_collision, None).unwrap_err();
        assert!(error.to_string().contains("shares a filesystem object"));
    }

    #[test]
    fn log_rotation_backup_cannot_be_the_served_single_file() {
        let temp = TempDir::new().unwrap();
        let control = temp.path().join("control");
        fs::create_dir(&control).unwrap();
        let log = control.join("access.log");
        let backup = crate::logging::rotated_path(&log, 1);
        fs::write(&backup, b"previous access log").unwrap();
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();

        // 中文：active log 本身不是服务文件；该断言单独证明派生 `.1` 槽也会走暴露检查。
        // English: The active log is not served; this isolates proof that the derived `.1` slot is exposure-checked too.
        let args = Args {
            serve_path: backup,
            path_is_file: true,
            log_file: Some(log),
            ..Args::default()
        };
        let error = validate_path_isolation(&args, None).unwrap_err();
        assert!(
            error.to_string().contains("access log rotation backup"),
            "unexpected backup-exposure error: {error:#}"
        );
        assert!(error.to_string().contains("served path"), "{error:#}");
    }

    #[test]
    fn pathname_listener_slots_conflict_with_logs_revocation_and_each_other() {
        let temp = TempDir::new().unwrap();
        let served = temp.path().join("served");
        let control = temp.path().join("control");
        fs::create_dir(&served).unwrap();
        fs::create_dir(&control).unwrap();
        let log = control.join("access.log");
        let backup = crate::logging::rotated_path(&log, 1);

        let socket_log_collision = Args {
            serve_path: served.clone(),
            addrs: vec![BindAddr::SocketPath(backup.to_string_lossy().into_owned())],
            log_file: Some(log),
            ..Args::default()
        };
        let error = validate_path_isolation(&socket_log_collision, None).unwrap_err();
        assert!(error.to_string().contains("shares a namespace slot"));

        let shared = control.join("shared.sock");
        let duplicate_sockets = Args {
            serve_path: served.clone(),
            addrs: vec![
                BindAddr::SocketPath(shared.to_string_lossy().into_owned()),
                BindAddr::SocketPath(shared.to_string_lossy().into_owned()),
            ],
            ..Args::default()
        };
        let error = validate_path_isolation(&duplicate_sockets, None).unwrap_err();
        assert!(error.to_string().contains("shares a namespace slot"));

        let socket_revocation_collision = Args {
            serve_path: served,
            addrs: vec![BindAddr::SocketPath(shared.to_string_lossy().into_owned())],
            token_revocation_file: Some(shared),
            ..Args::default()
        };
        let error = validate_path_isolation(&socket_revocation_collision, None).unwrap_err();
        assert!(error.to_string().contains("shares a namespace slot"));
    }
}
