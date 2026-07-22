#[path = "common/fixtures.rs"]
mod fixtures;

use fixtures::{
    Error, ServerProc, TEST_AUTH_PASS, TEST_AUTH_RULE, TEST_AUTH_USER, TestServer, port,
    ram_command, server, tmpdir,
};

use assert_cmd::prelude::*;
use assert_fs::fixture::TempDir;
use regex::Regex;
use rstest::rstest;
use std::env;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const PEER_HELPER_SOCKET_ENV: &str = "RAM_BIND_TEST_PEER_SOCKET";
const PEER_HELPER_MODE_ENV: &str = "RAM_BIND_TEST_PEER_MODE";
const PEER_HELPER_MARKER_ENV: &str = "RAM_BIND_TEST_PEER_MARKER";

#[rstest]
#[case(&["-b", "20.205.243.166"])]
fn bind_fails(tmpdir: TempDir, port: u16, #[case] args: &[&str]) -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .args(["--auth", TEST_AUTH_RULE])
        .arg("--allow-insecure-http")
        .args(args)
        .assert()
        .stderr(predicates::str::contains("Failed to bind"))
        .failure();

    Ok(())
}

#[rstest]
#[case(server(&[] as &[&str]), true, true)]
#[case(server(&["-b", "0.0.0.0", "--allow-insecure-http"]), true, false)]
#[case(server(&["-b", "127.0.0.1", "-b", "::1"]), true, true)]
fn bind_ipv4_ipv6(
    #[case] server: TestServer,
    #[case] bind_ipv4: bool,
    #[case] bind_ipv6: bool,
) -> Result<(), Error> {
    assert_eq!(
        reqwest::blocking::get(format!("http://127.0.0.1:{}", server.port()).as_str()).is_ok(),
        bind_ipv4
    );
    assert_eq!(
        reqwest::blocking::get(format!("http://[::1]:{}", server.port()).as_str()).is_ok(),
        bind_ipv6
    );

    Ok(())
}

#[rstest]
#[case(&[] as &[&str])]
#[case(&["--path-prefix", "/prefix"])]
fn validate_printed_urls(tmpdir: TempDir, port: u16, #[case] args: &[&str]) -> Result<(), Error> {
    let mut cmd = ram_command(tmpdir.path(), port);
    cmd.args(["--auth", TEST_AUTH_RULE]).args(args);
    let server = ServerProc::spawn(cmd);

    // 就绪横幅先打印 "Listening on"，URL 行紧随其后（同一次 println）；
    // 等到第一条含 URL 的行出现后再取快照，避免读到半截横幅。
    // The readiness banner prints "Listening on" before its URL lines in one println; wait for the
    // first URL before taking a snapshot so the test cannot observe a partial banner.
    server
        .wait_for_stdout_line(|line| line.contains("http://"), Duration::from_secs(2))
        .expect("no URL line in the startup banner");
    let banner = server.stdout_lines().join("\n");

    let urls = Regex::new(r"http://[a-zA-Z0-9\.\[\]:/]+")
        .unwrap()
        .captures_iter(&banner)
        .filter_map(|caps| caps.get(0).map(|v| v.as_str().to_string()))
        .collect::<Vec<_>>();

    assert!(!urls.is_empty());
    reqwest::blocking::Client::new()
        .get(&urls[0])
        .basic_auth(TEST_AUTH_USER, Some(TEST_AUTH_PASS))
        .send()?
        .error_for_status()?;

    Ok(())
}

#[test]
fn pathname_unix_socket_has_exact_mode_logs_peer_credentials_and_is_removed() -> Result<(), Error> {
    let root = tmpdir();
    let socket_root = tmpdir();
    let socket = socket_root.path().join("ram.sock");
    let mut cmd = ram_command(root.path(), port());
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--unix-socket-mode",
        "0660",
        "--log-format",
        "$remote_addr",
        "--bind",
    ])
    .arg(&socket);
    let mut server = ServerProc::spawn(cmd);

    let metadata = std::fs::symlink_metadata(&socket)?;
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o660);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.gid(), rustix::process::getegid().as_raw());

    let mut stream = UnixStream::connect(&socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");

    let expected_peer = format!(
        "unix:uid={},gid={},pid={}",
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        std::process::id(),
    );
    assert_eq!(
        server.wait_for_stdout_line(|line| line == expected_peer, Duration::from_secs(2),),
        Some(expected_peer),
        "the access log did not use kernel SO_PEERCRED"
    );

    server.sigterm();
    assert!(
        server.wait_exit(Duration::from_secs(3)).is_some(),
        "server did not terminate"
    );
    assert!(
        !socket.exists(),
        "the server-owned Unix socket was not removed"
    );
    Ok(())
}

#[test]
fn unix_socket_peer_request_helper() -> Result<(), Error> {
    let Some(socket) = env::var_os(PEER_HELPER_SOCKET_ENV) else {
        return Ok(());
    };
    let mode = env::var(PEER_HELPER_MODE_ENV)?;
    let path = if mode == "hold" {
        "/large.bin"
    } else {
        "/index.html"
    };
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nConnection: close\r\n\r\n"
    )?;
    let mut first = [0u8; 1];
    stream.read_exact(&mut first)?;

    if mode == "hold" {
        let marker = env::var_os(PEER_HELPER_MARKER_ENV)
            .ok_or_else(|| std::io::Error::other("peer helper marker is missing"))?;
        std::fs::write(marker, b"ready")?;
        sleep(Duration::from_millis(1500));
        return Ok(());
    }

    let mut response = vec![first[0]];
    stream.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root to launch real clients under distinct Linux UIDs; enforced by privileged CI"]
fn real_unix_peer_uids_have_independent_source_buckets_and_logs() -> Result<(), Error> {
    assert!(
        rustix::process::geteuid().is_root(),
        "privileged Unix peer-identity test must run as root"
    );

    const FIRST_UID: u32 = 60_001;
    const SECOND_UID: u32 = 60_002;
    const SOCKET_UID: u32 = 60_003;
    const SOCKET_GID: u32 = 60_004;

    let root = tmpdir();
    std::fs::File::create(root.path().join("large.bin"))?.set_len(16 * 1024 * 1024)?;
    let socket_root = tmpdir();
    // 保持套接字命名空间私有且 root 所有，使显式把套接字 inode 委托给其他 UID 时，该 UID
    // 不能替换路径名；两个客户端 UID 只需遍历此目录。
    // Keep the socket namespace private and root-owned so delegating its inode cannot allow pathname
    // replacement; both client UIDs need only traverse this directory.
    std::fs::set_permissions(socket_root.path(), std::fs::Permissions::from_mode(0o711))?;
    let marker_root = tmpdir();
    std::fs::set_permissions(marker_root.path(), std::fs::Permissions::from_mode(0o1777))?;
    let socket = socket_root.path().join("ram.sock");
    let marker = marker_root.path().join("first-ready");
    let mut cmd = ram_command(root.path(), port());
    cmd.args([
        "--auth",
        TEST_AUTH_RULE,
        "--unix-socket-mode",
        "0666",
        "--unix-socket-uid",
        "60003",
        "--unix-socket-gid",
        "60004",
        "--max-concurrent-requests",
        "4",
        "--max-concurrent-requests-per-source",
        "1",
        "--max-concurrent-requests-per-user",
        "4",
        "--response-write-idle-timeout",
        "5s",
        "--log-format",
        "$remote_addr",
        "--bind",
    ])
    .arg(&socket);
    let server = ServerProc::spawn(cmd);

    let socket_metadata = std::fs::symlink_metadata(&socket)?;
    assert_eq!(socket_metadata.permissions().mode() & 0o7777, 0o666);
    assert_eq!(socket_metadata.uid(), SOCKET_UID);
    assert_eq!(socket_metadata.gid(), SOCKET_GID);

    let mut first_command =
        unix_peer_helper_command(&socket, "hold", Some(&marker), FIRST_UID, FIRST_UID)?;
    let mut first = first_command.spawn()?;
    let first_pid = first.id();
    let marker_deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        if let Some(status) = first.try_wait()? {
            return Err(format!("first peer helper exited before admission: {status}").into());
        }
        if Instant::now() >= marker_deadline {
            return Err("first peer helper did not reach its streaming response".into());
        }
        sleep(Duration::from_millis(10));
    }

    let second =
        unix_peer_helper_command(&socket, "read", None, SECOND_UID, SECOND_UID)?.spawn()?;
    let second_pid = second.id();
    let second_output = second.wait_with_output()?;
    assert!(
        second_output.status.success(),
        "second peer helper failed: {}",
        String::from_utf8_lossy(&second_output.stderr)
    );

    let first_output = first.wait_with_output()?;
    assert!(
        first_output.status.success(),
        "first peer helper failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );

    let first_identity = format!("unix:uid={FIRST_UID},gid={FIRST_UID},pid={first_pid}");
    assert_eq!(
        server.wait_for_stdout_line(|line| line == first_identity, Duration::from_secs(2),),
        Some(first_identity),
        "access log did not preserve the first kernel peer identity"
    );
    let second_identity = format!("unix:uid={SECOND_UID},gid={SECOND_UID},pid={second_pid}");
    assert_eq!(
        server.wait_for_stdout_line(|line| line == second_identity, Duration::from_secs(2),),
        Some(second_identity),
        "access log did not preserve the second kernel peer identity"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "requires Linux SO_PEERCRED and root; enforced by privileged Linux CI"]
fn real_unix_peer_uids_have_independent_source_buckets_and_logs() {}

fn unix_peer_helper_command(
    socket: &std::path::Path,
    mode: &str,
    marker: Option<&std::path::Path>,
    uid: u32,
    gid: u32,
) -> Result<Command, Error> {
    let mut command = Command::new(env::current_exe()?);
    command
        .args([
            "--exact",
            "unix_socket_peer_request_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PEER_HELPER_SOCKET_ENV, socket)
        .env(PEER_HELPER_MODE_ENV, mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(marker) = marker {
        command.env(PEER_HELPER_MARKER_ENV, marker);
    }
    command.uid(uid).gid(gid);
    Ok(command)
}

#[test]
fn unix_socket_cleanup_never_unlinks_a_replacement_inode() -> Result<(), Error> {
    let root = tmpdir();
    let socket_root = tmpdir();
    let socket = socket_root.path().join("ram.sock");
    let moved_socket = socket_root.path().join("ram-owned.sock");
    let mut cmd = ram_command(root.path(), port());
    cmd.args(["--auth", TEST_AUTH_RULE, "--bind"]).arg(&socket);
    let mut server = ServerProc::spawn(cmd);

    let owned_inode = std::fs::symlink_metadata(&socket)?.ino();
    std::fs::rename(&socket, &moved_socket)?;
    let replacement = UnixListener::bind(&socket)?;
    let replacement_inode = std::fs::symlink_metadata(&socket)?.ino();
    assert_ne!(owned_inode, replacement_inode);

    server.sigterm();
    assert!(
        server.wait_exit(Duration::from_secs(3)).is_some(),
        "server did not terminate"
    );
    assert_eq!(
        std::fs::symlink_metadata(&socket)?.ino(),
        replacement_inode,
        "shutdown removed a pathname replacement not owned by the server"
    );
    drop(replacement);
    Ok(())
}

#[test]
fn shared_sticky_socket_parent_rejects_an_untrusted_final_uid() -> Result<(), Error> {
    let root = tmpdir();
    let socket_root = tmpdir();
    std::fs::set_permissions(socket_root.path(), std::fs::Permissions::from_mode(0o1777))?;
    let socket = socket_root.path().join("ram.sock");
    let euid = rustix::process::geteuid().as_raw();
    let untrusted_uid = if euid == 0 {
        65_534
    } else {
        euid.wrapping_add(1).max(1)
    };
    let mut command = ram_command(root.path(), port());
    command
        .args(["--auth", TEST_AUTH_RULE, "--unix-socket-uid"])
        .arg(untrusted_uid.to_string())
        .arg("--bind")
        .arg(&socket);
    command.assert().failure().stderr(predicates::str::contains(
        "cannot be assigned to an untrusted owner in a shared sticky parent",
    ));
    assert!(
        !socket.exists(),
        "rejected configuration still created a socket"
    );
    Ok(())
}

#[test]
fn stale_unix_socket_with_untrusted_owner_is_never_removed() -> Result<(), Error> {
    if !rustix::process::geteuid().is_root() {
        return Ok(());
    }
    let root = tmpdir();
    let socket_root = tmpdir();
    let socket = socket_root.path().join("ram.sock");
    drop(UnixListener::bind(&socket)?);
    if rustix::fs::chown(&socket, Some(rustix::fs::Uid::from_raw(65_534)), None).is_err() {
        // 某些 rootless 测试容器报告 euid 0 却没有 CAP_CHOWN。
        // Some rootless test containers report euid 0 without CAP_CHOWN.
        return Ok(());
    }

    let mut command = ram_command(root.path(), port());
    command
        .args(["--auth", TEST_AUTH_RULE, "--bind"])
        .arg(&socket);
    command
        .assert()
        .failure()
        .stderr(predicates::str::contains("Refusing to clean Unix socket"));
    assert_eq!(std::fs::symlink_metadata(&socket)?.uid(), 65_534);
    Ok(())
}

#[test]
fn attacker_owned_grandparent_is_rejected_even_with_a_trusted_parent() -> Result<(), Error> {
    if !rustix::process::geteuid().is_root() {
        return Ok(());
    }
    let root = tmpdir();
    let namespace = tmpdir();
    let attacker_grandparent = namespace.path().join("attacker");
    let trusted_parent = attacker_grandparent.join("trusted-parent");
    std::fs::create_dir(&attacker_grandparent)?;
    std::fs::create_dir(&trusted_parent)?;
    if rustix::fs::chown(
        &attacker_grandparent,
        Some(rustix::fs::Uid::from_raw(65_534)),
        None,
    )
    .is_err()
    {
        return Ok(());
    }
    let socket = trusted_parent.join("ram.sock");
    let mut command = ram_command(root.path(), port());
    command
        .args(["--auth", TEST_AUTH_RULE, "--bind"])
        .arg(&socket);
    command
        .assert()
        .failure()
        .stderr(predicates::str::contains("has an untrusted owner"));
    assert!(
        !socket.exists(),
        "unsafe ancestor chain still received a socket"
    );
    Ok(())
}

#[test]
fn pathname_unix_socket_rejects_absolute_symlink_components() -> Result<(), Error> {
    let root = tmpdir();
    let namespace = tmpdir();
    let real_parent = namespace.path().join("real-parent");
    let alias_parent = namespace.path().join("alias-parent");
    std::fs::create_dir(&real_parent)?;
    symlink(&real_parent, &alias_parent)?;
    let socket = alias_parent.join("ram.sock");

    let mut command = ram_command(root.path(), port());
    command
        .args(["--auth", TEST_AUTH_RULE, "--bind"])
        .arg(&socket);
    command.assert().failure().stderr(predicates::str::contains(
        "must not contain symbolic-link components",
    ));
    assert!(!real_parent.join("ram.sock").exists());
    Ok(())
}

#[test]
fn pathname_unix_socket_rejects_relative_symlink_components() -> Result<(), Error> {
    let root = tmpdir();
    let namespace = tmpdir();
    let real_parent = namespace.path().join("real-parent");
    let alias_parent = namespace.path().join("alias-parent");
    std::fs::create_dir(&real_parent)?;
    symlink("real-parent", &alias_parent)?;

    let mut command = ram_command(root.path(), port());
    command.current_dir(namespace.path()).args([
        "--auth",
        TEST_AUTH_RULE,
        "--bind",
        "alias-parent/ram.sock",
    ]);
    command.assert().failure().stderr(predicates::str::contains(
        "must not contain symbolic-link components",
    ));
    assert!(!real_parent.join("ram.sock").exists());
    Ok(())
}

#[test]
fn pathname_unix_socket_rejects_a_client_unaddressable_full_path() -> Result<(), Error> {
    const INVALID_SUN_PATH_LEN: usize = 108;
    const SOCKET_BASENAME: &str = "ram.sock";

    let root = tmpdir();
    let namespace = tmpdir();
    let fixed_len = namespace.path().as_os_str().as_bytes().len() + 1 + 1 + SOCKET_BASENAME.len();
    let component_len = INVALID_SUN_PATH_LEN
        .checked_sub(fixed_len)
        .expect("temporary test path is unexpectedly long");
    let parent = namespace.path().join("x".repeat(component_len));
    std::fs::create_dir(&parent)?;
    let socket = parent.join(SOCKET_BASENAME);
    assert_eq!(socket.as_os_str().as_bytes().len(), INVALID_SUN_PATH_LEN);

    let mut command = ram_command(root.path(), port());
    command
        .args(["--auth", TEST_AUTH_RULE, "--bind"])
        .arg(&socket);
    command.assert().failure().stderr(predicates::str::contains(
        "cannot be represented by clients in sockaddr_un",
    ));
    assert!(!socket.exists());
    Ok(())
}
