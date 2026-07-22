#[path = "common/digest_auth_util.rs"]
mod digest_auth_util;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use assert_cmd::prelude::*;
use digest_auth_util::send_with_digest_auth;
use fixtures::{Error, ServerProc, TestServer, port, ram_command, server, tmpdir};
use indexmap::IndexSet;
use predicates::prelude::PredicateBooleanExt;
use rstest::rstest;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;
use std::time::Duration;

const SHA512_CRYPT_DIGEST: &str =
    "4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81";

#[rstest]
fn no_auth(#[with(&["--auth", "user:pass@/:rw", "-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_eq!(resp.status(), 401);
    let values: Vec<&str> = resp
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert!(values[0].starts_with("Digest"));
    assert!(values[0].contains("algorithm=SHA-256"));
    assert!(values[1].starts_with("Basic"));

    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[test]
fn digest_md5_compatibility_flag_is_rejected() -> Result<(), Error> {
    // MD5 Digest 支持已刻意移除；废弃的启用标志不得悄然恢复弱质询。
    // MD5 Digest support was removed; the obsolete opt-in flag must not re-enable a weaker challenge.
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .arg("--digest-md5-compat")
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "unexpected argument '--digest-md5-compat'",
        ));
    Ok(())
}

#[test]
fn duplicate_auth_usernames_are_rejected() -> Result<(), Error> {
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .args([
            "--auth",
            "user:first-secret@/:rw",
            "--auth",
            "user:second-secret@/private:ro",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Duplicate auth username `user`"))
        .stderr(predicates::str::contains("first-secret").not())
        .stderr(predicates::str::contains("second-secret").not());
    Ok(())
}

#[test]
fn password_hash_algorithms_and_blocking_pool_are_validated_at_startup() -> Result<(), Error> {
    let excessive = format!("user:$6$rounds=1000001$test-salt${SHA512_CRYPT_DIGEST}@/:rw");
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .args(["--auth", &excessive])
        .assert()
        .failure()
        .stderr(predicates::str::contains("server safety limit of 1000000"))
        .stderr(predicates::str::contains(SHA512_CRYPT_DIGEST).not());

    let argon2id = "user:$argon2id$v=19$m=19456,t=2,p=1$YmFkIHNhbHQh$DqHGwv6NQV0VcaJi7jeF1E8IpfMXmXcpq4r2kKyqpXk@/:rw";
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .args(["--auth", argon2id, "--max-blocking-threads", "4"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "must be at least 5 when expensive authentication",
        ));

    for variant in ["argon2i", "argon2d"] {
        let unsupported = argon2id.replace("argon2id", variant);
        Command::new(assert_cmd::cargo::cargo_bin!("ram"))
            .env_remove("RAM_CONFIG")
            .args(["--auth", &unsupported])
            .assert()
            .failure()
            .stderr(predicates::str::contains(
                "only `$argon2id$` version 19 is accepted",
            ))
            .stderr(predicates::str::contains("DqHGwv6").not());
    }

    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .args(["--auth", "plain:password@/:rw", "--auth", argon2id])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Argon2id credentials cannot be mixed",
        ));

    let bounded_pool_rule = format!("user:$6$test-salt${SHA512_CRYPT_DIGEST}@/:rw");
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .args(["--auth", &bounded_pool_rule, "--max-blocking-threads", "4"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "must be at least 5 when expensive authentication",
        ))
        .stderr(predicates::str::contains(SHA512_CRYPT_DIGEST).not());
    Ok(())
}

#[rstest]
#[case(server(&["--auth", "user:pass@/:rw", "-A"]), "user", "pass")]
#[case(server(&["--auth", "user:pa:ss@1@/:rw", "-A"]), "user", "pa:ss@1")]
fn auth(#[case] server: TestServer, #[case] user: &str, #[case] pass: &str) -> Result<(), Error> {
    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), user, pass)?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn invalid_auth(#[with(&["-a", "user:pass@/:rw", "-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", server.url())
        .basic_auth("user", Some("-"))
        .send()?;
    assert_eq!(resp.status(), 401);
    let resp = fetch!(b"GET", server.url())
        .basic_auth("-", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 401);
    let resp = fetch!(b"GET", server.url())
        .header("Authorization", "Basic Og==")
        .send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn authentication_failures_are_rate_limited_per_source_and_user(
    #[with(&["-a", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    for _ in 0..4 {
        let resp = fetch!(b"GET", server.url())
            .basic_auth("user", Some("wrong"))
            .send()?;
        assert_eq!(resp.status(), 401);
    }
    let resp = fetch!(b"GET", server.url())
        .basic_auth("user", Some("wrong"))
        .send()?;
    assert_eq!(resp.status(), 429);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "1");

    // 服务器不阻塞 Tokio 工作线程；公告间隔后，成功认证清除该键失败状态。
    // The server does not sleep a Tokio worker; after the interval, successful authentication clears failure state.
    std::thread::sleep(Duration::from_millis(1100));
    let resp = fetch!(b"GET", server.url())
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[test]
fn trusted_forwarding_identity_drives_auth_limits_and_access_logs() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        "user:pass@/:rw",
        "--trusted-proxy",
        "127.0.0.1/32",
        "--trusted-proxy-header",
        "x-forwarded-for",
        "--log-format",
        "$remote_addr",
    ]);
    let server = ServerProc::spawn(cmd);
    let client = reqwest::blocking::Client::new();
    let url = format!("http://127.0.0.1:{port}/index.html");

    let malformed = client
        .get(&url)
        .header("x-forwarded-for", "not-an-ip")
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(malformed.status(), 400);
    assert_eq!(malformed.text()?, "Invalid forwarding header");

    for _ in 0..4 {
        let response = client
            .get(&url)
            .header("x-forwarded-for", "198.51.100.10")
            .basic_auth("user", Some("wrong"))
            .send()?;
        assert_eq!(response.status(), 401);
    }
    let limited = client
        .get(&url)
        .header("x-forwarded-for", "198.51.100.10")
        .basic_auth("user", Some("wrong"))
        .send()?;
    assert_eq!(limited.status(), 429);

    // 同一可信代理后的另一已验证客户端拥有独立认证预算。
    // A distinct verified client behind the same trusted proxy has an independent authentication budget.
    let independent = client
        .get(&url)
        .header("x-forwarded-for", "198.51.100.11")
        .basic_auth("user", Some("wrong"))
        .send()?;
    assert_eq!(independent.status(), 401);
    assert_eq!(
        server.wait_for_stdout_line(|line| line == "198.51.100.10", Duration::from_secs(2),),
        Some("198.51.100.10".to_owned()),
        "access logging did not use the same verified source identity"
    );
    Ok(())
}

#[test]
fn untrusted_forwarding_headers_cannot_split_authentication_buckets() -> Result<(), Error> {
    let root = tmpdir();
    let port = port();
    let mut cmd = ram_command(root.path(), port);
    cmd.args([
        "--auth",
        "user:pass@/:rw",
        // 有意排除直连 127.0.0.1 对端。 / Deliberately excludes the direct 127.0.0.1 peer.
        "--trusted-proxy",
        "127.0.0.2/32",
        "--trusted-proxy-header",
        "x-forwarded-for",
    ]);
    let _server = ServerProc::spawn(cmd);
    let client = reqwest::blocking::Client::new();
    let url = format!("http://127.0.0.1:{port}/index.html");

    for index in 0..4 {
        let response = client
            .get(&url)
            .header("x-forwarded-for", format!("198.51.100.{index}"))
            .basic_auth("user", Some("wrong"))
            .send()?;
        assert_eq!(response.status(), 401);
    }
    let limited = client
        .get(&url)
        .header("x-forwarded-for", "203.0.113.250")
        .basic_auth("user", Some("wrong"))
        .send()?;
    assert_eq!(limited.status(), 429);
    assert_eq!(limited.headers().get("retry-after").unwrap(), "1");
    Ok(())
}

#[rstest]
fn unknown_hashed_usernames_share_a_source_rate_limit(
    #[with(&["--auth", "user:$6$gQxZwKyWn/ZmWEA2$4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81@/:rw"])]
    server: TestServer,
) -> Result<(), Error> {
    for index in 0..4 {
        let resp = fetch!(b"GET", server.url())
            .basic_auth(format!("unknown-{index}"), Some("wrong"))
            .send()?;
        assert_eq!(resp.status(), 401);
    }
    let resp = fetch!(b"GET", server.url())
        .basic_auth("another-unknown-user", Some("wrong"))
        .send()?;
    assert_eq!(resp.status(), 429);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "1");
    Ok(())
}

#[rstest]
#[case(server(&["--auth", "user:$6$gQxZwKyWn/ZmWEA2$4uV7KKMnSUnET2BtWTj/9T5.Jq3h/MdkOlnIl5hdlTxDZ4MZKmJ.kl6C.NL9xnNPqC4lVHC1vuI0E5cLpTJX81@/:rw", "-A"]), "user", "pass")]
#[case(server(&["--auth", "user:$6$YV1J6OHZAAgbzCbS$V55ZEgvJ6JFdz1nLO4AD696PRHAJYhfQf.Gy2HafrCz5itnbgNTtTgfUSqZrt4BJ7FcpRfSt/QZzAan68pido0@/:rw", "-A"]), "user", "pa:ss@1")]
#[case(server(&["--auth", "user:$argon2id$v=19$m=19456,t=2,p=1$YmFkIHNhbHQh$DqHGwv6NQV0VcaJi7jeF1E8IpfMXmXcpq4r2kKyqpXk@/:rw", "-A"]), "user", "password")]
fn auth_hashed_password(
    #[case] server: TestServer,
    #[case] user: &str,
    #[case] pass: &str,
) -> Result<(), Error> {
    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);
    if let Err(err) = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), user, pass)
    {
        assert_eq!(
            err.to_string(),
            r#"Missing "realm" in header: Basic realm="RAM""#
        );
    }
    let resp = fetch!(b"PUT", &url)
        .body(b"abc".to_vec())
        .basic_auth(user, Some(pass))
        .send()?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn auth_required_for_read(
    #[with(&["-a", "user:pass@/:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), "user", "pass")?;
    assert_eq!(resp.status(), 201);
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text()?, "abc");
    Ok(())
}

#[rstest]
fn digest_auth_rejects_replay_on_different_path(
    #[with(&["--auth", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url1 = format!("{}file1", server.url());
    let url2 = format!("{}file2", server.url());

    let challenge = fetch!(b"PUT", &url1).body(b"abc".to_vec()).send()?;
    assert_eq!(challenge.status(), 401);
    let www_auth = challenge
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .find(|v| v.starts_with("Digest"))
        .expect("server should offer Digest auth");

    let context = digest_auth::AuthContext::new_with_method(
        "user",
        "pass",
        "/file1",
        None::<&[u8]>,
        digest_auth::HttpMethod::from("PUT"),
    );
    let mut prompt = digest_auth::parse(&www_auth)?;
    let answer = prompt.respond(&context)?.to_header_string();

    // 此 Authorization 只对 /file1 有效（digest `uri`/签名基于它）。即使用户、方法相同且
    // nonce 仍新鲜，原样重放到 /file2 也必须拒绝，不能授权不同资源。
    // This Authorization is valid only for /file1; replay against /file2 must be rejected despite same user/method/fresh nonce.
    let resp = fetch!(b"PUT", &url2)
        .body(b"abc".to_vec())
        .header("Authorization", answer)
        .send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn digest_auth_rejects_exact_replay_and_accepts_distinct_nc_out_of_order(
    #[with(&["--auth", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let challenge = fetch!(b"GET", &url).send()?;
    assert_eq!(challenge.status(), 401);
    let www_auth = challenge
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .find(|v| v.starts_with("Digest"))
        .expect("server should offer Digest auth");

    // 常规顺序：同一精确 Authorization 只能成功一次，递增 nc 通过。
    // Ordered case: one exact Authorization succeeds only once, while an incremented nc is accepted.
    let mut ordered_context = digest_auth::AuthContext::new_with_method(
        "user",
        "pass",
        "/index.html",
        None::<&[u8]>,
        digest_auth::HttpMethod::from("GET"),
    );
    ordered_context.set_custom_cnonce("ram-ordered-replay-test");
    let mut ordered_prompt = digest_auth::parse(&www_auth)?;
    let nc1 = ordered_prompt.respond(&ordered_context)?.to_header_string();
    let nc2 = ordered_prompt.respond(&ordered_context)?.to_header_string();

    assert_eq!(
        fetch!(b"GET", &url)
            .header("Authorization", &nc1)
            .send()?
            .status(),
        200
    );
    assert_eq!(
        fetch!(b"GET", &url)
            .header("Authorization", &nc1)
            .send()?
            .status(),
        401
    );
    assert_eq!(
        fetch!(b"GET", &url)
            .header("Authorization", &nc2)
            .send()?
            .status(),
        200
    );

    // HTTP/2 乱序：nc=2 先到不得导致尚未使用的 nc=1 被误判为
    // replay；但 nc=2 本身的第二次仍必须拒绝。
    // HTTP/2 out of order: accepting nc=2 first must not classify unused nc=1 as replay, while a
    // second use of nc=2 itself must still be rejected.
    let mut unordered_context = digest_auth::AuthContext::new_with_method(
        "user",
        "pass",
        "/index.html",
        None::<&[u8]>,
        digest_auth::HttpMethod::from("GET"),
    );
    unordered_context.set_custom_cnonce("ram-unordered-replay-test");
    let mut unordered_prompt = digest_auth::parse(&www_auth)?;
    let late_nc1 = unordered_prompt
        .respond(&unordered_context)?
        .to_header_string();
    let early_nc2 = unordered_prompt
        .respond(&unordered_context)?
        .to_header_string();

    assert_eq!(
        fetch!(b"GET", &url)
            .header("Authorization", &early_nc2)
            .send()?
            .status(),
        200
    );
    assert_eq!(
        fetch!(b"GET", &url)
            .header("Authorization", &late_nc1)
            .send()?
            .status(),
        200
    );
    assert_eq!(
        fetch!(b"GET", &url)
            .header("Authorization", &early_nc2)
            .send()?
            .status(),
        401
    );
    Ok(())
}

#[rstest]
fn anonymous_auth_rule_is_rejected() -> Result<(), Error> {
    let tmpdir = tmpdir();
    let port = port();
    Command::new(assert_cmd::cargo::cargo_bin!("ram"))
        .env_remove("RAM_CONFIG")
        .arg(tmpdir.path())
        .arg("-p")
        .arg(port.to_string())
        .args(["--auth", "@/"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "Anonymous auth rules are disabled",
        ));
    Ok(())
}

#[rstest]
fn auth_skip_on_options_method(
    #[with(&["--auth", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"OPTIONS", &url).send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn options_with_invalid_authorization_is_not_treated_as_anonymous(
    #[with(&["--auth", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());

    // 无凭据 OPTIONS 仍是廉价匿名发现路径；一旦客户端提供凭据，Allow 就是 ACL 专属断言，
    // 无效凭据不得悄然得到貌似已认证的匿名响应。
    // Credential-free OPTIONS is cheap anonymous discovery. Once credentials are supplied, Allow is ACL-specific;
    // invalid credentials must not receive an anonymous response that looks authenticated.
    for (user, pass) in [("user", "wrong"), ("missing", "wrong")] {
        let resp = fetch!(b"OPTIONS", &url)
            .basic_auth(user, Some(pass))
            .send()?;
        assert_eq!(resp.status(), 401);
    }
    Ok(())
}

#[rstest]
fn options_can_never_generate_a_token(
    #[with(&["--auth", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html?tokengen", server.url());

    // 既要覆盖原漏洞的“对的用户名 + 错的密码”，也要
    // 确认即使是真实凭据，OPTIONS 也不是令牌签发方法。
    // Cover the original correct-user/wrong-password bug and confirm that even valid credentials do
    // not turn OPTIONS into a token-issuance method.
    for pass in ["wrong", "pass"] {
        let resp = fetch!(b"OPTIONS", &url)
            .basic_auth("user", Some(pass))
            .send()?;
        assert_eq!(resp.status(), 405);
        assert_eq!(resp.headers().get("allow").unwrap(), "GET, POST");
        assert!(resp.text()?.is_empty());
    }
    Ok(())
}

#[rstest]
fn tokengen_accepts_only_get_or_post_with_verified_identity(
    // 默认路径权限是只读；POST 签发不应错误地要求 rw。
    // Default path permission is read-only; POST issuance must not incorrectly require read-write.
    #[with(&["--auth", "user:pass@/"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html?tokengen", server.url());

    let resp = fetch!(b"POST", &url)
        .basic_auth("user", Some("wrong"))
        .send()?;
    assert_eq!(resp.status(), 401);

    let resp = fetch!(b"POST", &url)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    let token = resp.text()?;
    assert!(!token.is_empty());

    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .bearer_auth(&token)
        .send()?;
    assert_eq!(resp.status(), 200);

    // 下载 token 不能用来给自己无限续期；签发必须重新提交
    // Basic/Digest 原始凭据。
    // A download token cannot renew itself indefinitely; issuance must resubmit original Basic/Digest credentials.
    let resp = fetch!(
        b"GET",
        format!("{}index.html?tokengen&token={token}", server.url())
    )
    .send()?;
    assert_eq!(resp.status(), 401);

    let resp = fetch!(b"PUT", &url)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 405);
    assert_eq!(resp.headers().get("allow").unwrap(), "GET, POST");
    Ok(())
}

#[rstest]
fn malformed_digest_header_is_rejected_without_killing_server(
    #[with(&["--auth", "user:pass@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"GET", &url)
        .header("Authorization", r#"Digest username="user", a=b=c,"#)
        .send()?;
    assert_eq!(resp.status(), 401);

    // release 配置使用 panic=unwind 作为任务级最后隔离边界；第二个独立
    // 请求同时验证畸形输入没有破坏进程级可用性。
    // Release uses panic=unwind as the final task-level isolation boundary; a second independent
    // request also proves malformed input did not damage process-wide availability.
    let resp = fetch!(b"GET", &url)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn auth_no_skip_if_unknown_user(
    #[with(&["--auth", "admin:admin@/:rw"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"GET", &url)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn auth_required_when_no_credentials(
    #[with(&["--auth", "user:pass@/:ro"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = fetch!(b"GET", &url)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn auth_check(
    #[with(&["--auth", "user:pass@/:rw", "--auth", "user2:pass2@/", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}", server.url());
    let resp = fetch!(b"CHECKAUTH", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"CHECKAUTH", &url), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    let resp = send_with_digest_auth(fetch!(b"CHECKAUTH", &url), "user2", "pass2")?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn auth_check2(
    #[with(&["--auth", "user:pass@/:rw|user2:pass2@/", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}", server.url());
    let resp = fetch!(b"CHECKAUTH", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"CHECKAUTH", &url), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    let resp = send_with_digest_auth(fetch!(b"CHECKAUTH", &url), "user2", "pass2")?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn auth_check3(
    #[with(&["--auth", "user:pass@/dir1:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}dir1/", server.url());
    let resp = fetch!(b"CHECKAUTH", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"CHECKAUTH", &url), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn auth_logout(
    #[with(&["--auth", "user:pass@/:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"LOGOUT", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"LOGOUT", &url), "user", "pass")?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn auth_readonly(
    #[with(&["--auth", "user:pass@/:rw", "--auth", "user2:pass2@/", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "user2", "pass2")?;
    assert_eq!(resp.status(), 200);
    let url = format!("{}file1", server.url());
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), "user2", "pass2")?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn editor_capabilities_follow_the_effective_path_acl(
    #[with(&[
        "--auth",
        "reader:pass@/:ro,/dir1:rw",
        "--allow-all",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let readonly = fetch!(b"GET", format!("{}test.txt?edit", server.url()))
        .basic_auth("reader", Some("pass"))
        .send()?;
    assert_eq!(readonly.status(), 200);
    let readonly_data = utils::retrieve_json(&readonly.text()?).expect("embedded editor data");
    for capability in ["can_save", "can_delete", "can_move"] {
        assert_eq!(readonly_data[capability], false, "{capability}");
    }

    let writable = fetch!(b"GET", format!("{}dir1/test.txt?edit", server.url()))
        .basic_auth("reader", Some("pass"))
        .send()?;
    assert_eq!(writable.status(), 200);
    let writable_data = utils::retrieve_json(&writable.text()?).expect("embedded editor data");
    for capability in ["can_save", "can_delete", "can_move"] {
        assert_eq!(writable_data[capability], true, "{capability}");
    }

    // 隐藏控件不是授权边界。 / Hiding controls is not an authorization boundary.
    let denied = fetch!(b"PUT", format!("{}test.txt", server.url()))
        .basic_auth("reader", Some("pass"))
        .body("forbidden")
        .send()?;
    assert_eq!(denied.status(), 403);
    Ok(())
}

#[rstest]
fn editor_capabilities_combine_independent_global_feature_gates(
    #[with(&["--auth", "writer:pass@/:rw", "--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    let response = fetch!(b"GET", format!("{}test.txt?edit", server.url()))
        .basic_auth("writer", Some("pass"))
        .send()?;
    let data = utils::retrieve_json(&response.text()?).expect("embedded editor data");
    assert_eq!(data["can_save"], true);
    assert_eq!(data["can_delete"], false);
    assert_eq!(data["can_move"], false);
    Ok(())
}

#[rstest]
fn auth_nest(
    #[with(&["--auth", "user:pass@/:rw", "--auth", "user2:pass2@/", "--auth", "user3:pass3@/dir1:rw", "-A"])]
    server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}dir1/file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), "user3", "pass3")?;
    assert_eq!(resp.status(), 201);
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), "user", "pass")?;
    assert_eq!(resp.status(), 204);
    Ok(())
}

#[rstest]
fn auth_nest_share(
    #[with(&["--auth", "user:pass@/:rw", "--auth", "user3:pass3@/dir1:rw", "-A"])]
    server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn index_only_intermediate_file_never_becomes_readable(
    #[with(&[
        "--auth",
        "user:pass@/test.txt/descendant:ro,/dir1/test.txt:ro,/dir2:rw",
        "--allow-upload",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let protected = format!("{}test.txt", server.url());

    // ACL 允许 IndexOnly 中间节点通过初次只读方法检查，因为它可能是必需
    // 的目录导航点。一旦 openat2 描述符证明它是文件，内容、元数据与副本都
    // 必须拒绝。
    // IndexOnly provisionally passes read-only ACL checks because an
    // intermediate node may be a required collection. Once openat2 descriptor metadata
    // proves it is a file, content, metadata, and copying must all be denied.
    for method in ["GET", "HEAD", "PROPFIND"] {
        let response = reqwest::blocking::Client::new()
            .request(reqwest::Method::from_bytes(method.as_bytes())?, &protected)
            .basic_auth("user", Some("pass"))
            .send()?;
        assert_eq!(response.status(), 403, "{method} exposed an IndexOnly file");
    }

    let token = fetch!(b"POST", format!("{protected}?tokengen"))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(token.status(), 403);

    let destination = format!("{}dir2/index-only-copy.txt", server.url());
    let copy = fetch!(b"COPY", &protected)
        .basic_auth("user", Some("pass"))
        .header("Destination", &destination)
        .send()?;
    assert_eq!(copy.status(), 403);
    assert!(!server.path().join("dir2/index-only-copy.txt").exists());

    let options = fetch!(b"OPTIONS", &protected)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(options.status(), 200);
    let allow = options
        .headers()
        .get("allow")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    for forbidden in ["GET", "HEAD", "PROPFIND", "COPY"] {
        assert!(!allow.split(", ").any(|method| method == forbidden));
    }

    // 相同用户仍能打开 IndexOnly 目录，并只看见明确授权的后代。
    // The same user may still navigate an IndexOnly directory and see only the
    // explicitly authorized descendant.
    let directory = fetch!(b"GET", format!("{}dir1/", server.url()))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(directory.status(), 200);
    assert_eq!(
        utils::retrieve_index_paths(&directory.text()?),
        IndexSet::from(["test.txt".into()])
    );
    let readable = fetch!(b"GET", format!("{}dir1/test.txt", server.url()))
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(readable.status(), 200);
    Ok(())
}

#[rstest]
#[case(server(&["--auth", "user:pass@/:rw", "-A"]), "user", "pass")]
#[case(server(&["--auth", "u1:p1@/:rw", "-A"]), "u1", "p1")]
fn auth_basic(
    #[case] server: TestServer,
    #[case] user: &str,
    #[case] pass: &str,
) -> Result<(), Error> {
    let url = format!("{}file1", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);
    let resp = fetch!(b"PUT", &url)
        .body(b"abc".to_vec())
        .basic_auth(user, Some(pass))
        .send()?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn auth_webdav_move(
    #[with(&["--auth", "user:pass@/:rw", "--auth", "user3:pass3@/dir1:rw", "-A"])]
    server: TestServer,
) -> Result<(), Error> {
    let origin_url = format!("{}dir1/test.html", server.url());
    let new_url = format!("{}test2.html", server.url());
    let resp = send_with_digest_auth(
        fetch!(b"MOVE", &origin_url).header("Destination", &new_url),
        "user3",
        "pass3",
    )?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn auth_webdav_copy(
    #[with(&["--auth", "user:pass@/:rw", "--auth", "user3:pass3@/dir1:rw", "-A"])]
    server: TestServer,
) -> Result<(), Error> {
    let origin_url = format!("{}dir1/test.html", server.url());
    let new_url = format!("{}test2.html", server.url());
    let resp = send_with_digest_auth(
        fetch!(b"COPY", &origin_url).header("Destination", &new_url),
        "user3",
        "pass3",
    )?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn copy_destination_symlink_is_reauthorized_against_real_acl(
    #[with(&[
        "--auth",
        "user:pass@/dir1:ro,/visible:rw",
        "--allow-upload",
        "--allow-symlink"
    ])]
    server: TestServer,
) -> Result<(), Error> {
    // URL 上的 Destination 位于可写 `/visible`，但真实目标是
    // 未授权的 `/dir2`。目标 ACL 必须在解析链接后重新判定。
    // The URL Destination is writable `/visible`, but its real target is unauthorized `/dir2`;
    // destination ACL must be evaluated again after resolving the link.
    symlink(server.path().join("dir2"), server.path().join("visible"))?;
    let source = format!("{}dir1/test.html", server.url());
    let destination = format!("{}visible/copied.html", server.url());
    let resp = fetch!(b"COPY", source)
        .basic_auth("user", Some("pass"))
        .header("Destination", destination)
        .send()?;
    assert_eq!(resp.status(), 403);
    assert!(!server.path().join("dir2/copied.html").exists());
    Ok(())
}

#[cfg(unix)]
#[rstest]
fn internal_symlink_is_rejected_by_default(server: TestServer) -> Result<(), Error> {
    symlink(server.path().join("dir2"), server.path().join("visible"))?;
    let resp = fetch!(b"GET", format!("{}visible/test.txt", server.url())).send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn auth_path_prefix(
    #[with(&["--auth", "user:pass@/:rw", "--path-prefix", "xyz", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}xyz/index.html", server.url());
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);
    let resp = send_with_digest_auth(fetch!(b"GET", &url), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn auth_partial_index(
    #[with(&["--auth", "user:pass@/dir1:rw,/dir2:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let resp = send_with_digest_auth(fetch!(b"GET", server.url()), "user", "pass")?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert_eq!(paths, IndexSet::from(["dir1/".into(), "dir2/".into()]));
    let resp = send_with_digest_auth(
        fetch!(b"GET", format!("{}?q={}", server.url(), "test.html")),
        "user",
        "pass",
    )?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert_eq!(
        paths,
        IndexSet::from(["dir1/test.html".into(), "dir2/test.html".into()])
    );
    Ok(())
}

#[rstest]
fn no_auth_propfind_dir(
    #[with(&["--auth", "admin:admin@/:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"PROPFIND", server.url()).send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn auth_propfind_dir(
    #[with(&["--auth", "admin:admin@/:rw", "--auth", "user:pass@/dir-assets", "-A"])]
    server: TestServer,
) -> Result<(), Error> {
    let resp = send_with_digest_auth(
        fetch!(b"PROPFIND", server.url()).header("depth", "1"),
        "user",
        "pass",
    )?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/dir-assets/</D:href>"));
    assert!(!body.contains("<D:href>/dir1/</D:href>"));
    Ok(())
}

#[rstest]
fn auth_data(#[with(&["-a", "user:pass@/:rw", "-A"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_eq!(resp.status(), 401);
    let resp = fetch!(b"GET", server.url())
        .basic_auth("user", Some("pass"))
        .send()?;
    let content = resp.text()?;
    let json = utils::retrieve_json(&content).unwrap();
    assert_eq!(json["allow_delete"], serde_json::Value::Bool(true));
    assert_eq!(json["allow_upload"], serde_json::Value::Bool(true));
    Ok(())
}

#[rstest]
fn auth_precedence(
    #[with(&["--auth", "user:pass@/dir1:rw,/dir1/test.txt", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}dir1/test.txt", server.url());
    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), "user", "pass")?;
    assert_eq!(resp.status(), 403);

    Ok(())
}

#[rstest]
fn auth_user_paths_require_credentials(
    #[with(&["--auth", "user:pass@/:rw", "-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}dir1/test.txt", server.url());
    let resp = fetch!(b"PUT", &url).body(b"abc".to_vec()).send()?;
    assert_eq!(resp.status(), 401);

    let resp = send_with_digest_auth(fetch!(b"PUT", &url).body(b"abc".to_vec()), "user", "pass")?;
    assert_eq!(resp.status(), 204);

    Ok(())
}

#[rstest]
fn token_auth(#[with(&["-a", "user:pass@/"])] server: TestServer) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);

    let url = format!("{}index.html?tokengen", server.url());
    let resp = fetch!(b"GET", &url).send()?;
    assert_eq!(resp.status(), 401);

    let url = format!("{}index.html?tokengen", server.url());
    let resp = fetch!(b"GET", &url)
        .basic_auth("user", Some("pass"))
        .send()?;
    let token = resp.text()?;
    let url = format!("{}index.html", server.url());
    // 默认禁用查询串凭据。 / Query credentials are disabled by default.
    let resp = fetch!(b"GET", format!("{url}?token={token}")).send()?;
    assert_eq!(resp.status(), 401);

    let resp = fetch!(b"GET", &url).bearer_auth(&token).send()?;
    assert_eq!(resp.status(), 200);
    let cache_control = resp.headers().get("cache-control").unwrap().to_str()?;
    assert!(cache_control.contains("private"));
    assert!(cache_control.contains("no-store"));

    let resp = fetch!(b"HEAD", &url).bearer_auth(&token).send()?;
    assert_eq!(resp.status(), 200);
    let cache_control = resp.headers().get("cache-control").unwrap().to_str()?;
    assert!(cache_control.contains("private"));
    assert!(cache_control.contains("no-store"));

    // Bearer 凭据不能为自己签发替代品；令牌签发/撤销要求新鲜 Basic/Digest 证明。
    // A bearer credential cannot mint its replacement; issuance and revocation require fresh Basic/Digest proof.
    let resp = fetch!(b"GET", format!("{url}?tokengen"))
        .bearer_auth(&token)
        .send()?;
    assert_eq!(resp.status(), 401);

    // 使用原始凭据和敏感请求头撤销确切令牌，绝不用 URL 参数；撤销由 jti 幂等表示。
    // Revoke the exact token with original credentials and a sensitive header, never URL parameters; jti makes it idempotent.
    let resp = fetch!(b"POST", &url)
        .basic_auth("user", Some("pass"))
        .header("X-Ram-Revoke-Token", &token)
        .send()?;
    assert_eq!(resp.status(), 204);
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    let resp = fetch!(b"GET", &url).bearer_auth(&token).send()?;
    assert_eq!(resp.status(), 401);
    Ok(())
}

#[rstest]
fn duplicate_credential_and_revocation_headers_are_rejected_without_revoking(
    #[with(&["-a", "user:pass@/"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}index.html", server.url());
    let mut duplicate_authorization = reqwest::header::HeaderMap::new();
    duplicate_authorization.append("authorization", "Basic dXNlcjpwYXNz".parse()?);
    duplicate_authorization.append("authorization", "Basic dXNlcjpwYXNz".parse()?);
    let response = client.get(&url).headers(duplicate_authorization).send()?;
    assert_eq!(response.status(), 400);

    let token = client
        .get(format!("{url}?tokengen"))
        .basic_auth("user", Some("pass"))
        .send()?
        .error_for_status()?
        .text()?;
    let mut duplicate_revoke = reqwest::header::HeaderMap::new();
    duplicate_revoke.append("x-ram-revoke-token", token.parse()?);
    duplicate_revoke.append("x-ram-revoke-token", token.parse()?);
    let response = client
        .post(&url)
        .basic_auth("user", Some("pass"))
        .headers(duplicate_revoke)
        .send()?;
    assert_eq!(response.status(), 400);
    assert_eq!(client.get(&url).bearer_auth(&token).send()?.status(), 200);
    Ok(())
}

#[rstest]
fn persistent_revocation_is_visible_to_another_live_process(
    tmpdir: assert_fs::TempDir,
    port: u16,
) -> Result<(), Error> {
    let state_dir = assert_fs::TempDir::new()?;
    let secret = state_dir.path().join("token.secret");
    let revocations = state_dir.path().join("revocations.json");
    fs::write(&secret, b"0123456789abcdef0123456789abcdef")?;
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))?;
    let second_port = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        listener.local_addr()?.port()
    };
    let command = |listen_port| {
        let mut command = ram_command(tmpdir.path(), listen_port);
        command
            .args(["--auth", "user:pass@/:rw", "--token-secret-file"])
            .arg(&secret)
            .args([
                "--token-audience",
                "shared-revocation-test",
                "--token-revocation-file",
            ])
            .arg(&revocations);
        command
    };
    let _first = ServerProc::spawn(command(port));
    let _second = ServerProc::spawn(command(second_port));
    let first_url = format!("http://localhost:{port}/index.html");
    let second_url = format!("http://localhost:{second_port}/index.html");

    let token = fetch!(b"GET", format!("{first_url}?tokengen"))
        .basic_auth("user", Some("pass"))
        .send()?
        .error_for_status()?
        .text()?;
    assert_eq!(
        fetch!(b"GET", &second_url)
            .bearer_auth(&token)
            .send()?
            .status(),
        200
    );
    assert_eq!(
        fetch!(b"POST", &first_url)
            .basic_auth("user", Some("pass"))
            .header("X-Ram-Revoke-Token", &token)
            .send()?
            .status(),
        204
    );
    assert_eq!(
        fetch!(b"GET", &second_url)
            .bearer_auth(&token)
            .send()?
            .status(),
        401
    );

    let second_token = fetch!(b"GET", format!("{first_url}?tokengen"))
        .basic_auth("user", Some("pass"))
        .send()?
        .error_for_status()?
        .text()?;
    fs::write(&revocations, b"{\"version\":2,")?;
    assert_eq!(
        fetch!(b"POST", &first_url)
            .basic_auth("user", Some("pass"))
            .header("X-Ram-Revoke-Token", &second_token)
            .send()?
            .status(),
        503
    );
    assert_eq!(
        fetch!(b"GET", &second_url)
            .bearer_auth(&second_token)
            .send()?
            .status(),
        503
    );
    Ok(())
}
