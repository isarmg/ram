//! 认证单元测试与安全回归测试。
//! Authentication unit and security-regression tests.

use super::{
    ARGON2_M_COST_MAX_KIB, ARGON2_M_COST_MIN_KIB, ARGON2_OUTPUT_MAX_BYTES, ARGON2_OUTPUT_MIN_BYTES,
    ARGON2_P_COST_MAX, ARGON2_P_COST_MIN, ARGON2_SALT_MAX_BYTES, ARGON2_SALT_MIN_BYTES,
    ARGON2_T_COST_MAX, ARGON2_T_COST_MIN, AUTH_RATE_FREE_FAILURES, AUTH_USERNAME_MAX_LEN,
    AccessControl, AuthDecision, AuthRateKey, AuthRequest, DIGEST_CNONCE_MAX_LEN,
    DIGEST_REPLAY_CAPACITY, DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES, DUMMY_SHA512_CRYPT,
    DigestReplayAttempt, DigestReplayCache, DigestReplayKey, DigestReplayReject,
    HashAttemptReservationReject, PASSWORD_PRINCIPAL_RATE_DOMAIN, PASSWORD_SOURCE_RATE_DOMAIN,
    PASSWORD_VERIFY_CONCURRENCY, PASSWORD_VERIFY_PER_SOURCE, PASSWORD_VERIFY_PER_USERNAME,
    PasswordHashAdmission, PasswordHashAdmissionOutcome, PasswordHashAdmissionState,
    PasswordHashWorkerLease, PasswordRateReservation, REALM, SHA512_CRYPT_MAX_ROUNDS,
    argon2id_profile_from_phc, check_auth, create_nonce, digest_hex, digest_param, get_auth_user,
    sha512_crypt_rounds, to_headermap, verify_supported_password_hash,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use headers::HeaderValue;
use hyper::Method;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, oneshot};

fn synthetic_sha512_hash(rounds: u32) -> String {
    let digest = DUMMY_SHA512_CRYPT
        .rsplit_once('$')
        .expect("dummy hash has a digest")
        .1;
    format!("$6$rounds={rounds}$test-salt${digest}")
}

fn synthetic_argon2id_phc(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt_len: usize,
    output_len: usize,
) -> String {
    let salt = STANDARD_NO_PAD.encode(vec![0x53; salt_len]);
    let output = STANDARD_NO_PAD.encode(vec![0x48; output_len]);
    format!("$argon2id$v=19$m={m_cost},t={t_cost},p={p_cost}${salt}${output}")
}

#[test]
fn digest_auth_params_are_case_insensitive_and_reject_ambiguous_duplicates() {
    let params = to_headermap(b"Username=alice, QOP=auth, Algorithm=SHA-256 \t").unwrap();
    assert_eq!(
        digest_param(&params, b"username"),
        Some(b"alice".as_slice())
    );
    assert_eq!(digest_param(&params, b"qop"), Some(b"auth".as_slice()));
    assert_eq!(
        digest_param(&params, b"algorithm"),
        Some(b"SHA-256".as_slice())
    );
    assert!(to_headermap(b"qop=auth,QOP=auth-int").is_err());

    let authorization = HeaderValue::from_static("Digest Username=alice");
    assert_eq!(get_auth_user(&authorization).as_deref(), Some("alice"));
}

#[test]
fn digest_quoted_pairs_are_unescaped_and_invalid_octets_fail_closed() {
    let params = to_headermap(br#"username="a\"b\,c", realm="RAM""#).unwrap();
    assert_eq!(
        digest_param(&params, b"username"),
        Some(b"a\"b,c".as_slice())
    );
    assert_eq!(digest_param(&params, b"realm"), Some(b"RAM".as_slice()));

    for invalid in [
        b"a=bare=value".as_slice(),
        b"a=\"unterminated".as_slice(),
        b"a=\"trailing\\\"".as_slice(),
        b"a=\"line\nfeed\"".as_slice(),
        b"a=\"nul\0byte\"".as_slice(),
        b"a=b,".as_slice(),
    ] {
        assert!(to_headermap(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
fn digest_auth_param_count_and_byte_budgets_are_exact() {
    let exact = (0..super::DIGEST_AUTH_PARAMS_MAX_FIELDS)
        .map(|index| format!("k{index}=v"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        to_headermap(exact.as_bytes()).unwrap().len(),
        super::DIGEST_AUTH_PARAMS_MAX_FIELDS
    );
    let over = format!("{exact},overflow=v");
    assert!(to_headermap(over.as_bytes()).is_err());
    assert!(to_headermap(&vec![b'a'; super::DIGEST_AUTH_PARAMS_MAX_BYTES + 1]).is_err());
}

fn test_admission(
    concurrency: usize,
    capacity: usize,
    per_source_limit: usize,
    per_username_limit: usize,
) -> Arc<PasswordHashAdmission> {
    Arc::new(PasswordHashAdmission {
        verify_limit: Arc::new(Semaphore::new(concurrency)),
        state: Mutex::new(PasswordHashAdmissionState::default()),
        capacity,
        per_source_limit,
        per_username_limit,
        queue_timeout: Duration::from_secs(1),
    })
}

fn ready_now<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("lightweight authentication unexpectedly waited for a hash"),
    }
}

#[test]
fn sha512_crypt_rounds_have_a_startup_safety_ceiling() {
    let boundary = synthetic_sha512_hash(SHA512_CRYPT_MAX_ROUNDS);
    assert_eq!(
        sha512_crypt_rounds(&boundary).unwrap(),
        SHA512_CRYPT_MAX_ROUNDS
    );
    let boundary_rule = format!("user:{boundary}@/:rw");
    AccessControl::new(&[&boundary_rule]).expect("documented boundary must be accepted");

    let excessive = synthetic_sha512_hash(SHA512_CRYPT_MAX_ROUNDS + 1);
    let error = sha512_crypt_rounds(&excessive).unwrap_err().to_string();
    assert!(error.contains("exceed the server safety limit"), "{error}");
    let excessive_rule = format!("user:{excessive}@/:rw");
    let startup_error = AccessControl::new(&[&excessive_rule]).unwrap_err();
    let startup_error = format!("{startup_error:#}");
    assert!(
        startup_error.contains("server safety limit"),
        "{startup_error}"
    );
    assert!(
        !startup_error.contains(
            DUMMY_SHA512_CRYPT
                .rsplit_once('$')
                .expect("dummy hash has a digest")
                .1
        ),
        "startup diagnostics leaked a password hash: {startup_error}"
    );
}

#[test]
fn access_control_debug_never_exposes_reusable_credentials_or_hashes() {
    let plaintext = AccessControl::new(&["alice:debug-only-secret@/:rw"]).unwrap();
    let rendered = format!("{plaintext:?}");
    assert!(!rendered.contains("alice"));
    assert!(!rendered.contains("debug-only-secret"));

    let hash = synthetic_argon2id_phc(19_456, 2, 1, 16, 32);
    let rule = format!("alice:{hash}@/:rw");
    let hashed = AccessControl::new(&[&rule]).unwrap();
    let rendered = format!("{hashed:?}");
    assert!(!rendered.contains("alice"));
    assert!(!rendered.contains(&hash));
}

#[tokio::test]
async fn unknown_plaintext_basic_and_digest_use_unpredictable_non_authenticating_dummy_work() {
    let auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    let other = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    assert_eq!(auth.dummy_plaintext_secret.len(), 64);
    assert_ne!(auth.dummy_plaintext_secret, other.dummy_plaintext_secret);
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 18)).into());

    // 中文：即使测试掌握 dummy 并提交完全匹配的 Basic，`accept_password=false` 仍只能失败；
    // 生产攻击者既无法预测该值，也不能利用已知固定 dummy 进入不同 proof 路径。
    // English: Even a test that knows and exactly submits the dummy Basic secret cannot authenticate
    // with `accept_password=false`; production callers also cannot predict it to select another path.
    let basic = HeaderValue::from_str(&format!(
        "Basic {}",
        STANDARD.encode(format!("candidate:{}", auth.dummy_plaintext_secret))
    ))
    .unwrap();
    let comparisons_before_unknown = auth.plaintext_comparison_count();
    assert!(matches!(
        auth.check_auth(super::CredentialCheck {
            authorization: &basic,
            method: "GET",
            request_target: "/file.txt",
            auth_user: "candidate",
            auth_pass: &auth.dummy_plaintext_secret,
            source,
            admission_username: "candidate",
            accept_password: false,
        })
        .await,
        super::AuthCheckOutcome::PasswordRejected
    ));
    assert_eq!(
        auth.plaintext_comparison_count() - comparisons_before_unknown,
        1,
        "unknown Basic must execute exactly one dummy comparison"
    );

    // 中文：不用不稳定的耗时阈值；测试计数器直接证明 known 与 unknown 各执行一次相同
    // 比较 primitive，`accept_password=false` 没有在 `&&` 左侧短路 dummy。
    // English: Avoid brittle timing thresholds. The deterministic counter proves known and unknown
    // each execute one identical comparison primitive and that `accept_password=false` cannot
    // short-circuit dummy work.
    let known =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("alice:wrong"))).unwrap();
    let comparisons_before_known = auth.plaintext_comparison_count();
    assert!(matches!(
        auth.check_auth(super::CredentialCheck {
            authorization: &known,
            method: "GET",
            request_target: "/file.txt",
            auth_user: "alice",
            auth_pass: "secret",
            source,
            admission_username: "alice",
            accept_password: true,
        })
        .await,
        super::AuthCheckOutcome::PasswordRejected
    ));
    assert_eq!(
        auth.plaintext_comparison_count() - comparisons_before_known,
        1,
        "known Basic must execute exactly one real comparison"
    );

    let nonce = create_nonce().unwrap();
    let ha1 = digest_hex(format!("candidate:{REALM}:{}", auth.dummy_plaintext_secret).as_bytes());
    let ha2 = digest_hex(b"GET:/file.txt");
    let response = digest_hex(format!("{ha1}:{nonce}:00000001:dummy-cnonce:auth:{ha2}").as_bytes());
    let digest = HeaderValue::from_str(&format!(
        "Digest username=\"candidate\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"/file.txt\", response=\"{response}\", algorithm=SHA-256, qop=auth, nc=00000001, cnonce=\"dummy-cnonce\""
    ))
    .unwrap();
    assert!(
        check_auth(
            &digest,
            "GET",
            "/file.txt",
            "candidate",
            &auth.dummy_plaintext_secret
        )
        .is_some()
    );
    assert!(matches!(
        auth.check_auth(super::CredentialCheck {
            authorization: &digest,
            method: "GET",
            request_target: "/file.txt",
            auth_user: "candidate",
            auth_pass: &auth.dummy_plaintext_secret,
            source,
            admission_username: "candidate",
            accept_password: false,
        })
        .await,
        super::AuthCheckOutcome::PasswordRejected
    ));
}

#[tokio::test]
async fn hashed_instances_reject_known_and_unknown_digest_before_account_specific_work() {
    let hash = synthetic_sha512_hash(20_000);
    let rule = format!("alice:{hash}@/:rw");
    let auth = AccessControl::new(&[&rule]).unwrap();
    let known = HeaderValue::from_static("Digest username=alice");
    let unknown = HeaderValue::from_static("Digest username=candidate");
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 19)).into());
    for (authorization, user, pass) in [
        (&known, "alice", hash.as_str()),
        (&unknown, "candidate", auth.dummy_plaintext_secret.as_str()),
    ] {
        assert!(matches!(
            auth.check_auth(super::CredentialCheck {
                authorization,
                method: "GET",
                request_target: "/file.txt",
                auth_user: user,
                auth_pass: pass,
                source,
                admission_username: user,
                accept_password: user == "alice",
            })
            .await,
            super::AuthCheckOutcome::PasswordRejected
        ));
    }
}

#[test]
fn sha512_crypt_requires_one_rounds_profile_and_known_unknown_work_plans_match() {
    let uniform = synthetic_sha512_hash(20_000);
    let first = format!("first:{uniform}@/:rw");
    let second = format!("second:{uniform}@/public:ro");
    let auth = AccessControl::new(&[&first, &second]).unwrap();

    let known = auth.password_hash_work_plan(Some(&uniform)).unwrap();
    let unknown = auth.password_hash_work_plan(None).unwrap();
    assert_eq!(known, unknown);
    assert_eq!(
        known,
        vec![super::PasswordHashWorkProfile::Sha512Crypt { rounds: 20_000 }]
    );

    let mixed = format!("low:{DUMMY_SHA512_CRYPT}@/:rw");
    let error = AccessControl::new(&[&first, &mixed])
        .unwrap_err()
        .to_string();
    assert!(error.contains("one uniform rounds profile"), "{error}");
}

#[tokio::test]
async fn mixed_sha_plaintext_and_unknown_basic_have_identical_counted_work_shape() {
    let hash = synthetic_sha512_hash(20_000);
    let hashed_rule = format!("hashed:{hash}@/:rw");
    let auth = AccessControl::new(&[&hashed_rule, "plain:secret@/:rw"]).unwrap();
    let dummy_hash = auth
        .dummy_password_hash
        .clone()
        .expect("mixed SHA deployment must select its uniform dummy profile");
    assert_eq!(
        auth.password_hash_work_plan(Some(&hash)).unwrap(),
        auth.password_hash_work_plan(None).unwrap(),
        "known hashes and dummy work must use one profile"
    );
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 24)).into());
    let hashed =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("hashed:wrong"))).unwrap();
    let plaintext =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("plain:wrong"))).unwrap();
    let unknown =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("unknown:wrong"))).unwrap();

    // 中文：计数真实比较 primitive 与已提交 worker，不比较易受调度/CPU 噪声影响的耗时。
    // 三类路径都必须严格是“一次明文比较 + 一次统一成本哈希”。
    // English: Count the real comparison primitive and submitted worker instead of noisy elapsed
    // time. Every branch must be exactly one plaintext comparison plus one uniform-cost hash.
    for (authorization, user, pass, accept_password) in [
        (&hashed, "hashed", hash.as_str(), true),
        (&plaintext, "plain", "secret", true),
        (&unknown, "unknown", dummy_hash.as_str(), false),
    ] {
        let comparisons_before = auth.plaintext_comparison_count();
        let workers_before = auth.password_hash_worker_count();
        assert!(matches!(
            auth.check_auth(super::CredentialCheck {
                authorization,
                method: "GET",
                request_target: "/file.txt",
                auth_user: user,
                auth_pass: pass,
                source,
                admission_username: user,
                accept_password,
            })
            .await,
            super::AuthCheckOutcome::PasswordRejected
        ));
        assert_eq!(auth.plaintext_comparison_count() - comparisons_before, 1);
        assert_eq!(auth.password_hash_worker_count() - workers_before, 1);
    }
}

#[test]
fn argon2id_policy_accepts_documented_profile_and_rejects_every_parameter_boundary() {
    let valid = synthetic_argon2id_phc(
        ARGON2_M_COST_MIN_KIB,
        ARGON2_T_COST_MIN,
        ARGON2_P_COST_MIN,
        ARGON2_SALT_MIN_BYTES,
        ARGON2_OUTPUT_MIN_BYTES,
    );
    argon2id_profile_from_phc(&valid).unwrap();

    for (m_cost, accepted) in [
        (ARGON2_M_COST_MIN_KIB - 1, false),
        (ARGON2_M_COST_MIN_KIB, true),
        (ARGON2_M_COST_MIN_KIB + 1, true),
        (ARGON2_M_COST_MAX_KIB - 1, true),
        (ARGON2_M_COST_MAX_KIB, true),
        (ARGON2_M_COST_MAX_KIB + 1, false),
    ] {
        let phc = synthetic_argon2id_phc(
            m_cost,
            ARGON2_T_COST_MIN,
            ARGON2_P_COST_MIN,
            ARGON2_SALT_MIN_BYTES,
            ARGON2_OUTPUT_MIN_BYTES,
        );
        assert_eq!(
            argon2id_profile_from_phc(&phc).is_ok(),
            accepted,
            "m={m_cost}"
        );
    }
    for (t_cost, accepted) in [
        (ARGON2_T_COST_MIN - 1, false),
        (ARGON2_T_COST_MIN, true),
        (ARGON2_T_COST_MIN + 1, true),
        (ARGON2_T_COST_MAX - 1, true),
        (ARGON2_T_COST_MAX, true),
        (ARGON2_T_COST_MAX + 1, false),
    ] {
        let phc = synthetic_argon2id_phc(
            ARGON2_M_COST_MIN_KIB,
            t_cost,
            ARGON2_P_COST_MIN,
            ARGON2_SALT_MIN_BYTES,
            ARGON2_OUTPUT_MIN_BYTES,
        );
        assert_eq!(
            argon2id_profile_from_phc(&phc).is_ok(),
            accepted,
            "t={t_cost}"
        );
    }
    for (p_cost, accepted) in [
        (ARGON2_P_COST_MIN - 1, false),
        (ARGON2_P_COST_MIN, true),
        (ARGON2_P_COST_MIN + 1, true),
        (ARGON2_P_COST_MAX - 1, true),
        (ARGON2_P_COST_MAX, true),
        (ARGON2_P_COST_MAX + 1, false),
    ] {
        let phc = synthetic_argon2id_phc(
            ARGON2_M_COST_MIN_KIB,
            ARGON2_T_COST_MIN,
            p_cost,
            ARGON2_SALT_MIN_BYTES,
            ARGON2_OUTPUT_MIN_BYTES,
        );
        assert_eq!(
            argon2id_profile_from_phc(&phc).is_ok(),
            accepted,
            "p={p_cost}"
        );
    }
}

#[test]
fn argon2id_policy_bounds_salt_output_version_and_exact_parameter_set() {
    for (salt_len, accepted) in [
        (ARGON2_SALT_MIN_BYTES - 1, false),
        (ARGON2_SALT_MIN_BYTES, true),
        (ARGON2_SALT_MAX_BYTES, true),
        (ARGON2_SALT_MAX_BYTES + 1, false),
    ] {
        let phc = synthetic_argon2id_phc(
            ARGON2_M_COST_MIN_KIB,
            ARGON2_T_COST_MIN,
            ARGON2_P_COST_MIN,
            salt_len,
            ARGON2_OUTPUT_MIN_BYTES,
        );
        assert_eq!(
            argon2id_profile_from_phc(&phc).is_ok(),
            accepted,
            "salt_len={salt_len}"
        );
    }
    for (output_len, accepted) in [
        (ARGON2_OUTPUT_MIN_BYTES - 1, false),
        (ARGON2_OUTPUT_MIN_BYTES, true),
        (ARGON2_OUTPUT_MAX_BYTES, true),
        (ARGON2_OUTPUT_MAX_BYTES + 1, false),
    ] {
        let phc = synthetic_argon2id_phc(
            ARGON2_M_COST_MIN_KIB,
            ARGON2_T_COST_MIN,
            ARGON2_P_COST_MIN,
            ARGON2_SALT_MIN_BYTES,
            output_len,
        );
        assert_eq!(
            argon2id_profile_from_phc(&phc).is_ok(),
            accepted,
            "output_len={output_len}"
        );
    }

    let valid = synthetic_argon2id_phc(
        ARGON2_M_COST_MIN_KIB,
        ARGON2_T_COST_MIN,
        ARGON2_P_COST_MIN,
        ARGON2_SALT_MIN_BYTES,
        ARGON2_OUTPUT_MIN_BYTES,
    );
    assert!(argon2id_profile_from_phc(&valid.replace("v=19", "v=16")).is_err());
    assert!(argon2id_profile_from_phc(&valid.replace("p=1", "p=1,keyid=YWJj")).is_err());
    assert!(argon2id_profile_from_phc(&valid.replace("$m=", "$x=1,m=")).is_err());
}

#[test]
fn argon2id_requires_one_family_and_one_uniform_profile() {
    let primary = synthetic_argon2id_phc(19_456, 2, 1, 16, 32);
    let same_profile = synthetic_argon2id_phc(19_456, 2, 1, 20, 32);
    let first = format!("first:{primary}@/:rw");
    let second = format!("second:{same_profile}@/public:ro");
    let auth = AccessControl::new(&[&first, &second]).unwrap();
    assert_eq!(auth.dummy_password_hash.as_deref(), Some(primary.as_str()));
    assert!(auth.argon2id_profile.is_some());
    assert_eq!(
        auth.password_hash_work_plan(Some(&same_profile)).unwrap(),
        auth.password_hash_work_plan(None).unwrap()
    );

    let changed = synthetic_argon2id_phc(19_457, 2, 1, 16, 32);
    let changed = format!("second:{changed}@/:rw");
    assert!(
        AccessControl::new(&[&first, &changed])
            .unwrap_err()
            .to_string()
            .contains("one uniform")
    );
    assert!(
        AccessControl::new(&[&first, "plain:password@/:rw"])
            .unwrap_err()
            .to_string()
            .contains("cannot be mixed")
    );
    let sha = format!("sha:{DUMMY_SHA512_CRYPT}@/:rw");
    assert!(
        AccessControl::new(&[&first, &sha])
            .unwrap_err()
            .to_string()
            .contains("cannot be mixed")
    );
    for unsupported in [
        "user:$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$YWJjZGVmZ2hpamtsbW5vcA@/:rw",
        "user:$argon2d$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$YWJjZGVmZ2hpamtsbW5vcA@/:rw",
        "user:$scrypt$ln=15,r=8,p=1$c2FsdHNhbHQ$YWJjZGVmZ2hpamtsbW5vcA@/:rw",
    ] {
        assert!(AccessControl::new(&[unsupported]).is_err());
    }
}

#[tokio::test]
async fn argon2id_basic_verifies_correct_wrong_and_unknown_users_through_hash_admission() {
    const HASH: &str =
        "$argon2id$v=19$m=19456,t=2,p=1$YmFkIHNhbHQh$DqHGwv6NQV0VcaJi7jeF1E8IpfMXmXcpq4r2kKyqpXk";
    assert!(verify_supported_password_hash(b"password", HASH));
    assert!(!verify_supported_password_hash(b"wrong", HASH));
    let rule = format!("alice:{HASH}@/:rw");

    fn request(authorization: &HeaderValue) -> AuthRequest<'_> {
        AuthRequest {
            path: "index.html",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(authorization),
            request_target: "/index.html",
            source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        }
    }
    let valid = HeaderValue::from_static("Basic YWxpY2U6cGFzc3dvcmQ=");
    let auth = AccessControl::new(&[&rule]).unwrap();
    assert!(matches!(
        auth.guard(request(&valid)).await,
        AuthDecision::Allowed { .. }
    ));

    let wrong = HeaderValue::from_static("Basic YWxpY2U6d3Jvbmc=");
    let auth = AccessControl::new(&[&rule]).unwrap();
    assert!(matches!(
        auth.guard(request(&wrong)).await,
        AuthDecision::Unauthorized
    ));

    let unknown = HeaderValue::from_static("Basic Ym9iOnBhc3N3b3Jk");
    let auth = AccessControl::new(&[&rule]).unwrap();
    assert!(matches!(
        auth.guard(request(&unknown)).await,
        AuthDecision::Unauthorized
    ));

    let mut keyed_limited = AccessControl::new(&[&rule]).unwrap();
    keyed_limited.password_hash_admission = test_admission(1, 2, 0, 2);
    assert!(matches!(
        keyed_limited.guard(request(&valid)).await,
        AuthDecision::RateLimited { .. }
    ));
}

#[test]
fn expired_backoff_admits_one_correct_recovery_attempt_without_sleeping() {
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 23)).into());
    let key = AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "alice");
    let start = Instant::now();
    let mut limiter = super::AuthRateLimiter::default();

    for _ in 0..AUTH_RATE_FREE_FAILURES {
        limiter
            .reserve_hash_attempt(key.clone(), start)
            .expect("free credential attempt must be admitted");
        assert!(limiter.finish_hash_attempt(&key, false, start));
    }
    assert_eq!(
        limiter.reserve_hash_attempt(key.clone(), start),
        Err(HashAttemptReservationReject::Blocked {
            retry_after_secs: 1
        })
    );

    // 中文：直接推进确定性 Instant，不依赖墙钟或 sleep。deadline 到达后，一个请求可进入；
    // 它提交正确 proof 后清除用户名状态，证明退避不是永久锁死。
    // English: Advance a deterministic Instant without wall-clock sleeps. At the deadline exactly
    // one request enters, and committing its correct proof clears the principal rather than renewing
    // a permanent lockout.
    let after_backoff = start + Duration::from_secs(1);
    limiter
        .reserve_hash_attempt(key.clone(), after_backoff)
        .expect("one recovery attempt must be admitted after backoff");
    assert_eq!(
        limiter.reserve_hash_attempt(key.clone(), after_backoff),
        Err(HashAttemptReservationReject::ConcurrentAttemptLimit)
    );
    assert!(limiter.finish_hash_attempt(&key, true, after_backoff));
    assert!(!limiter.entries.contains_key(&key));
}

#[test]
fn authentication_rate_protocol_domains_cannot_collide() {
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17)).into());
    let keys = [
        AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, ""),
        AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "alice"),
        // 中文：即使配置用户名恰好等于协议域标签，直接用户名哈希也不能碰撞协议域。
        // English: Even a configured username equal to a protocol-domain label cannot collide with a
        // protocol-domain key.
        AuthRateKey::new(source, "password-principal"),
    ];
    for left in 0..keys.len() {
        for right in (left + 1)..keys.len() {
            assert_ne!(keys[left], keys[right]);
        }
    }
}

#[tokio::test]
async fn basic_and_digest_failures_update_source_and_claimed_name_buckets_uniformly() {
    let auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)).into());
    let basic = |credentials: &str| {
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(credentials))).unwrap()
    };
    let unknown_basic = basic("mallory:wrong");
    let unknown_digest = HeaderValue::from_static("Digest username=trent");
    let known_basic = basic("alice:wrong");

    for authorization in [&unknown_basic, &unknown_digest, &known_basic] {
        assert!(matches!(
            auth.guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(authorization),
                request_target: "/file.txt",
                source,
            })
            .await,
            AuthDecision::Unauthorized
        ));
    }

    let state = auth.auth_rate.lock().unwrap();
    let source_key = AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, "");
    // 中文：每次失败都进入跨用户名来源预算，同时进入只按声明名派生的用户名桶；
    // known/unknown 与 Basic/Digest 不会改变派生规则。
    // English: Every failure charges the cross-name source budget and the bucket derived solely
    // from its claimed name; known/unknown status and Basic versus Digest never alter that rule.
    assert_eq!(state.entries.len(), 4);
    assert_eq!(state.entries.get(&source_key).unwrap().failures, 3);
    for user in ["mallory", "trent", "alice"] {
        let principal_key = AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, user);
        assert_eq!(state.entries.get(&principal_key).unwrap().failures, 1);
    }
}

#[tokio::test]
async fn successful_low_privilege_login_cannot_clear_admin_or_source_failures() {
    let auth =
        AccessControl::new(&["admin:admin-secret@/:rw", "low:low-secret@/public:ro"]).unwrap();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21)).into());
    let basic = |credentials: &str| {
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(credentials))).unwrap()
    };
    let wrong_admin = basic("admin:wrong");
    let valid_low = basic("low:low-secret");
    let request = |authorization| AuthRequest {
        path: "public/file.txt",
        method: &Method::GET,
        authorization_method: &Method::GET,
        authorization: Some(authorization),
        request_target: "/public/file.txt",
        source,
    };

    // 中文：攻击者在退避前穿插一个真实低权登录。旧单一来源桶会在这里被成功清空，
    // 从而允许无限重复“三次 admin 猜测 + 一次 low 成功”。
    // English: Insert a real low-privilege login before backoff. The former single source bucket
    // was cleared here, enabling an unlimited three-admin-guesses-plus-one-low-success cycle.
    for _ in 0..3 {
        assert!(matches!(
            auth.guard(request(&wrong_admin)).await,
            AuthDecision::Unauthorized
        ));
    }
    assert!(matches!(
        auth.guard(request(&valid_low)).await,
        AuthDecision::Allowed {
            user: Some(ref user),
            ..
        } if user == "low"
    ));

    let source_key = AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, "");
    let admin_key = AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "admin");
    let low_key = AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "low");
    {
        let state = auth.auth_rate.lock().unwrap();
        assert_eq!(state.entries.get(&source_key).unwrap().failures, 3);
        assert_eq!(state.entries.get(&admin_key).unwrap().failures, 3);
        assert!(!state.entries.contains_key(&low_key));
    }

    assert!(matches!(
        auth.guard(request(&wrong_admin)).await,
        AuthDecision::Unauthorized
    ));
    assert!(matches!(
        auth.guard(request(&wrong_admin)).await,
        AuthDecision::RateLimited { .. }
    ));
    let state = auth.auth_rate.lock().unwrap();
    assert_eq!(state.entries.get(&admin_key).unwrap().failures, 4);
    assert!(state.entries.get(&source_key).unwrap().failures >= 4);
}

#[tokio::test]
async fn rotating_fake_usernames_cannot_bypass_the_cross_name_source_budget() {
    let auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22)).into());

    for index in 0..AUTH_RATE_FREE_FAILURES {
        let credentials = format!("fake-{index}:wrong");
        let authorization =
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(credentials))).unwrap();
        assert!(matches!(
            auth.guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&authorization),
                request_target: "/file.txt",
                source,
            })
            .await,
            AuthDecision::Unauthorized
        ));
    }

    // 中文：第五个从未见过的声明名仍被来源预算阻止；用户名桶不会泄露存在性，而来源层
    // 阻止攻击者用无限新名字取得无限免费校验。
    // English: A fifth never-before-seen claimed name is still stopped by the source budget. The
    // principal bucket does not reveal existence, while the source layer prevents unlimited free
    // checks through unlimited new names.
    let fifth = HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("fake-overflow:wrong")))
        .unwrap();
    assert!(matches!(
        auth.guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&fifth),
            request_target: "/file.txt",
            source,
        })
        .await,
        AuthDecision::RateLimited { .. }
    ));
    let state = auth.auth_rate.lock().unwrap();
    let source_key = AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, "");
    assert_eq!(
        state.entries.get(&source_key).unwrap().failures,
        AUTH_RATE_FREE_FAILURES
    );
    let overflow_key =
        AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "fake-overflow");
    assert!(!state.entries.contains_key(&overflow_key));
}

#[tokio::test]
async fn known_and_unknown_basic_or_digest_candidates_have_identical_source_backoff() {
    let basic = |credentials: &str| {
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(credentials))).unwrap()
    };
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 16)).into());
    for candidate in [
        basic("alice:wrong"),
        basic("candidate-unknown:wrong"),
        HeaderValue::from_static("Digest username=alice"),
        HeaderValue::from_static("Digest username=candidate-unknown"),
    ] {
        let auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
        let pollution = basic("other-unknown:wrong");
        for _ in 0..AUTH_RATE_FREE_FAILURES {
            assert!(matches!(
                auth.guard(AuthRequest {
                    path: "file.txt",
                    method: &Method::GET,
                    authorization_method: &Method::GET,
                    authorization: Some(&pollution),
                    request_target: "/file.txt",
                    source,
                })
                .await,
                AuthDecision::Unauthorized
            ));
        }
        // 中文：第五次失败只由公共来源状态决定；候选账号存在性和 Basic/Digest 协议均不改变 429。
        // English: The fifth failure is selected solely by shared source state; account existence
        // and Basic versus Digest cannot change the observable 429 result.
        assert!(matches!(
            auth.guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&candidate),
                request_target: "/file.txt",
                source,
            })
            .await,
            AuthDecision::RateLimited { .. }
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hashed_basic_admission_does_not_normalize_unknown_accounts_into_an_oracle_bucket() {
    let maximum = synthetic_sha512_hash(20_000);
    let rule = format!("alice:{maximum}@/:rw");
    let auth = AccessControl::new(&[&rule]).unwrap();

    // 中文：模拟旧实现中三个不同未知名正在 dummy worker 内，却都被错误归入 `<unknown>`
    // admission 主体。新请求必须按自身声明名分区，因此 known/unknown 都能使用保留的第四槽。
    // English: Model three different unknown-name dummy workers that the old implementation wrongly
    // grouped under `<unknown>`. New requests must use their own claimed name, so known and unknown
    // candidates can both use the reserved fourth slot.
    let mut held = Vec::new();
    for octet in 1..=PASSWORD_VERIFY_PER_USERNAME {
        let source = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet as u8)).into());
        let mut guard = auth
            .password_hash_admission
            .try_reserve(source, "<unknown>")
            .unwrap();
        guard.started().unwrap();
        let permit = auth
            .password_hash_admission
            .verify_limit
            .clone()
            .try_acquire_owned()
            .unwrap();
        held.push((guard, permit));
    }
    let source = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200)).into());
    let known =
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode("alice:wrong"))).unwrap();
    let unknown = HeaderValue::from_str(&format!(
        "Basic {}",
        STANDARD.encode("candidate-unknown:wrong")
    ))
    .unwrap();
    for authorization in [&known, &unknown] {
        assert!(matches!(
            auth.guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(authorization),
                request_target: "/file.txt",
                source,
            })
            .await,
            AuthDecision::Unauthorized
        ));
    }
    drop(held);
}

#[test]
fn source_username_and_global_hash_budgets_are_independent_and_recycle_keys() {
    let source_a = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)).into());
    let source_b = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)).into());
    let admission = test_admission(1, 4, 1, 1);
    let first = admission.try_reserve(source_a, "alice").unwrap();
    assert!(matches!(
        admission.try_reserve(source_a, "bob"),
        Err(PasswordHashAdmissionOutcome::SourceLimit)
    ));
    assert!(matches!(
        admission.try_reserve(source_b, "alice"),
        Err(PasswordHashAdmissionOutcome::UsernameLimit)
    ));
    {
        let state = admission.state.lock().unwrap();
        assert_eq!(state.counters.source_limit, 1);
        assert_eq!(state.counters.username_limit, 1);
        assert_eq!(state.per_source.len(), 1);
        assert_eq!(state.per_username.len(), 1);
    }
    drop(first);
    {
        let state = admission.state.lock().unwrap();
        assert_eq!(state.in_flight, 0);
        assert!(state.per_source.is_empty());
        assert!(state.per_username.is_empty());
    }

    let global = test_admission(1, 1, 2, 2);
    let first = global.try_reserve(source_a, "alice").unwrap();
    assert!(matches!(
        global.try_reserve(source_b, "bob"),
        Err(PasswordHashAdmissionOutcome::GlobalQueueFull)
    ));
    assert_eq!(global.state.lock().unwrap().counters.global_queue_full, 1);
    drop(first);
}

#[test]
fn one_source_cannot_exhaust_an_accounts_hash_workers_or_all_global_capacity() {
    let attacker = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)).into());
    let legitimate = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)).into());
    let other_source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)).into());
    let admission = test_admission(
        PASSWORD_VERIFY_CONCURRENCY,
        PASSWORD_VERIFY_CONCURRENCY,
        PASSWORD_VERIFY_PER_SOURCE,
        PASSWORD_VERIFY_PER_USERNAME,
    );

    let alice_attacker_1 = admission.try_reserve(attacker, "alice").unwrap();
    let alice_attacker_2 = admission.try_reserve(attacker, "alice").unwrap();
    assert!(matches!(
        admission.try_reserve(attacker, "alice"),
        Err(PasswordHashAdmissionOutcome::SourceLimit)
    ));

    // 账户上限严格大于单一来源上限，因此另一已验证来源仍可预留一次 Alice 校验。
    // The account ceiling is larger than one source ceiling, so another source can reserve Alice verification.
    let alice_legitimate = admission.try_reserve(legitimate, "alice").unwrap();
    assert!(matches!(
        admission.try_reserve(other_source, "alice"),
        Err(PasswordHashAdmissionOutcome::UsernameLimit)
    ));

    // Alice 最多占四个工作槽中的三个，另一账户即使在边界也保留全局预留。
    // Alice consumes at most three of four worker slots, leaving a global reservation for another account.
    let bob = admission.try_reserve(other_source, "bob").unwrap();
    assert!(matches!(
        admission.try_reserve(legitimate, "charlie"),
        Err(PasswordHashAdmissionOutcome::GlobalQueueFull)
    ));

    drop((alice_attacker_1, alice_attacker_2, alice_legitimate, bob));
    assert_eq!(admission.state.lock().unwrap().in_flight, 0);
}

#[test]
fn admission_status_mapping_distinguishes_client_floods_from_server_saturation() {
    for outcome in [
        PasswordHashAdmissionOutcome::SourceLimit,
        PasswordHashAdmissionOutcome::UsernameLimit,
        PasswordHashAdmissionOutcome::ConcurrentAttemptLimit,
        PasswordHashAdmissionOutcome::BlockedAfterGlobalPermit {
            retry_after_secs: 7,
        },
    ] {
        assert_eq!(outcome.mapped_status(), 429);
        assert!(matches!(
            outcome.into_decision(),
            AuthDecision::RateLimited { .. }
        ));
    }
    assert!(matches!(
        PasswordHashAdmissionOutcome::BlockedAfterGlobalPermit {
            retry_after_secs: 7
        }
        .into_decision(),
        AuthDecision::RateLimited {
            retry_after_secs: 7
        }
    ));

    for outcome in [
        PasswordHashAdmissionOutcome::GlobalQueueFull,
        PasswordHashAdmissionOutcome::StateUnavailable,
        PasswordHashAdmissionOutcome::QueueTimeout,
        PasswordHashAdmissionOutcome::QueueClosed,
        PasswordHashAdmissionOutcome::WorkerFailed,
        PasswordHashAdmissionOutcome::RateStateCapacity,
        PasswordHashAdmissionOutcome::RateStateUnavailable,
    ] {
        assert_eq!(outcome.mapped_status(), 503);
        assert!(matches!(
            outcome.into_decision(),
            AuthDecision::ServiceUnavailable { .. }
        ));
    }
}

#[tokio::test]
async fn actual_auth_path_maps_keyed_rejection_to_429_and_queue_timeout_to_503() {
    let maximum = synthetic_sha512_hash(20_000);
    let rule = format!("alice:{maximum}@/:rw");
    let authorization = HeaderValue::from_static("Basic YWxpY2U6d3Jvbmc=");
    let request = || AuthRequest {
        path: "index.html",
        method: &Method::GET,
        authorization_method: &Method::GET,
        authorization: Some(&authorization),
        request_target: "/index.html",
        source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
    };

    let mut keyed_limited = AccessControl::new(&[&rule]).unwrap();
    keyed_limited.password_hash_admission = test_admission(1, 2, 0, 2);
    assert!(matches!(
        keyed_limited.guard(request()).await,
        AuthDecision::RateLimited {
            retry_after_secs: 1
        }
    ));
    assert!(keyed_limited.auth_rate.lock().unwrap().entries.is_empty());
    assert_eq!(
        keyed_limited
            .password_hash_admission
            .state
            .lock()
            .unwrap()
            .counters
            .source_limit,
        1
    );

    let mut queue_saturated = AccessControl::new(&[&rule]).unwrap();
    queue_saturated.password_hash_admission = Arc::new(PasswordHashAdmission {
        verify_limit: Arc::new(Semaphore::new(0)),
        state: Mutex::new(PasswordHashAdmissionState::default()),
        capacity: 2,
        per_source_limit: 2,
        per_username_limit: 2,
        queue_timeout: Duration::ZERO,
    });
    assert!(matches!(
        queue_saturated.guard(request()).await,
        AuthDecision::ServiceUnavailable {
            retry_after_secs: 1
        }
    ));
    // 准入失败绝不会变成密码错误失败。
    // Admission failure never becomes an incorrect-password failure.
    assert!(queue_saturated.auth_rate.lock().unwrap().entries.is_empty());
    let state = queue_saturated
        .password_hash_admission
        .state
        .lock()
        .unwrap();
    assert_eq!(state.counters.queue_timeout, 1);
    assert_eq!((state.in_flight, state.active), (0, 0));
    assert!(state.per_source.is_empty());
    assert!(state.per_username.is_empty());
}

#[test]
fn poisoned_rate_state_cannot_fail_open_on_a_valid_plaintext_password() {
    let auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    let poisoned = auth.auth_rate.clone();
    let _ = std::panic::catch_unwind(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("deliberately poison authentication rate state");
    });

    // 中文：限流状态被污染后，即使密码正确也必须 fail closed 返回 503，而非放行。
    // English: With poisoned rate state, even a correct password must fail closed as 503 rather than pass.
    let authorization = HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0");
    let decision = ready_now(auth.guard(AuthRequest {
        path: "index.html",
        method: &Method::GET,
        authorization_method: &Method::GET,
        authorization: Some(&authorization),
        request_target: "/index.html",
        source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
    }));
    assert!(matches!(
        decision,
        AuthDecision::ServiceUnavailable {
            retry_after_secs: 1
        }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_owns_every_hash_resource_after_the_request_future_is_dropped() {
    let limiter = Arc::new(Mutex::new(super::AuthRateLimiter::default()));
    let source = Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let source_key = AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, "");
    let principal_key = AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "alice");
    let reservation = PasswordRateReservation::reserve(
        limiter.clone(),
        source_key.clone(),
        principal_key.clone(),
    )
    .unwrap();
    let admission = test_admission(1, 2, 2, 2);
    let guard = admission.try_reserve(source, "alice").unwrap();
    let permit = admission.verify_limit.clone().try_acquire_owned().unwrap();
    let (lease, _) = PasswordHashWorkerLease::start(permit, guard, reservation).unwrap();

    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let _ = started_tx.send(());
        let _ = release_rx.blocking_recv();
        let committed = lease.finish(false);
        let _ = done_tx.send(committed);
    });
    started_rx.await.unwrap();

    // 中止/丢弃运行中的 spawn_blocking JoinHandle 模拟取消 HTTP future。Tokio 无法停止工作
    // 线程，其租约必须继续占用全部预算直到闭包退出。
    // Aborting/dropping a running spawn_blocking JoinHandle models cancellation. Tokio cannot stop
    // the worker, whose lease must consume all budgets until the closure exits.
    worker.abort();
    drop(worker);
    {
        let state = admission.state.lock().unwrap();
        assert_eq!((state.in_flight, state.active), (1, 1));
    }
    {
        let state = limiter.lock().unwrap();
        for key in [&source_key, &principal_key] {
            let state = state.entries.get(key).unwrap();
            assert_eq!((state.failures, state.pending_hash_attempts), (0, 1));
        }
    }
    assert_eq!(admission.verify_limit.available_permits(), 0);

    release_tx.send(()).unwrap();
    assert!(done_rx.await.unwrap());
    {
        let state = admission.state.lock().unwrap();
        assert_eq!((state.in_flight, state.active), (0, 0));
        assert!(state.per_source.is_empty());
        assert!(state.per_username.is_empty());
    }
    {
        let state = limiter.lock().unwrap();
        for key in [&source_key, &principal_key] {
            let state = state.entries.get(key).unwrap();
            assert_eq!((state.failures, state.pending_hash_attempts), (1, 0));
        }
    }
    assert_eq!(admission.verify_limit.available_permits(), 1);
}

fn replay_attempt(user: &str, nc: u32) -> DigestReplayAttempt {
    DigestReplayAttempt {
        key: DigestReplayKey {
            nonce: [b'n'; 34],
            user: Arc::from(user),
            cnonce: Arc::from(*b"c"),
            nc,
        },
        expires_at: 100,
    }
}

#[test]
fn digest_replay_variable_key_budget_is_derived_from_input_limits() {
    assert_eq!(
        DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES,
        DIGEST_REPLAY_CAPACITY * (AUTH_USERNAME_MAX_LEN + DIGEST_CNONCE_MAX_LEN)
    );
    assert_eq!(DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES, 24 * 1024 * 1024);
}

#[test]
fn configured_auth_username_has_a_hard_byte_limit() {
    let accepted = format!("{}:pass@/", "u".repeat(AUTH_USERNAME_MAX_LEN));
    AccessControl::new(&[&accepted]).expect("boundary username should be accepted");

    let rejected = format!("{}:pass@/", "u".repeat(AUTH_USERNAME_MAX_LEN + 1));
    let error = AccessControl::new(&[&rejected]).unwrap_err().to_string();
    assert!(error.contains("username exceeds 256 bytes"));
    assert!(!error.contains(":pass@"));
}

#[test]
fn acl_empty_entries_fail_closed_without_partially_mutating_the_tree() {
    let mut paths = super::AccessPaths::default();
    assert!(paths.merge("/existing:rw").is_some());
    let original = paths.clone();

    for malformed in [
        "/intended,,/other",
        "/intended,:rw,/other",
        "/intended,/other,",
        ",/intended",
    ] {
        assert!(paths.merge(malformed).is_none(), "accepted {malformed:?}");
        assert_eq!(paths, original, "partially applied {malformed:?}");
    }

    for malformed in ["/intended,,/other", "/intended,:rw,/other"] {
        let rule = format!("alice:do-not-log-this@{malformed}");
        let error = AccessControl::new(&[&rule]).unwrap_err().to_string();
        assert!(error.contains("Invalid auth path rules for user `alice`"));
        assert!(!error.contains("do-not-log-this"));
    }
}

#[test]
fn acl_paths_reject_ambiguous_or_escaping_components() {
    for malformed in ["relative", "/a//b", "/a/./b", "/a/../b", "/a/\0b"] {
        let mut paths = super::AccessPaths::default();
        assert!(paths.merge(malformed).is_none(), "accepted {malformed:?}");
        assert_eq!(paths, super::AccessPaths::default());
    }
    let mut paths = super::AccessPaths::default();
    assert!(paths.merge("/:ro,/nested/path/:rw").is_some());
}

#[test]
fn acl_single_path_depth_limit_has_an_exact_boundary() {
    let at_limit = format!("/{}", vec!["x"; super::AUTH_ACL_PATH_MAX_DEPTH].join("/"));
    let mut accepted = super::AccessPaths::default();
    assert!(accepted.merge(&at_limit).is_some());

    let over_limit = format!("{at_limit}/x");
    let mut rejected = super::AccessPaths::default();
    assert!(rejected.merge(&over_limit).is_none());
    assert_eq!(rejected, super::AccessPaths::default());
}

#[test]
fn acl_aggregate_rule_and_component_budgets_are_exact() {
    let root_rules = std::iter::repeat_n("/", super::AUTH_ACL_PATH_RULE_MAX_COUNT)
        .collect::<Vec<_>>()
        .join(",");
    let mut paths = super::AccessPaths::default();
    assert!(paths.merge(&root_rules).is_some());
    assert!(paths.merge(&format!("{root_rules},/")).is_none());

    let deep_path = format!("/{}", vec!["x"; super::AUTH_ACL_PATH_MAX_DEPTH].join("/"));
    let repeated = std::iter::repeat_n(
        deep_path.as_str(),
        super::AUTH_ACL_COMPONENT_MAX_TOTAL / super::AUTH_ACL_PATH_MAX_DEPTH,
    )
    .collect::<Vec<_>>()
    .join(",");
    let mut budget = super::acl::AccessPathBudget::default();
    let mut aggregate = super::AccessPaths::default();
    aggregate
        .merge_with_budget(&repeated, &mut budget)
        .expect("the exact aggregate component budget must be accepted");
    let original = aggregate.clone();
    assert!(aggregate.merge_with_budget("/extra", &mut budget).is_err());
    assert_eq!(aggregate, original);
}

#[test]
fn expanded_account_rule_count_has_an_exact_boundary() {
    let rules = (0..super::AUTH_ACCOUNT_RULE_MAX_COUNT)
        .map(|index| format!("user{index}:password@/"))
        .collect::<Vec<_>>();
    let refs = rules.iter().map(String::as_str).collect::<Vec<_>>();
    super::split_rules(&refs).expect("the exact account-rule budget must be accepted");

    let mut excessive = rules;
    excessive.push("overflow:password@/".to_string());
    let refs = excessive.iter().map(String::as_str).collect::<Vec<_>>();
    let error = super::split_rules(&refs).unwrap_err().to_string();
    assert!(error.contains("4096-account-rule limit"), "{error}");
}

#[test]
fn iterative_acl_traversal_preserves_inheritance_and_entry_order() {
    let mut paths = super::AccessPaths::default();
    paths
        .merge("/read:ro,/branch/write:rw,/later:ro")
        .expect("valid ACL");

    assert!(
        paths
            .find("read/child")
            .is_some_and(|path| path.perm() == super::AccessPerm::ReadOnly)
    );
    assert!(
        paths
            .find("branch")
            .is_some_and(|path| path.perm().indexonly())
    );
    assert!(
        paths
            .find("branch/write/child")
            .is_some_and(|path| path.perm().readwrite())
    );
    assert!(paths.find("missing").is_none());
    assert!(paths.has_write_access());
    assert_eq!(
        paths.entry_paths(Path::new("base")),
        vec![
            Path::new("base/read").to_path_buf(),
            Path::new("base/branch/write").to_path_buf(),
            Path::new("base/later").to_path_buf(),
        ]
    );
}

async fn digest_proof_with_cnonce(cnonce: &str) -> Option<super::AuthProof> {
    let nonce = create_nonce().unwrap();
    let ha1 = digest_hex(format!("user:{REALM}:pass").as_bytes());
    let ha2 = digest_hex(b"GET:/");
    let response = digest_hex(format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}").as_bytes());
    let authorization = HeaderValue::from_str(&format!(
            "Digest username=\"user\", realm=\"{REALM}\", nonce=\"{nonce}\", uri=\"/\", response=\"{response}\", algorithm=SHA-256, qop=auth, nc=00000001, cnonce=\"{cnonce}\""
        ))
        .unwrap();
    check_auth(&authorization, "GET", "/", "user", "pass")
}

#[tokio::test]
async fn digest_cnonce_has_exact_boundary_checks() {
    assert!(digest_proof_with_cnonce("").await.is_none());
    assert!(digest_proof_with_cnonce("c").await.is_some());
    assert!(
        digest_proof_with_cnonce(&"c".repeat(DIGEST_CNONCE_MAX_LEN - 1))
            .await
            .is_some()
    );
    assert!(
        digest_proof_with_cnonce(&"c".repeat(DIGEST_CNONCE_MAX_LEN))
            .await
            .is_some()
    );
    assert!(
        digest_proof_with_cnonce(&"c".repeat(DIGEST_CNONCE_MAX_LEN + 1))
            .await
            .is_none()
    );
}

#[test]
fn digest_expiry_heap_removes_only_elapsed_entries() {
    let mut cache = DigestReplayCache::default();
    let mut long_lived = replay_attempt("alice", 1);
    long_lived.expires_at = 1_000;
    let long_key = long_lived.key.clone();
    let mut short_lived = replay_attempt("alice", 2);
    short_lived.expires_at = 10;
    let short_key = short_lived.key.clone();

    cache.accept(long_lived, None, 1).unwrap();
    cache.accept(short_lived, None, 1).unwrap();
    cache.prune(10);

    assert_eq!(cache.entry_count, 1);
    assert!(cache.contains(&long_key));
    assert!(!cache.contains(&short_key));
    assert_eq!(cache.expirations.len(), 1);
    assert_eq!(cache.per_user_entries.get("alice").copied(), Some(1));
}

#[test]
fn one_digest_user_cannot_exhaust_everyones_replay_budget() {
    let mut cache = DigestReplayCache {
        capacity: 4,
        per_user_capacity: 2,
        per_nonce_capacity: 4,
        per_source_capacity: 4,
        ..DigestReplayCache::default()
    };

    assert!(cache.accept(replay_attempt("alice", 1), None, 1).is_ok());
    assert!(cache.accept(replay_attempt("alice", 2), None, 1).is_ok());
    assert_eq!(
        cache.accept(replay_attempt("alice", 3), None, 1),
        Err(DigestReplayReject::UserCapacity)
    );
    assert!(cache.accept(replay_attempt("bob", 1), None, 1).is_ok());
    assert_eq!(
        cache.accept(replay_attempt("bob", 1), None, 1),
        Err(DigestReplayReject::ExactReplay)
    );
}

#[test]
fn digest_replay_expiry_is_incremental_and_updates_all_budgets() {
    let source = Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    let mut cache = DigestReplayCache {
        capacity: 4,
        per_user_capacity: 4,
        per_nonce_capacity: 4,
        per_source_capacity: 1,
        ..DigestReplayCache::default()
    };
    assert!(cache.accept(replay_attempt("alice", 1), source, 1).is_ok());
    assert_eq!(
        cache.accept(replay_attempt("bob", 1), source, 1),
        Err(DigestReplayReject::SourceCapacity)
    );

    cache.prune(100);
    assert_eq!(cache.entry_count, 0);
    assert_eq!(cache.dynamic_key_bytes, 0);
    assert!(cache.nonces.is_empty());
    assert!(cache.expirations.is_empty());
    assert!(cache.per_user_entries.is_empty());
    assert!(cache.per_source_entries.is_empty());
    assert!(cache.accept(replay_attempt("bob", 1), source, 100).is_ok());
}

#[test]
fn digest_replay_nonce_budget_is_independent_of_users_and_sources() {
    let mut cache = DigestReplayCache {
        capacity: 4,
        per_user_capacity: 4,
        per_nonce_capacity: 1,
        per_source_capacity: 4,
        ..DigestReplayCache::default()
    };
    assert!(
        cache
            .accept(
                replay_attempt("alice", 1),
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)).into()),
                1,
            )
            .is_ok()
    );
    assert_eq!(
        cache.accept(
            replay_attempt("bob", 1),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)).into()),
            1,
        ),
        Err(DigestReplayReject::NonceCapacity)
    );

    let mut other_nonce = replay_attempt("bob", 1);
    other_nonce.key.nonce = [b'o'; 34];
    assert!(
        cache
            .accept(
                other_nonce,
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)).into()),
                1,
            )
            .is_ok()
    );
    assert_eq!(cache.nonces.len(), 2);
}
