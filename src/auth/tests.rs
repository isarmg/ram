//! 认证单元测试与安全回归测试。
//! Authentication unit and security-regression tests.

use super::{
    ARGON2_M_COST_MAX_KIB, ARGON2_M_COST_MIN_KIB, ARGON2_OUTPUT_MAX_BYTES, ARGON2_OUTPUT_MIN_BYTES,
    ARGON2_P_COST_MAX, ARGON2_P_COST_MIN, ARGON2_SALT_MAX_BYTES, ARGON2_SALT_MIN_BYTES,
    ARGON2_T_COST_MAX, ARGON2_T_COST_MIN, AUTH_RATE_FREE_FAILURES, AUTH_USERNAME_MAX_LEN,
    AccessControl, AuthDecision, AuthRateKey, AuthRequest, AuthSource, BEARER_INVALID_RATE_DOMAIN,
    BEARER_REVOCATION_ADMISSION_DOMAIN, BEARER_SUBJECT_RATE_DOMAIN, DIGEST_CNONCE_MAX_LEN,
    DIGEST_REPLAY_CAPACITY, DIGEST_REPLAY_MAX_DYNAMIC_KEY_BYTES, DUMMY_SHA512_CRYPT,
    DigestReplayAttempt, DigestReplayCache, DigestReplayKey, DigestReplayReject,
    HashAttemptReservation, HashAttemptReservationReject, PASSWORD_PRINCIPAL_RATE_DOMAIN,
    PASSWORD_SOURCE_RATE_DOMAIN, PASSWORD_VERIFY_CONCURRENCY, PASSWORD_VERIFY_PER_SOURCE,
    PASSWORD_VERIFY_PER_USERNAME, PasswordHashAdmission, PasswordHashAdmissionOutcome,
    PasswordHashAdmissionState, PasswordHashWorkerLease, PasswordRateReservation, REALM,
    RevocationCapacityExhausted, RevocationDocument, RevocationIoPause, RevocationLockMode,
    RevocationPersistFault, RevocationSet, SHA512_CRYPT_MAX_ROUNDS, TOKEN_REVOCATION_CAPACITY,
    TOKEN_REVOKE_ADMISSION_DOMAIN, TOKEN_REVOKE_RATE_DOMAIN, TokenClaims,
    TokenRevocationCapabilities, TokenState, TokenVerifyFailure, argon2id_profile_from_phc,
    check_auth, create_nonce, digest_hex, digest_param, flock, get_auth_user,
    open_revocation_transaction_lock, revocation_failure_requires_degraded, sha512_crypt_rounds,
    to_headermap, verify_supported_password_hash, with_revocation_lock,
};
use assert_fs::TempDir;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use headers::HeaderValue;
use hyper::Method;
use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex, atomic::Ordering};
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
            allow_token_auth: true,
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
fn hash_attempts_are_reserved_atomically_and_cancellation_is_not_a_failure() {
    let limiter = Arc::new(Mutex::new(super::AuthRateLimiter::default()));
    let key = AuthRateKey::new(Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()), "alice");
    let mut reservations = Vec::new();
    for _ in 0..AUTH_RATE_FREE_FAILURES {
        reservations.push(
            HashAttemptReservation::reserve(limiter.clone(), key.clone())
                .expect("free attempts must be reservable"),
        );
    }
    assert!(matches!(
        HashAttemptReservation::reserve(limiter.clone(), key.clone()),
        Err(HashAttemptReservationReject::ConcurrentAttemptLimit)
    ));
    {
        let state = limiter.lock().unwrap();
        let state = state.entries.get(&key).unwrap();
        assert_eq!(state.failures, 0);
        assert_eq!(state.pending_hash_attempts, AUTH_RATE_FREE_FAILURES);
    }

    // 队列/准入取消只丢弃临时预留。
    // Queue/admission cancellation drops only provisional reservations.
    drop(reservations);
    assert!(limiter.lock().unwrap().entries.is_empty());
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
fn rate_capacity_never_evicts_an_unexpired_blocked_principal() {
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)).into());
    let victim = AuthRateKey::new(source, "victim");
    let now = Instant::now();
    let mut limiter = super::AuthRateLimiter::default();

    for attempt in 0..=AUTH_RATE_FREE_FAILURES {
        let outcome = limiter.failed(victim.clone(), now).unwrap();
        if attempt == AUTH_RATE_FREE_FAILURES {
            assert_eq!(outcome, Some(1));
        } else {
            assert_eq!(outcome, None);
        }
    }
    assert_eq!(limiter.retry_after(&victim, now), Some(1));

    // 中文：填满除 victim 外的全部容量，然后再插入一个攻击者键；旧实现会任意驱逐一个
    // 无 pending worker 的状态，因而 victim 最终可被持续 churn 擦除。
    // English: Fill every slot except the victim, then insert one attacker key. The former arbitrary
    // idle eviction made a blocked victim removable under sustained churn.
    for index in 0..(super::AUTH_RATE_CAPACITY - 1) {
        let key = AuthRateKey::new(source, &format!("churn-{index}"));
        assert_eq!(limiter.failed(key, now), Ok(None));
    }
    assert_eq!(limiter.entries.len(), super::AUTH_RATE_CAPACITY);
    let overflow = AuthRateKey::new(source, "capacity-overflow");
    assert_eq!(
        limiter.failed(overflow, now),
        Err(super::AuthRateStateError::Capacity)
    );
    assert_eq!(limiter.entries.len(), super::AUTH_RATE_CAPACITY);
    assert_eq!(limiter.retry_after(&victim, now), Some(1));
}

#[tokio::test]
async fn forged_bearer_subjects_share_one_invalid_source_bucket() {
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security(Some(&[b's'; 32]), Some("test-audience"), 60, None)
        .unwrap();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)).into());

    for (index, subject) in ["forged-alice", "forged-bob"].into_iter().enumerate() {
        let claims = TokenClaims {
            v: super::TOKEN_VERSION,
            sub: subject.to_string(),
            path: "file.txt".to_string(),
            aud: "test-audience".to_string(),
            iat: 1,
            exp: u64::MAX - 1,
            jti: format!("{index:032x}"),
        };
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        // 中文：`AA` 是合法的 base64url，但不可能是有效的 HMAC-SHA256 签名。
        // English: `AA` is valid base64url but cannot be a valid HMAC-SHA256 signature.
        let authorization = HeaderValue::from_str(&format!("Bearer {payload}.AA")).unwrap();
        assert!(matches!(
            auth.guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&authorization),
                request_target: "/file.txt",
                source,
                allow_token_auth: true,
            })
            .await,
            AuthDecision::Unauthorized
        ));
    }

    let invalid_key = AuthRateKey::namespaced(source, BEARER_INVALID_RATE_DOMAIN, "");
    let state = auth.auth_rate.lock().unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.entries.get(&invalid_key).unwrap().failures, 2);
    assert!(
        !state
            .entries
            .contains_key(&AuthRateKey::new(source, "forged-alice"))
    );
    assert!(
        !state
            .entries
            .contains_key(&AuthRateKey::new(source, "forged-bob"))
    );
}

#[test]
fn authentication_rate_protocol_domains_cannot_collide() {
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 17)).into());
    let keys = [
        AuthRateKey::namespaced(source, PASSWORD_SOURCE_RATE_DOMAIN, ""),
        AuthRateKey::namespaced(source, PASSWORD_PRINCIPAL_RATE_DOMAIN, "alice"),
        AuthRateKey::namespaced(source, BEARER_INVALID_RATE_DOMAIN, ""),
        AuthRateKey::namespaced(source, BEARER_SUBJECT_RATE_DOMAIN, "alice"),
        AuthRateKey::namespaced(source, TOKEN_REVOKE_RATE_DOMAIN, "alice"),
        // 中文：即使配置用户名恰好等于旧固定标签，直接用户名哈希也不能碰撞协议域。
        // English: Even a configured username equal to the old fixed label cannot collide with a
        // protocol-domain key.
        AuthRateKey::new(source, "<invalid-bearer>"),
    ];
    for left in 0..keys.len() {
        for right in (left + 1)..keys.len() {
            assert_ne!(keys[left], keys[right]);
        }
    }
}

#[tokio::test]
async fn invalid_bearer_backoff_does_not_block_a_valid_token_from_the_same_source() {
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security(Some(&[b's'; 32]), Some("test-audience"), 60, None)
        .unwrap();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)).into());
    let forged = HeaderValue::from_static("Bearer e30.AA");

    for attempt in 0..=AUTH_RATE_FREE_FAILURES {
        let decision = auth
            .guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&forged),
                request_target: "/file.txt",
                source,
                allow_token_auth: true,
            })
            .await;
        if attempt == AUTH_RATE_FREE_FAILURES {
            assert!(matches!(decision, AuthDecision::RateLimited { .. }));
        } else {
            assert!(matches!(decision, AuthDecision::Unauthorized));
        }
    }

    let token = auth.generate_token("file.txt", "alice").unwrap();
    let valid = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    assert!(matches!(
        auth.guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&valid),
            request_target: "/file.txt",
            source,
            allow_token_auth: true,
        })
        .await,
        AuthDecision::Allowed {
            source: AuthSource::Token,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_bearer_backoff_never_submits_revocation_io_but_valid_token_does() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security_with_revocation_path(
        Some(&[b's'; 32]),
        Some("test-audience"),
        60,
        Some(path),
    )
    .unwrap();
    let state = auth.token_state.as_ref().unwrap().clone();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12)).into());
    let token = auth.generate_token("file.txt", "alice").unwrap();
    let (payload, _) = token.split_once('.').unwrap();
    let forged = HeaderValue::from_str(&format!("Bearer {payload}.AA")).unwrap();

    // 中文：先建立无效来源退避，再继续发送坏 MAC；所有请求都只能做有界的内存预检，
    // 绝不能向 Tokio 阻塞池提交撤销文件任务。
    // English: Establish invalid-source backoff and keep sending a bad MAC. Every request must stop
    // after bounded in-memory preflight without submitting revocation-file work to Tokio's blocking pool.
    for _ in 0..=AUTH_RATE_FREE_FAILURES {
        let _ = auth
            .guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&forged),
                request_target: "/file.txt",
                source,
                allow_token_auth: true,
            })
            .await;
    }
    assert!(matches!(
        auth.guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&forged),
            request_target: "/file.txt",
            source,
            allow_token_auth: true,
        })
        .await,
        AuthDecision::RateLimited { .. }
    ));
    assert_eq!(state.revocation_workers_started.load(Ordering::Relaxed), 0);

    // 中文：同一来源的合法签名使用 alice 主体桶，不受无效来源桶影响，并恰好提交一次撤销查询。
    // English: A valid signature from the same source uses Alice's subject bucket, bypasses the
    // invalid-source bucket, and submits exactly one revocation lookup.
    let valid = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    assert!(matches!(
        auth.guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&valid),
            request_target: "/file.txt",
            source,
            allow_token_auth: true,
        })
        .await,
        AuthDecision::Allowed {
            source: AuthSource::Token,
            ..
        }
    ));
    assert_eq!(state.revocation_workers_started.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_token_replay_stops_submitting_io_after_subject_backoff() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security_with_revocation_path(
        Some(&[b's'; 32]),
        Some("test-audience"),
        60,
        Some(path),
    )
    .unwrap();
    let state = auth.token_state.as_ref().unwrap().clone();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)).into());
    let token = auth.generate_token("file.txt", "alice").unwrap();
    auth.revoke_token(&token, "alice", "file.txt", source)
        .await
        .unwrap();
    let authorization = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();

    // 中文：前四次可信主体重放查询撤销状态并积累失败；第五次由原子暂定预留直接建立退避，
    // 不再提交撤销 I/O。
    // English: The first four trusted-subject replays query revocation state and accumulate failures;
    // the fifth provisional reservation establishes backoff without submitting more revocation I/O.
    for attempt in 0..=AUTH_RATE_FREE_FAILURES {
        let decision = auth
            .guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&authorization),
                request_target: "/file.txt",
                source,
                allow_token_auth: true,
            })
            .await;
        if attempt == AUTH_RATE_FREE_FAILURES {
            assert!(matches!(decision, AuthDecision::RateLimited { .. }));
        } else {
            assert!(matches!(decision, AuthDecision::Unauthorized));
        }
    }
    assert_eq!(
        state.revocation_workers_started.load(Ordering::Relaxed),
        AUTH_RATE_FREE_FAILURES as usize
    );

    // 中文：后续重放在提交 spawn_blocking 前由 alice 主体桶拒绝，计数必须保持不变。
    // English: Subsequent replay is rejected by Alice's subject bucket before spawn_blocking, so
    // the worker count must remain unchanged.
    assert!(matches!(
        auth.guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&authorization),
            request_target: "/file.txt",
            source,
            allow_token_auth: true,
        })
        .await,
        AuthDecision::RateLimited { .. }
    ));
    assert_eq!(
        state.revocation_workers_started.load(Ordering::Relaxed),
        AUTH_RATE_FREE_FAILURES as usize
    );

    // 中文：Bearer 主体桶与密码协议域隔离；同来源 alice 的撤销 token 退避不能锁死正确 Basic 登录。
    // English: The bearer-subject bucket is isolated from password protocols, so revoked-token
    // backoff for Alice cannot lock out a correct Basic login from the same source.
    let basic = HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0");
    assert!(matches!(
        auth.guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&basic),
            request_target: "/file.txt",
            source,
            allow_token_auth: true,
        })
        .await,
        AuthDecision::Allowed {
            source: AuthSource::Password,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_revocation_burst_is_bounded_and_cancelled_requests_keep_worker_leases() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security_with_revocation_path(
        Some(&[b's'; 32]),
        Some("test-audience"),
        60,
        Some(path),
    )
    .unwrap();
    let state = auth.token_state.as_ref().unwrap().clone();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 14)).into());
    let token = auth.generate_token("file.txt", "alice").unwrap();
    auth.revoke_token(&token, "alice", "file.txt", source)
        .await
        .unwrap();
    let authorization = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    let rate_key = AuthRateKey::namespaced(source, BEARER_SUBJECT_RATE_DOMAIN, "alice");

    // 中文：外部持有独占事务锁，使真实撤销 worker 确定性停在 flock；这模拟慢磁盘/锁竞争，
    // 不依赖 sleep 推断并发状态。
    // English: Hold the transaction lock exclusively so real revocation workers deterministically
    // stop in flock, modeling slow storage/lock contention without sleep-based timing assumptions.
    let backend = state.revocation_backend.as_ref().unwrap();
    let competing_lock = open_revocation_transaction_lock(backend).unwrap();
    flock(&competing_lock, super::FlockOperation::LockExclusive).unwrap();

    let first_auth = auth.clone();
    let first_authorization = authorization.clone();
    let first = tokio::spawn(async move {
        first_auth
            .guard(AuthRequest {
                path: "file.txt",
                method: &Method::GET,
                authorization_method: &Method::GET,
                authorization: Some(&first_authorization),
                request_target: "/file.txt",
                source,
                allow_token_auth: true,
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.revocation_workers_started.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first revocation worker did not start");

    // 中文：取消 HTTP future 只能分离 spawn_blocking，不能提前释放 worker 持有的三层资源。
    // English: Cancelling the HTTP future only detaches spawn_blocking; it cannot release the
    // worker-owned semaphore, keyed admission guard, or provisional failure reservation early.
    first.abort();
    let _ = first.await;
    {
        let admission = auth.password_hash_admission.state.lock().unwrap();
        assert_eq!((admission.in_flight, admission.active), (1, 1));
    }
    {
        let limiter = auth.auth_rate.lock().unwrap();
        let failure = limiter.entries.get(&rate_key).unwrap();
        assert_eq!((failure.failures, failure.pending_hash_attempts), (0, 1));
    }
    assert_eq!(
        auth.password_hash_admission
            .verify_limit
            .available_permits(),
        PASSWORD_VERIFY_CONCURRENCY - 1
    );

    let mut burst = Vec::new();
    for _ in 0..16 {
        let request_auth = auth.clone();
        let request_authorization = authorization.clone();
        burst.push(tokio::spawn(async move {
            request_auth
                .guard(AuthRequest {
                    path: "file.txt",
                    method: &Method::GET,
                    authorization_method: &Method::GET,
                    authorization: Some(&request_authorization),
                    request_target: "/file.txt",
                    source,
                    allow_token_auth: true,
                })
                .await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let active = auth.password_hash_admission.state.lock().unwrap().active;
            if state.revocation_workers_started.load(Ordering::Relaxed) == 2 && active == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded second revocation worker did not start");
    assert_eq!(
        state.revocation_workers_started.load(Ordering::Relaxed),
        PASSWORD_VERIFY_PER_SOURCE
    );
    {
        let admission = auth.password_hash_admission.state.lock().unwrap();
        assert_eq!(
            (admission.in_flight, admission.active),
            (PASSWORD_VERIFY_PER_SOURCE, PASSWORD_VERIFY_PER_SOURCE)
        );
    }

    // 中文：取消整个突发后两个已提交 worker 仍占资源；其余 future 的预留均由 Drop 回收。
    // English: Cancelling the burst leaves both submitted workers owning resources while every
    // not-submitted future returns its provisional reservation through Drop.
    for task in &burst {
        task.abort();
    }
    for task in burst {
        let _ = task.await;
    }
    assert_eq!(
        auth.password_hash_admission.state.lock().unwrap().active,
        PASSWORD_VERIFY_PER_SOURCE
    );
    assert_eq!(
        auth.auth_rate
            .lock()
            .unwrap()
            .entries
            .get(&rate_key)
            .unwrap()
            .pending_hash_attempts,
        PASSWORD_VERIFY_PER_SOURCE as u32
    );

    flock(&competing_lock, super::FlockOperation::Unlock).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let admission_empty = {
                let admission = auth.password_hash_admission.state.lock().unwrap();
                admission.in_flight == 0 && admission.active == 0
            };
            let no_pending = auth
                .auth_rate
                .lock()
                .unwrap()
                .entries
                .get(&rate_key)
                .is_none_or(|failure| failure.pending_hash_attempts == 0);
            if admission_empty && no_pending {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached revocation workers did not release their leases");
    assert_eq!(
        auth.password_hash_admission
            .verify_limit
            .available_permits(),
        PASSWORD_VERIFY_CONCURRENCY
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_revoke_writes_are_bounded_idempotent_and_own_leases_after_cancellation() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security_with_revocation_path(
        Some(&[b's'; 32]),
        Some("test-audience"),
        60,
        Some(path.clone()),
    )
    .unwrap();
    let state = auth.token_state.as_ref().unwrap().clone();
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 15)).into());
    let rate_key = AuthRateKey::namespaced(source, TOKEN_REVOKE_RATE_DOMAIN, "alice");
    let token = auth.generate_token("file.txt", "alice").unwrap();
    let backend = state.revocation_backend.as_ref().unwrap();
    let competing_lock = open_revocation_transaction_lock(backend).unwrap();
    flock(&competing_lock, super::FlockOperation::LockExclusive).unwrap();

    let first_auth = auth.clone();
    let first_token = token.clone();
    let first = tokio::spawn(async move {
        first_auth
            .revoke_token(&first_token, "alice", "file.txt", source)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while state
            .revocation_mutation_workers_started
            .load(Ordering::Relaxed)
            != 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first revocation mutation worker did not start");
    first.abort();
    let _ = first.await;
    assert_eq!(auth.password_hash_admission.state.lock().unwrap().active, 1);
    assert_eq!(
        auth.auth_rate
            .lock()
            .unwrap()
            .entries
            .get(&rate_key)
            .unwrap()
            .pending_hash_attempts,
        1
    );

    let mut burst = Vec::new();
    for _ in 0..8 {
        let request_auth = auth.clone();
        let request_token = token.clone();
        burst.push(tokio::spawn(async move {
            request_auth
                .revoke_token(&request_token, "alice", "file.txt", source)
                .await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let active = auth.password_hash_admission.state.lock().unwrap().active;
            if state
                .revocation_mutation_workers_started
                .load(Ordering::Relaxed)
                == PASSWORD_VERIFY_PER_SOURCE
                && active == PASSWORD_VERIFY_PER_SOURCE
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("bounded second revocation mutation worker did not start");
    for task in &burst {
        task.abort();
    }
    for task in burst {
        let _ = task.await;
    }
    assert_eq!(
        state
            .revocation_mutation_workers_started
            .load(Ordering::Relaxed),
        PASSWORD_VERIFY_PER_SOURCE
    );
    assert_eq!(
        auth.password_hash_admission.state.lock().unwrap().active,
        PASSWORD_VERIFY_PER_SOURCE
    );
    assert_eq!(
        auth.auth_rate
            .lock()
            .unwrap()
            .entries
            .get(&rate_key)
            .unwrap()
            .pending_hash_attempts,
        PASSWORD_VERIFY_PER_SOURCE as u32
    );

    // 中文：释放锁后两个重复写请求完成；第二个必须命中锁内幂等路径，只产生一次新 generation。
    // English: After unlock both duplicate writes finish; the second must take the under-lock
    // idempotent path, producing only one new generation.
    flock(&competing_lock, super::FlockOperation::Unlock).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let admission_empty = {
                let admission = auth.password_hash_admission.state.lock().unwrap();
                admission.in_flight == 0 && admission.active == 0
            };
            let no_pending = auth
                .auth_rate
                .lock()
                .unwrap()
                .entries
                .get(&rate_key)
                .is_none_or(|failure| failure.pending_hash_attempts == 0);
            if admission_empty && no_pending {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached revocation mutation workers did not release their leases");
    let document: RevocationDocument = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(document.generation, Some(2));
    assert_eq!(document.revoked.len(), 1);
    assert_eq!(
        auth.password_hash_admission
            .verify_limit
            .available_permits(),
        PASSWORD_VERIFY_CONCURRENCY
    );
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
                allow_token_auth: true,
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
        allow_token_auth: true,
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
                allow_token_auth: true,
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
            allow_token_auth: true,
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
                    allow_token_auth: true,
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
                allow_token_auth: true,
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
                allow_token_auth: true,
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
fn expensive_auth_subject_slots_are_protocol_domain_separated() {
    let admission = test_admission(8, 8, 8, PASSWORD_VERIFY_PER_USERNAME);
    let mut bearer_guards = Vec::new();
    for octet in 1..=PASSWORD_VERIFY_PER_USERNAME {
        let source = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet as u8)).into());
        bearer_guards.push(
            admission
                .try_reserve_namespaced(source, BEARER_REVOCATION_ADMISSION_DOMAIN, "alice")
                .unwrap(),
        );
    }
    let other_source = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)).into());
    assert!(matches!(
        admission.try_reserve_namespaced(other_source, BEARER_REVOCATION_ADMISSION_DOMAIN, "alice"),
        Err(PasswordHashAdmissionOutcome::UsernameLimit)
    ));

    // 中文：Bearer 撤销查询占满 alice 的主体槽后，密码哈希和撤销写仍拥有各自的主体域；
    // 全局/来源容量仍由同一个 admission 状态共享。
    // English: Saturating Alice's bearer-revocation subject slots does not consume Alice's password
    // or mutation domains, while global/source capacity remains shared by the same admission state.
    let password_guard = admission.try_reserve(other_source, "alice").unwrap();
    let mutation_guard = admission
        .try_reserve_namespaced(other_source, TOKEN_REVOKE_ADMISSION_DOMAIN, "alice")
        .unwrap();
    assert_eq!(admission.state.lock().unwrap().in_flight, 5);
    drop((password_guard, mutation_guard, bearer_guards));
    assert_eq!(admission.state.lock().unwrap().in_flight, 0);
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
        allow_token_auth: true,
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
    assert!(!auth.auth_succeeded(&AuthRateKey::new(
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        "alice"
    )));

    let authorization = HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0");
    let decision = ready_now(auth.guard(AuthRequest {
        path: "index.html",
        method: &Method::GET,
        authorization_method: &Method::GET,
        authorization: Some(&authorization),
        request_target: "/index.html",
        source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        allow_token_auth: true,
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

#[test]
fn options_and_bearer_auth_remain_ready_when_every_hash_slot_is_occupied() {
    let maximum = synthetic_sha512_hash(20_000);
    let rule = format!("alice:{maximum}@/:rw");
    let mut auth = AccessControl::new(&[&rule]).unwrap();
    auth.configure_security(Some(&[b's'; 32]), Some("test-audience"), 60, None)
        .unwrap();
    let _all_hash_slots = auth
        .password_hash_admission
        .verify_limit
        .clone()
        .try_acquire_many_owned(PASSWORD_VERIFY_CONCURRENCY as u32)
        .unwrap();

    let options = ready_now(auth.guard(AuthRequest {
        path: "index.html",
        method: &Method::OPTIONS,
        authorization_method: &Method::OPTIONS,
        authorization: None,
        request_target: "/index.html",
        source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        allow_token_auth: true,
    }));
    assert!(matches!(
        options,
        AuthDecision::Allowed {
            source: AuthSource::Anonymous,
            ..
        }
    ));

    let token = auth.generate_token("index.html", "alice").unwrap();
    let authorization = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    let bearer = ready_now(auth.guard(AuthRequest {
        path: "index.html",
        method: &Method::GET,
        authorization_method: &Method::GET,
        authorization: Some(&authorization),
        request_target: "/index.html",
        source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        allow_token_auth: true,
    }));
    assert!(matches!(
        bearer,
        AuthDecision::Allowed {
            source: AuthSource::Token,
            ..
        }
    ));
}

#[test]
fn revocation_expiry_is_incremental_and_handles_replacement() {
    let mut entries = HashMap::new();
    entries.insert("already-revoked".to_string(), 10);
    entries.insert("still-active".to_string(), 30);
    let mut revoked = RevocationSet::new(entries);

    assert!(revoked.contains("already-revoked", 9));
    assert!(!revoked.contains("already-revoked", 10));
    assert!(revoked.contains("still-active", 10));

    revoked.insert("replace-me".to_string(), 20);
    revoked.insert("replace-me".to_string(), 40);
    revoked.prune(20);
    assert!(revoked.entries.contains_key("replace-me"));
    revoked.prune(40);
    assert!(!revoked.entries.contains_key("replace-me"));

    let heap_len = revoked.expirations.len();
    revoked.insert("same-token".to_string(), 50);
    revoked.insert("same-token".to_string(), 50);
    assert_eq!(revoked.expirations.len(), heap_len + 1);
}

fn persistent_token_state(path: &Path) -> TokenState {
    TokenState::new(
        Some(&[b's'; 32]),
        Some("revocation-test"),
        60,
        Some(path.to_path_buf()),
    )
    .unwrap()
}

#[test]
fn persistent_revocation_requires_expensive_auth_slots_plus_one_filesystem_worker() {
    let mut ephemeral = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    ephemeral
        .configure_security(Some(&[b's'; 32]), Some("test-audience"), 60, None)
        .unwrap();
    assert_eq!(ephemeral.minimum_blocking_threads(), 1);

    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut persistent = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    persistent
        .configure_security_with_revocation_path(
            Some(&[b's'; 32]),
            Some("test-audience"),
            60,
            Some(path),
        )
        .unwrap();
    assert_eq!(
        persistent.minimum_blocking_threads(),
        PASSWORD_VERIFY_CONCURRENCY as u64 + 1
    );
}

#[test]
fn duplicate_persistent_revocation_is_idempotent_without_generation_or_inode_change() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let state = persistent_token_state(&path);
    let jti = "81000000000000000000000000000000";
    state.revoke(jti.to_string(), 1_000, 100).unwrap();
    let first_document: RevocationDocument =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let first_metadata = fs::metadata(&path).unwrap();

    // 中文：相同或更短 expiry 已被现有记录覆盖，必须只走锁内幂等快路径。
    // English: Equal or shorter expiry is already covered and must take the under-lock idempotent path.
    state.revoke(jti.to_string(), 1_000, 100).unwrap();
    state.revoke(jti.to_string(), 999, 100).unwrap();
    let duplicate_document: RevocationDocument =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let duplicate_metadata = fs::metadata(&path).unwrap();
    assert_eq!(duplicate_document.generation, first_document.generation);
    assert_eq!(duplicate_metadata.ino(), first_metadata.ino());
    assert_eq!(duplicate_document.revoked.get(jti), Some(&1_000));

    // 中文：只有延长撤销窗口才发布新 generation/inode。
    // English: Extending the revocation window is the case that publishes a new generation/inode.
    state.revoke(jti.to_string(), 1_001, 100).unwrap();
    let extended_document: RevocationDocument =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let extended_metadata = fs::metadata(&path).unwrap();
    assert_eq!(
        extended_document.generation,
        first_document.generation.map(|generation| generation + 1)
    );
    assert_ne!(extended_metadata.ino(), first_metadata.ino());
    assert_eq!(extended_document.revoked.get(jti), Some(&1_001));
}

#[test]
fn revocation_backend_uses_captured_parent_after_namespace_replacement() {
    let temp = TempDir::new().unwrap();
    let configured_parent = temp.path().join("configured");
    fs::create_dir(&configured_parent).unwrap();
    let configured_state = configured_parent.join("revocations.json");
    let capabilities = TokenRevocationCapabilities::capture(&configured_state).unwrap();

    let pinned_parent = temp.path().join("captured-parent");
    fs::rename(&configured_parent, &pinned_parent).unwrap();
    fs::create_dir(&configured_parent).unwrap();

    let state = TokenState::new_with_capabilities(
        Some(&[b's'; 32]),
        Some("revocation-test"),
        60,
        Some(capabilities.clone()),
    )
    .unwrap();
    let finalized = capabilities.with_current_expectations().unwrap();
    state
        .verify_revocation_backend_binding(Some(&finalized))
        .unwrap();

    assert!(pinned_parent.join("revocations.json").is_file());
    assert!(pinned_parent.join("revocations.json.lock").is_file());
    assert_eq!(fs::read_dir(&configured_parent).unwrap().count(), 0);

    let jti = "90000000000000000000000000000000";
    state.revoke(jti.to_string(), u64::MAX - 1, 100).unwrap();
    assert!(state.is_revoked(jti, 100).unwrap());
    let persisted: serde_json::Value =
        serde_json::from_slice(&fs::read(pinned_parent.join("revocations.json")).unwrap()).unwrap();
    assert!(persisted["revoked"].get(jti).is_some());
    assert_eq!(fs::read_dir(&configured_parent).unwrap().count(), 0);
}

#[test]
fn startup_binding_accepts_newer_state_inode_and_loads_its_generation() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let capabilities = TokenRevocationCapabilities::capture(&path).unwrap();
    let first = TokenState::new_with_capabilities(
        Some(&[b's'; 32]),
        Some("revocation-test"),
        60,
        Some(capabilities.clone()),
    )
    .unwrap();
    // 模拟 config 在另一实例发布新状态 inode 前一刻捕获最终输出。
    // Model config's final output capture immediately before another instance publishes a new state inode.
    let stale_final_view = capabilities.with_current_expectations().unwrap();

    let second = persistent_token_state(&path);
    let jti = "91000000000000000000000000000000";
    second.revoke(jti.to_string(), u64::MAX - 1, 100).unwrap();

    first
        .verify_revocation_backend_binding(Some(&stale_final_view))
        .unwrap();
    let cached = first.revocations.lock().unwrap();
    assert_eq!(cached.generation, 2);
    assert_eq!(cached.revocations.entries.get(jti), Some(&(u64::MAX - 1)));
}

#[test]
fn absent_lock_transition_binds_trusted_competing_inode() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let capabilities = TokenRevocationCapabilities::capture(&path).unwrap();
    let lock_path = sibling_lock_path(&path);
    fs::write(&lock_path, b"").unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();

    let state = TokenState::new_with_capabilities(
        Some(&[b's'; 32]),
        Some("revocation-test"),
        60,
        Some(capabilities.clone()),
    )
    .unwrap();
    let finalized = capabilities.with_current_expectations().unwrap();
    state
        .verify_revocation_backend_binding(Some(&finalized))
        .unwrap();
    assert_eq!(
        finalized.lock().expected_object(),
        Some(state.revocation_backend.as_ref().unwrap().lock_identity)
    );
}

#[test]
fn preexisting_lock_must_keep_exact_inode_until_backend_binding() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let lock_path = sibling_lock_path(&path);
    fs::write(&lock_path, b"").unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    let capabilities = TokenRevocationCapabilities::capture(&path).unwrap();

    let replacement = temp.path().join("replacement.lock");
    fs::write(&replacement, b"").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(replacement, &lock_path).unwrap();

    assert!(
        TokenState::new_with_capabilities(
            Some(&[b's'; 32]),
            Some("revocation-test"),
            60,
            Some(capabilities),
        )
        .is_err()
    );
}

fn revocation_test_claims(jti: &str) -> TokenClaims {
    TokenClaims {
        v: super::TOKEN_VERSION,
        sub: "alice".to_string(),
        path: "file.txt".to_string(),
        aud: "revocation-test".to_string(),
        iat: 1,
        exp: u64::MAX - 1,
        jti: jti.to_string(),
    }
}

fn sibling_lock_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");
    name.into()
}

#[test]
fn revocation_creation_under_extreme_umask_child() {
    if std::env::var_os("RAM_REVOCATION_UMASK_CHILD").is_none() {
        return;
    }
    let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o777));
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let state = persistent_token_state(&path);
    state
        .revoke(
            "f0000000000000000000000000000000".to_string(),
            u64::MAX - 1,
            100,
        )
        .unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        fs::metadata(sibling_lock_path(&path)).unwrap().mode() & 0o7777,
        0o600
    );
    rustix::process::umask(previous);
}

#[test]
fn revocation_candidates_repair_permissions_under_extreme_umask() {
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("auth::tests::revocation_creation_under_extreme_umask_child")
        .arg("--exact")
        .arg("--nocapture")
        .env("RAM_REVOCATION_UMASK_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated umask test failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn revocations_are_immediately_visible_and_concurrent_instances_do_not_lose_updates() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let first = Arc::new(persistent_token_state(&path));
    let second = Arc::new(persistent_token_state(&path));
    let first_jti = "00000000000000000000000000000001";
    let token = first.sign(&revocation_test_claims(first_jti)).unwrap();

    assert!(second.verify(&token, 100, true).is_ok());
    first
        .revoke(first_jti.to_string(), u64::MAX - 1, 100)
        .unwrap();
    assert!(matches!(
        second.verify(&token, 100, true),
        Err(TokenVerifyFailure::Invalid(_))
    ));

    let barrier = Arc::new(Barrier::new(3));
    let worker_a = {
        let state = first.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            state.revoke(
                "00000000000000000000000000000002".to_string(),
                u64::MAX - 1,
                100,
            )
        })
    };
    let worker_b = {
        let state = second.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            state.revoke(
                "00000000000000000000000000000003".to_string(),
                u64::MAX - 1,
                100,
            )
        })
    };
    barrier.wait();
    worker_a.join().unwrap().unwrap();
    worker_b.join().unwrap().unwrap();

    let fresh = persistent_token_state(&path);
    for jti in [
        first_jti,
        "00000000000000000000000000000002",
        "00000000000000000000000000000003",
    ] {
        assert!(fresh.is_revoked(jti, 100).unwrap());
    }
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["version"], super::REVOCATION_FORMAT_CURRENT);
    assert_eq!(document["generation"], 4);
}

#[test]
fn slow_revocation_reload_does_not_serialize_independent_verifications() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let state = Arc::new(persistent_token_state(&path));
    let publisher = persistent_token_state(&path);
    let jti = "a0000000000000000000000000000000";
    publisher
        .revoke(jti.to_string(), u64::MAX - 1, 100)
        .unwrap();

    let pause = Arc::new(RevocationIoPause::new());
    *state
        .revocation_backend
        .as_ref()
        .unwrap()
        .test_io
        .reload
        .lock()
        .unwrap() = Some(pause.clone());

    let slow = {
        let state = state.clone();
        std::thread::spawn(move || state.is_revoked(jti, 100))
    };
    pause.entered.wait();

    // 暂停工作线程持有共享 flock 并已打开变化状态，但尚未开始解析。磁盘等待和共享事务均不得
    // 保留内存缓存互斥锁。
    // The paused worker opened changed state under shared flock but has not parsed. Neither disk wait
    // nor shared transaction may retain the in-memory cache mutex.
    assert!(
        state.revocations.try_lock().is_ok(),
        "slow reload retained the in-memory revocation mutex"
    );

    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let concurrent = {
        let state = state.clone();
        std::thread::spawn(move || {
            let result = state.is_revoked(jti, 100);
            finished_tx.send(result).unwrap();
        })
    };
    let concurrent_result = finished_rx.recv_timeout(Duration::from_secs(2));
    pause.release.wait();

    assert!(slow.join().unwrap().unwrap());
    concurrent.join().unwrap();
    assert!(
        concurrent_result
            .expect("a second shared verification was serialized behind slow disk I/O")
            .unwrap(),
        "the concurrently reloaded revocation was not observed"
    );
}

#[test]
fn revocation_failure_suppresses_an_inflight_shared_authorization() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let state = Arc::new(persistent_token_state(&path));
    let publisher = persistent_token_state(&path);
    publisher
        .revoke(
            "c0000000000000000000000000000000".to_string(),
            u64::MAX - 1,
            100,
        )
        .unwrap();

    let pause = Arc::new(RevocationIoPause::new());
    *state
        .revocation_backend
        .as_ref()
        .unwrap()
        .test_io
        .after_reload
        .lock()
        .unwrap() = Some(pause.clone());

    let in_flight = {
        let state = state.clone();
        std::thread::spawn(move || state.is_revoked("d0000000000000000000000000000000", 100))
    };
    pause.entered.wait();

    // 第一校验器已解析并验证变化快照、提交缓存、计算 `false`、释放缓存互斥锁，且仍在共享
    // flock 下暂停。此时移除已发布名称不能使完成事务失效，只会令第二个重叠校验器失败并
    // 发布全局关闭失败状态。
    // The first verifier has validated and cached the snapshot, computed false, and released the cache
    // mutex while paused under shared flock. Removing the name cannot invalidate that transaction;
    // it makes only an overlapping verifier fail and publish global fail-closed state.
    assert!(
        state.revocations.try_lock().is_ok(),
        "post-reload pause retained the in-memory revocation mutex"
    );
    fs::remove_file(&path).unwrap();
    assert!(
        state
            .is_revoked("d0000000000000000000000000000000", 100)
            .is_err(),
        "missing persistent state did not fail closed"
    );
    assert!(state.revocation_degraded.load(Ordering::Acquire));

    pause.release.wait();
    assert!(
        in_flight.join().unwrap().is_err(),
        "an in-flight verifier authorized after degraded was published"
    );
}

#[test]
fn slow_revocation_persistence_releases_cache_mutex_until_durable_commit() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let state = Arc::new(persistent_token_state(&path));
    let jti = "b0000000000000000000000000000000";
    let pause = Arc::new(RevocationIoPause::new());
    *state
        .revocation_backend
        .as_ref()
        .unwrap()
        .test_io
        .persist
        .lock()
        .unwrap() = Some(pause.clone());

    let writer = {
        let state = state.clone();
        std::thread::spawn(move || state.revoke(jti.to_string(), u64::MAX - 1, 100))
    };
    pause.entered.wait();

    // 候选已序列化并写入，但文件同步、重命名、父同步和缓存提交仍未完成。
    // The candidate is serialized and written, while file sync, rename, parent sync, and cache commit remain pending.
    assert!(
        state.revocations.try_lock().is_ok(),
        "slow persistence retained the in-memory revocation mutex"
    );
    assert_eq!(
        state
            .revocations
            .lock()
            .unwrap()
            .revocations
            .entries
            .get(jti),
        None,
        "the cache advanced before durable publication"
    );

    // 写入者仍拥有独占事务锁。独立 open-file description 无法取得令牌校验使用的共享锁，
    // 证明窗口期间没有校验器能观察旧持久快照并授权令牌。
    // The writer still owns the exclusive transaction lock. A distinct open-file description cannot
    // take the verifier's shared lock, so no verifier can authorize from the old durable snapshot.
    let backend = state.revocation_backend.as_ref().unwrap();
    let competing_lock = open_revocation_transaction_lock(backend).unwrap();
    assert_eq!(
        flock(
            &competing_lock,
            super::FlockOperation::NonBlockingLockShared,
        )
        .unwrap_err(),
        rustix::io::Errno::WOULDBLOCK,
        "a shared verification lock crossed an uncommitted revoke"
    );
    drop(competing_lock);

    let (verified_tx, verified_rx) = std::sync::mpsc::channel();
    let verifier = {
        let state = state.clone();
        std::thread::spawn(move || {
            verified_tx.send(state.is_revoked(jti, 100)).unwrap();
        })
    };
    assert!(
        verified_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "verification completed before the revoke was durably published"
    );

    pause.release.wait();
    writer.join().unwrap().unwrap();
    let verified = verified_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("verification did not resume after durable revoke")
        .unwrap();
    verifier.join().unwrap();
    assert!(
        verified,
        "the verifier did not observe the durably committed revocation"
    );
}

#[test]
fn legacy_revocation_format_is_read_and_upgraded_but_future_versions_are_rejected() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let legacy_jti = "10000000000000000000000000000000";
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "version": super::REVOCATION_FORMAT_V1,
            "revoked": { (legacy_jti): u64::MAX - 1 }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let state = persistent_token_state(&path);
    assert!(state.is_revoked(legacy_jti, 100).unwrap());
    state
        .revoke(
            "20000000000000000000000000000000".to_string(),
            u64::MAX - 1,
            100,
        )
        .unwrap();
    let upgraded: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(upgraded["version"], super::REVOCATION_FORMAT_CURRENT);
    assert_eq!(upgraded["generation"], 1);

    let future = temp.path().join("future.json");
    fs::write(
        &future,
        serde_json::to_vec(&serde_json::json!({
            "version": super::REVOCATION_FORMAT_CURRENT + 1,
            "generation": 1,
            "revoked": {}
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(TokenState::new(Some(&[b's'; 32]), Some("revocation-test"), 60, Some(future)).is_err());

    let unknown_field = temp.path().join("unknown-field.json");
    fs::write(
        &unknown_field,
        serde_json::to_vec(&serde_json::json!({
            "version": super::REVOCATION_FORMAT_CURRENT,
            "generation": 1,
            "revoked": {},
            "silently_ignored": true
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(
        TokenState::new(
            Some(&[b's'; 32]),
            Some("revocation-test"),
            60,
            Some(unknown_field)
        )
        .is_err()
    );
}

#[test]
fn missing_corrupt_partial_stale_and_replaced_lock_state_fail_closed() {
    // 初始化后缺失。
    // Missing after initialization.
    let missing_dir = TempDir::new().unwrap();
    let missing_path = missing_dir.path().join("revocations.json");
    let missing = persistent_token_state(&missing_path);
    fs::remove_file(&missing_path).unwrap();
    assert!(
        missing
            .is_revoked("00000000000000000000000000000000", 100)
            .is_err()
    );
    assert!(missing.revocation_degraded.load(Ordering::Acquire));

    // 部分/损坏的原地状态，包括 fstat 后读取路径。
    // Partial/corrupt in-place state, including the read-after-fstat path.
    let corrupt_dir = TempDir::new().unwrap();
    let corrupt_path = corrupt_dir.path().join("revocations.json");
    let corrupt = persistent_token_state(&corrupt_path);
    fs::write(&corrupt_path, b"{\"version\":2,").unwrap();
    assert!(
        corrupt
            .is_revoked("00000000000000000000000000000000", 100)
            .is_err()
    );
    assert!(corrupt.revocation_degraded.load(Ordering::Acquire));

    // 过期原子回滚具有新 inode 但世代不递增，因此不能替换更新缓存快照。
    // A stale atomic rollback has a new inode but a non-increasing generation and cannot replace newer cache.
    let stale_dir = TempDir::new().unwrap();
    let stale_path = stale_dir.path().join("revocations.json");
    let stale = persistent_token_state(&stale_path);
    let generation_one = fs::read(&stale_path).unwrap();
    stale
        .revoke(
            "30000000000000000000000000000000".to_string(),
            u64::MAX - 1,
            100,
        )
        .unwrap();
    let replacement = stale_dir.path().join("rollback.tmp");
    fs::write(&replacement, generation_one).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&replacement, &stale_path).unwrap();
    assert!(
        stale
            .is_revoked("30000000000000000000000000000000", 100)
            .is_err()
    );

    // 数值上更新的世代也必须保留此实例已观察到的每个未过期撤销。
    // A numerically newer generation must preserve every unexpired revocation already observed.
    let dropped_dir = TempDir::new().unwrap();
    let dropped_path = dropped_dir.path().join("revocations.json");
    let dropped = persistent_token_state(&dropped_path);
    dropped
        .revoke(
            "40000000000000000000000000000000".to_string(),
            u64::MAX - 1,
            100,
        )
        .unwrap();
    let higher = dropped_dir.path().join("higher.tmp");
    fs::write(
        &higher,
        serde_json::to_vec(&serde_json::json!({
            "version": super::REVOCATION_FORMAT_CURRENT,
            "generation": 3,
            "revoked": {}
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&higher, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&higher, &dropped_path).unwrap();
    assert!(
        dropped
            .is_revoked("40000000000000000000000000000000", 100)
            .is_err()
    );

    // 替换稳定锁路径不得悄然把实例分裂到两个锁 inode。
    // Replacing the stable lock path cannot split instances across two lock inodes unnoticed.
    let lock_dir = TempDir::new().unwrap();
    let lock_state_path = lock_dir.path().join("revocations.json");
    let lock_state = persistent_token_state(&lock_state_path);
    let lock_replacement = lock_dir.path().join("replacement.lock");
    fs::write(&lock_replacement, b"").unwrap();
    fs::set_permissions(&lock_replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&lock_replacement, sibling_lock_path(&lock_state_path)).unwrap();
    assert!(
        lock_state
            .is_revoked("00000000000000000000000000000000", 100)
            .is_err()
    );
    assert!(lock_state.revocation_degraded.load(Ordering::Acquire));
}

#[test]
fn replaced_lock_identity_overrides_capacity_error() {
    let temp = TempDir::new().unwrap();
    let state_path = temp.path().join("revocations.json");
    let state = persistent_token_state(&state_path);
    let backend = state.revocation_backend.as_ref().unwrap();

    let error = with_revocation_lock(backend, RevocationLockMode::Exclusive, || {
        let replacement = temp.path().join("replacement.lock");
        fs::write(&replacement, b"").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, sibling_lock_path(&state_path)).unwrap();
        Err::<(), _>(anyhow::Error::new(RevocationCapacityExhausted))
    })
    .unwrap_err();

    assert!(
        error
            .downcast_ref::<RevocationCapacityExhausted>()
            .is_none()
    );
    assert!(revocation_failure_requires_degraded(&error));
    let integrity_error = format!("{error:#}");
    assert!(
        integrity_error.contains("held token revocation transaction lock is no longer trusted")
            || integrity_error.contains("lock path no longer names the trusted held inode"),
        "unexpected integrity error: {integrity_error}"
    );
}

#[test]
fn every_persistence_fault_cut_point_leaves_no_temp_and_enters_degraded_mode() {
    let cases = [
        (RevocationPersistFault::BeforeWrite, false),
        (RevocationPersistFault::PartialWrite, false),
        (RevocationPersistFault::FileSync, false),
        (RevocationPersistFault::Rename, false),
        (RevocationPersistFault::AfterRename, true),
        (RevocationPersistFault::ParentSync, true),
        (RevocationPersistFault::AfterParentSync, true),
    ];
    for (index, (fault, published)) in cases.into_iter().enumerate() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("revocations.json");
        let state = persistent_token_state(&path);
        let jti = format!("{index:032x}");
        assert!(
            state
                .revoke_with_fault(jti.clone(), u64::MAX - 1, 100, fault)
                .is_err()
        );
        assert!(state.revocation_degraded.load(Ordering::Acquire));
        assert!(state.is_revoked(&jti, 100).is_err());

        let fresh = persistent_token_state(&path);
        assert_eq!(fresh.is_revoked(&jti, 100).unwrap(), published);
        let temp_candidates = fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(temp_candidates, 0, "fault={fault:?}");
    }
}

#[test]
fn maximum_revocation_table_keeps_lookup_incremental() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut entries = HashMap::with_capacity(TOKEN_REVOCATION_CAPACITY);
    for index in 0..TOKEN_REVOCATION_CAPACITY {
        entries.insert(format!("{index:032x}"), u64::MAX - 1);
    }
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "version": super::REVOCATION_FORMAT_CURRENT,
            "generation": 1,
            "revoked": entries
        }))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let state = persistent_token_state(&path);
    let mut cached = state.revocations.lock().unwrap();
    assert_eq!(cached.revocations.entries.len(), TOKEN_REVOCATION_CAPACITY);
    // 数千次查找使意外全表扫描成本高到不可接受，同时保持确定性且不依赖时钟。
    // Thousands of lookups make an accidental full-map scan prohibitively expensive while staying deterministic.
    for _ in 0..8_192 {
        assert!(
            cached
                .revocations
                .contains("00000000000000000000000000000001", 100)
        );
    }
    assert_eq!(cached.revocations.entries.len(), TOKEN_REVOCATION_CAPACITY);
    drop(cached);
    let error = state
        .revoke(
            "ffffffffffffffffffffffffffffffff".to_string(),
            u64::MAX - 1,
            100,
        )
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<super::RevocationCapacityExhausted>()
            .is_some()
    );
    assert!(!state.revocation_degraded.load(Ordering::Acquire));
    assert!(
        state
            .is_revoked("00000000000000000000000000000001", 100)
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_bearer_infrastructure_failure_is_503_without_counting_auth_failure() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("revocations.json");
    let mut auth = AccessControl::new(&["alice:secret@/:rw"]).unwrap();
    auth.configure_security_with_revocation_path(
        Some(&[b's'; 32]),
        Some("revocation-test"),
        60,
        Some(path.clone()),
    )
    .unwrap();
    let token = auth.generate_token("file.txt", "alice").unwrap();
    fs::write(&path, b"partial").unwrap();
    let authorization = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
    let decision = auth
        .guard(AuthRequest {
            path: "file.txt",
            method: &Method::GET,
            authorization_method: &Method::GET,
            authorization: Some(&authorization),
            request_target: "/file.txt",
            source: Some(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
            allow_token_auth: true,
        })
        .await;
    assert!(matches!(decision, AuthDecision::ServiceUnavailable { .. }));
    assert!(auth.auth_rate.lock().unwrap().entries.is_empty());
}

fn replay_attempt(user: &str, nc: u32) -> DigestReplayAttempt {
    DigestReplayAttempt {
        key: DigestReplayKey {
            nonce: [b'n'; 34],
            user: Arc::from(user),
            cnonce: Arc::from([b'c']),
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
