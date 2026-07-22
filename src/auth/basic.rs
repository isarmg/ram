//! Basic 凭据与有界密码哈希策略校验。比较不按首个差异短路；只有资源参数位于策略内的
//! SHA-512-crypt/Argon2id 才进入阻塞验证器；用户名和规则成为长期状态键前均受限并校验。
//!
//! Basic credentials and bounded password-hash policy validation.
//!
//! Security invariants:
//! - password comparisons do not short-circuit on the first differing byte;
//! - only explicitly supported SHA-512-crypt and Argon2id profiles enter the
//!   blocking verifier, and their resource costs are rejected outside policy;
//! - usernames and configuration rules are bounded and validated before they
//!   become keys in long-lived authentication state.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Argon2idProfile {
    pub(super) m_cost_kib: u32,
    pub(super) t_cost: u32,
    pub(super) p_cost: u32,
    pub(super) output_len: usize,
}

/// 凭据比较必须与内容无关地耗时（常数时间）：普通的 `==` 在第一个
/// 不同字节处就返回，耗时差异会向攻击者泄露"猜对了几位"。
/// 先用域分离的固定键计算固定长度 HMAC，再使用 HMAC 库的常数时间
/// `verify_slice`；此处只需要常数时间比较，不依赖该键提供真实性。
/// Compare credentials without content-dependent early return by hashing both
/// sides to fixed-length HMAC values and using constant-time `verify_slice`.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    const COMPARISON_KEY: &[u8] = b"ram.constant-time-comparison.v1";
    let mut expected = token_mac(COMPARISON_KEY);
    expected.update(a);
    let expected = expected.finalize().into_bytes();
    let mut actual = token_mac(COMPARISON_KEY);
    actual.update(b);
    actual.verify_slice(&expected).is_ok()
}

/// 把规则按**第一个** `@/` 切成（账号, 路径）两段——
/// 用 `@/` 而不是 `@` 定位，密码里就允许出现 `@` 字符。
/// Split at the first `@/`, not a bare `@`, so passwords may contain `@`.
pub(super) fn split_account_paths(s: &str) -> Option<(&str, &str)> {
    let i = s.find("@/")?;
    Some((&s[0..i], &s[i + 1..]))
}

pub(super) fn is_supported_password_hash(value: &str) -> bool {
    value.starts_with("$6$") || value.starts_with("$argon2id$")
}

pub(super) fn verify_supported_password_hash(password: &[u8], hash: &str) -> bool {
    if hash.starts_with("$6$") {
        return sha_crypt::ShaCrypt::SHA512
            .verify_password(password, hash)
            .is_ok();
    }
    if hash.starts_with("$argon2id$") {
        let Ok(parsed) = Argon2PasswordHash::new(hash) else {
            return false;
        };
        return Argon2::default().verify_password(password, &parsed).is_ok();
    }
    false
}

pub(super) fn argon2id_profile_from_phc(hash: &str) -> Result<Argon2idProfile> {
    let parsed =
        Argon2PasswordHash::new(hash).map_err(|_| anyhow!("invalid Argon2id PHC encoding"))?;
    if parsed.algorithm.as_str() != "argon2id" {
        bail!("expected Argon2id algorithm identifier");
    }
    if parsed.version != Some(ARGON2_VERSION) {
        bail!("Argon2id version must be explicitly v={ARGON2_VERSION}");
    }
    let parameter_names: Vec<&str> = parsed
        .params
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    if parameter_names.len() != 3
        || !["m", "t", "p"]
            .iter()
            .all(|required| parameter_names.contains(required))
    {
        bail!("Argon2id PHC must contain exactly the m, t, and p parameters");
    }
    let params = Argon2Params::try_from(&parsed)
        .map_err(|_| anyhow!("invalid Argon2id m/t/p parameters"))?;
    if !(ARGON2_M_COST_MIN_KIB..=ARGON2_M_COST_MAX_KIB).contains(&params.m_cost()) {
        bail!(
            "Argon2id m cost must be between {ARGON2_M_COST_MIN_KIB} and {ARGON2_M_COST_MAX_KIB} KiB"
        );
    }
    if !(ARGON2_T_COST_MIN..=ARGON2_T_COST_MAX).contains(&params.t_cost()) {
        bail!("Argon2id t cost must be between {ARGON2_T_COST_MIN} and {ARGON2_T_COST_MAX}");
    }
    if !(ARGON2_P_COST_MIN..=ARGON2_P_COST_MAX).contains(&params.p_cost()) {
        bail!("Argon2id p cost must be between {ARGON2_P_COST_MIN} and {ARGON2_P_COST_MAX}");
    }

    let salt = parsed
        .salt
        .ok_or_else(|| anyhow!("Argon2id PHC is missing a salt"))?;
    let mut decoded_salt = [0u8; 64];
    let salt_len = salt
        .decode_b64(&mut decoded_salt)
        .map_err(|_| anyhow!("invalid Argon2id salt encoding"))?
        .len();
    if !(ARGON2_SALT_MIN_BYTES..=ARGON2_SALT_MAX_BYTES).contains(&salt_len) {
        bail!(
            "Argon2id salt must decode to between {ARGON2_SALT_MIN_BYTES} and {ARGON2_SALT_MAX_BYTES} bytes"
        );
    }
    let output_len = parsed
        .hash
        .as_ref()
        .ok_or_else(|| anyhow!("Argon2id PHC is missing a hash output"))?
        .len();
    if !(ARGON2_OUTPUT_MIN_BYTES..=ARGON2_OUTPUT_MAX_BYTES).contains(&output_len) {
        bail!(
            "Argon2id hash output must be between {ARGON2_OUTPUT_MIN_BYTES} and {ARGON2_OUTPUT_MAX_BYTES} bytes"
        );
    }

    Ok(Argon2idProfile {
        m_cost_kib: params.m_cost(),
        t_cost: params.t_cost(),
        p_cost: params.p_cost(),
        output_len,
    })
}

pub(super) fn sha512_crypt_rounds(hash: &str) -> Result<u32> {
    let parsed = sha_crypt::PasswordHashRef::new(hash)
        .map_err(|_| anyhow!("invalid modular-crypt encoding"))?;
    if parsed.id() != "6" {
        bail!("expected SHA-512-crypt algorithm id 6");
    }
    let fields: Vec<&str> = parsed.fields().map(|field| field.as_str()).collect();
    let (rounds, salt, digest) = match fields.as_slice() {
        [salt, digest] => (sha_crypt::Params::RECOMMENDED_ROUNDS, *salt, *digest),
        [rounds, salt, digest] => {
            let rounds = rounds
                .strip_prefix("rounds=")
                .ok_or_else(|| anyhow!("unsupported SHA-512-crypt parameter"))?
                .parse::<u32>()
                .map_err(|_| anyhow!("invalid SHA-512-crypt rounds"))?;
            sha_crypt::Params::new(rounds)
                .map_err(|_| anyhow!("SHA-512-crypt rounds outside the supported range"))?;
            (rounds, *salt, *digest)
        }
        _ => bail!("invalid SHA-512-crypt field count"),
    };
    if rounds > SHA512_CRYPT_MAX_ROUNDS {
        bail!(
            "SHA-512-crypt rounds {rounds} exceed the server safety limit of {SHA512_CRYPT_MAX_ROUNDS}"
        );
    }
    if salt.is_empty() || salt.len() > 16 || digest.len() != 86 {
        bail!("invalid SHA-512-crypt salt or digest length");
    }
    Ok(rounds)
}

/// 把规则里的密码段（第一个 `:` 到 `@/` 之间）替换成 `***`，
/// 供报错消息安全地回显规则原文。没有 `:` 的规则不含密码，原样返回。
/// Replace the password span with `***` before echoing a rule in diagnostics.
pub(super) fn redact_rule(rule: &str) -> String {
    let account_end = rule.find("@/").unwrap_or(rule.len());
    match rule[..account_end].find(':') {
        Some(i) => format!("{}:***{}", &rule[..i], &rule[account_end..]),
        None => rule.to_string(),
    }
}

/// 支持在一个 `--auth` 参数里用 `|` 连接多条规则（如
/// `u1:p1@/:rw|u2:p2@/`）。难点在密码里也可能含 `|`：
/// 策略是持续拼接片段，直到遇到含 `@/` 的片段才算一条规则完结。
/// Expand `|`-joined rules while preserving `|` inside passwords by ending a rule only at a fragment containing `@/`.
pub(super) fn split_rules(rules: &[&str]) -> Result<Vec<String>> {
    let mut output = vec![];
    for rule in rules {
        let mut parts = rule.split('|').peekable();
        let mut concated_part = String::new();
        while let Some(part) = parts.next() {
            if part.contains("@/") {
                concated_part.push_str(part);
                let mut concated_part_tmp = String::new();
                std::mem::swap(&mut concated_part_tmp, &mut concated_part);
                push_bounded_auth_rule(&mut output, concated_part_tmp)?;
                continue;
            }
            concated_part.push_str(part);
            if parts.peek().is_some() {
                concated_part.push('|');
            }
        }
        if !concated_part.is_empty() {
            push_bounded_auth_rule(&mut output, concated_part)?;
        }
    }
    Ok(output)
}

fn push_bounded_auth_rule(output: &mut Vec<String>, rule: String) -> Result<()> {
    if output.len() >= AUTH_ACCOUNT_RULE_MAX_COUNT {
        bail!(
            "Authentication configuration exceeds the {AUTH_ACCOUNT_RULE_MAX_COUNT}-account-rule limit"
        );
    }
    output.push(rule);
    Ok(())
}
