//! 连接接收时只建立一次内核来源身份。只有直接 TCP 对端位于可信代理允许列表时，
//! 请求头才能把它细化为有效客户端 IP；Unix-domain 对端始终只使用 Linux
//! `SO_PEERCRED`，绝不从转发头推导。
//!
//! Kernel-derived and explicitly proxy-verified request source identities.
//! A transport peer is established once, when the connection is accepted.
//! Request headers may refine a TCP peer into an effective client IP only
//! when that direct peer belongs to the configured trusted-proxy allowlist.
//! Unix-domain peers are never header-derived: Linux `SO_PEERCRED` is the
//! complete source identity for those connections.

use anyhow::{Result, anyhow, bail};
use hyper::{HeaderMap, header::HeaderName};
use serde::{Deserialize, Deserializer};
use std::{
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

const X_FORWARDED_FOR_MAX_BYTES: usize = 4096;
const X_FORWARDED_FOR_MAX_HOPS: usize = 32;

/// 监听器建立的不可变直接对端。 / The immutable direct peer established by the listener.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum PeerIdentity {
    Tcp(SocketAddr),
    Unix { uid: u32, gid: u32, pid: u32 },
}

impl PeerIdentity {
    pub(crate) fn tcp(addr: SocketAddr) -> Self {
        Self::Tcp(addr)
    }

    pub(crate) fn unix(uid: u32, gid: u32, pid: u32) -> Self {
        Self::Unix { uid, gid, pid }
    }

    pub(crate) fn direct_source(&self) -> SourceIdentity {
        match *self {
            Self::Tcp(addr) => SourceIdentity::Tcp(addr.ip()),
            Self::Unix { uid, gid, pid } => SourceIdentity::Unix { uid, gid, pid },
        }
    }
}

/// 日志与所有按来源限流器共用的唯一已验证来源。 / The single verified source used by logging and every source-keyed limiter.
///
/// Unix 的 `gid`/`pid` 保留作审计上下文，但同一 UID 可自由 fork 且可能切换其获准的主组；
/// 因此安全相等性和哈希只使用 UID，防止换进程/组绕过按来源预算。TCP 则始终按客户端 IP。
/// Unix `gid`/`pid` remain audit context, but one UID can freely fork and may switch among its
/// permitted primary groups. Security equality and hashing therefore use only UID so process/group
/// churn cannot evade source budgets; TCP sources remain keyed by client IP.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SourceIdentity {
    Tcp(IpAddr),
    Unix { uid: u32, gid: u32, pid: u32 },
}

impl PartialEq for SourceIdentity {
    fn eq(&self, other: &Self) -> bool {
        match (*self, *other) {
            (Self::Tcp(left), Self::Tcp(right)) => left == right,
            (Self::Unix { uid: left, .. }, Self::Unix { uid: right, .. }) => left == right,
            _ => false,
        }
    }
}

impl Eq for SourceIdentity {}

impl Hash for SourceIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match *self {
            Self::Tcp(address) => {
                0_u8.hash(state);
                address.hash(state);
            }
            Self::Unix { uid, .. } => {
                1_u8.hash(state);
                uid.hash(state);
            }
        }
    }
}

impl From<IpAddr> for SourceIdentity {
    fn from(address: IpAddr) -> Self {
        Self::Tcp(address)
    }
}

impl fmt::Display for SourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(ip) => ip.fmt(formatter),
            Self::Unix { uid, gid, pid } => {
                write!(formatter, "unix:uid={uid},gid={gid},pid={pid}")
            }
        }
    }
}

/// 可信代理只能选择一种转发约定。 / Exactly one forwarding convention may be selected for trusted proxies.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ForwardedHeader {
    XForwardedFor,
    XRealIp,
}

impl FromStr for ForwardedHeader {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "x-forwarded-for" => Ok(Self::XForwardedFor),
            "x-real-ip" => Ok(Self::XRealIp),
            _ => bail!("trusted-proxy-header must be `x-forwarded-for` or `x-real-ip`"),
        }
    }
}

impl fmt::Display for ForwardedHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::XRealIp => "x-real-ip",
        })
    }
}

/// 一个规范化 IPv4 或 IPv6 网络前缀。 / One canonical IPv4 or IPv6 network prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub(crate) fn contains(self, candidate: IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                prefix_matches(&network.octets(), &candidate.octets(), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                prefix_matches(&network.octets(), &candidate.octets(), self.prefix_len)
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.is_empty() || value.trim() != value {
            bail!("trusted proxy CIDR must be non-empty and contain no surrounding whitespace");
        }
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) if !prefix.contains('/') => (address, Some(prefix)),
            Some(_) => bail!("trusted proxy CIDR contains more than one `/`"),
            None => (value, None),
        };
        let network: IpAddr = address
            .parse()
            .map_err(|_| anyhow!("invalid trusted proxy IP address `{address}`"))?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        let prefix_len = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .map_err(|_| anyhow!("invalid trusted proxy prefix length `{prefix}`"))?,
            None => maximum,
        };
        if prefix_len > maximum {
            bail!(
                "trusted proxy prefix length {prefix_len} exceeds the {maximum}-bit address size"
            );
        }
        if !address_is_canonical_network(network, prefix_len) {
            bail!("trusted proxy CIDR `{value}` has non-zero host bits");
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }
}

impl<'de> Deserialize<'de> for IpCidr {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

/// 对同一连接上的每个请求独立应用的不可变策略。 / Immutable policy applied independently to every request on a connection.
#[derive(Clone, Debug, Default)]
pub(crate) struct TrustedProxyPolicy {
    allowlist: Vec<IpCidr>,
    header: Option<ForwardedHeader>,
}

impl TrustedProxyPolicy {
    pub(crate) fn new(allowlist: Vec<IpCidr>, header: Option<ForwardedHeader>) -> Result<Self> {
        if allowlist.is_empty() && header.is_some() {
            bail!("trusted-proxy-header requires at least one trusted-proxy CIDR");
        }
        if !allowlist.is_empty() && header.is_none() {
            bail!("trusted-proxy requires an explicit trusted-proxy-header");
        }
        Ok(Self { allowlist, header })
    }

    pub(crate) fn resolve(
        &self,
        peer: &PeerIdentity,
        headers: &HeaderMap,
    ) -> Result<SourceIdentity> {
        let PeerIdentity::Tcp(peer_addr) = peer else {
            return Ok(peer.direct_source());
        };
        let Some(header) = self.header else {
            return Ok(peer.direct_source());
        };
        if !self.is_trusted(peer_addr.ip()) {
            // 中文：不可信直接对端提供的转发头既不解析、校验，也不做尺寸扫描。
            // English: Deliberately do not parse, validate, or size-check
            // attacker-supplied forwarding headers from an untrusted direct peer.
            return Ok(peer.direct_source());
        }

        let effective_ip = match header {
            ForwardedHeader::XForwardedFor => {
                self.resolve_x_forwarded_for(peer_addr.ip(), headers)?
            }
            ForwardedHeader::XRealIp => parse_x_real_ip(headers)?,
        };
        Ok(SourceIdentity::Tcp(effective_ip))
    }

    fn resolve_x_forwarded_for(&self, peer_ip: IpAddr, headers: &HeaderMap) -> Result<IpAddr> {
        let name = HeaderName::from_static("x-forwarded-for");
        let values = headers.get_all(name);
        let mut total_bytes = 0usize;
        let mut hops = Vec::new();
        for (index, value) in values.iter().enumerate() {
            total_bytes = total_bytes
                .checked_add(value.as_bytes().len())
                .and_then(|length| length.checked_add(usize::from(index != 0)))
                .ok_or_else(|| anyhow!("X-Forwarded-For length overflow"))?;
            if total_bytes > X_FORWARDED_FOR_MAX_BYTES {
                bail!("X-Forwarded-For exceeds the {X_FORWARDED_FOR_MAX_BYTES}-byte limit");
            }
            let value = value
                .to_str()
                .map_err(|_| anyhow!("X-Forwarded-For is not valid ASCII"))?;
            for hop in value.split(',') {
                if hops.len() >= X_FORWARDED_FOR_MAX_HOPS {
                    bail!("X-Forwarded-For exceeds the {X_FORWARDED_FOR_MAX_HOPS}-hop limit");
                }
                let hop = hop.trim();
                if hop.is_empty() {
                    bail!("X-Forwarded-For contains an empty hop");
                }
                let address = hop
                    .parse::<IpAddr>()
                    .map_err(|_| anyhow!("X-Forwarded-For contains an invalid IP address"))?;
                hops.push(address);
            }
        }
        if hops.is_empty() {
            bail!("trusted proxy request is missing X-Forwarded-For");
        }

        // 中文：从内核认证的直接对端向客户端方向回溯；可信代理可声明左侧一跳，
        // 第一个不可信地址即有效客户端，其左侧任何值都不能覆盖它。
        // English: Starting at the kernel-authenticated direct peer, walk
        // toward the client. A trusted proxy may name the hop to its left; the
        // first untrusted address is effective and nothing farther left can override it.
        let mut current = peer_ip;
        for hop in hops.into_iter().rev() {
            if !self.is_trusted(current) {
                break;
            }
            current = hop;
        }
        Ok(current)
    }

    fn is_trusted(&self, address: IpAddr) -> bool {
        self.allowlist
            .iter()
            .any(|network| network.contains(address))
    }
}

fn parse_x_real_ip(headers: &HeaderMap) -> Result<IpAddr> {
    let name = HeaderName::from_static("x-real-ip");
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| anyhow!("trusted proxy request is missing X-Real-IP"))?;
    if values.next().is_some() {
        bail!("X-Real-IP must occur exactly once");
    }
    if value.as_bytes().len() > X_FORWARDED_FOR_MAX_BYTES {
        bail!("X-Real-IP exceeds the 4096-byte limit");
    }
    let value = value
        .to_str()
        .map_err(|_| anyhow!("X-Real-IP is not valid ASCII"))?;
    if value.trim() != value || value.is_empty() || value.contains(',') {
        bail!("X-Real-IP must contain exactly one IP address");
    }
    value
        .parse()
        .map_err(|_| anyhow!("X-Real-IP contains an invalid IP address"))
}

fn address_is_canonical_network(address: IpAddr, prefix_len: u8) -> bool {
    match address {
        IpAddr::V4(address) => host_bits_are_zero(&address.octets(), prefix_len),
        IpAddr::V6(address) => host_bits_are_zero(&address.octets(), prefix_len),
    }
}

fn host_bits_are_zero(bytes: &[u8], prefix_len: u8) -> bool {
    let full_bytes = usize::from(prefix_len / 8);
    let partial_bits = prefix_len % 8;
    if partial_bits != 0 {
        let host_mask = (1u8 << (8 - partial_bits)) - 1;
        if bytes[full_bytes] & host_mask != 0 {
            return false;
        }
    }
    let host_start = full_bytes + usize::from(partial_bits != 0);
    bytes[host_start..].iter().all(|byte| *byte == 0)
}

fn prefix_matches(network: &[u8], candidate: &[u8], prefix_len: u8) -> bool {
    let full_bytes = usize::from(prefix_len / 8);
    let partial_bits = prefix_len % 8;
    if network[..full_bytes] != candidate[..full_bytes] {
        return false;
    }
    if partial_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - partial_bits);
    network[full_bytes] & mask == candidate[full_bytes] & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use std::{collections::HashSet, net::Ipv4Addr};

    fn tcp(address: &str) -> PeerIdentity {
        PeerIdentity::tcp(SocketAddr::new(address.parse().unwrap(), 1234))
    }

    fn policy(networks: &[&str], header: ForwardedHeader) -> TrustedProxyPolicy {
        TrustedProxyPolicy::new(
            networks
                .iter()
                .map(|network| network.parse().unwrap())
                .collect(),
            Some(header),
        )
        .unwrap()
    }

    #[test]
    fn cidr_parser_is_bounded_and_requires_a_canonical_network() {
        let v4: IpCidr = "192.0.2.0/24".parse().unwrap();
        assert!(v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99))));
        assert!(!v4.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
        assert!("192.0.2.1/24".parse::<IpCidr>().is_err());
        assert!("192.0.2.0/33".parse::<IpCidr>().is_err());

        let v6: IpCidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!("2001:db8::1/64".parse::<IpCidr>().is_err());
    }

    #[test]
    fn untrusted_peer_cannot_spoof_or_trigger_forwarded_header_errors() {
        let policy = policy(&["10.0.0.0/8"], ForwardedHeader::XForwardedFor);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(&vec![b'x'; X_FORWARDED_FOR_MAX_BYTES + 1]).unwrap(),
        );
        assert_eq!(
            policy.resolve(&tcp("192.0.2.44"), &headers).unwrap(),
            SourceIdentity::Tcp("192.0.2.44".parse().unwrap())
        );
    }

    #[test]
    fn x_forwarded_for_strips_trusted_proxies_from_right_to_left() {
        let policy = policy(
            &["10.0.0.0/8", "192.0.2.0/24"],
            ForwardedHeader::XForwardedFor,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 198.51.100.8, 192.0.2.9"),
        );
        assert_eq!(
            policy.resolve(&tcp("10.1.2.3"), &headers).unwrap(),
            SourceIdentity::Tcp("198.51.100.8".parse().unwrap())
        );
    }

    #[test]
    fn x_forwarded_for_accepts_multiple_lines_but_rejects_bad_or_excess_hops() {
        let policy = policy(&["10.0.0.0/8"], ForwardedHeader::XForwardedFor);
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));
        headers.append("x-forwarded-for", HeaderValue::from_static("10.2.3.4"));
        assert_eq!(
            policy.resolve(&tcp("10.1.2.3"), &headers).unwrap(),
            SourceIdentity::Tcp("203.0.113.1".parse().unwrap())
        );

        headers.insert("x-forwarded-for", HeaderValue::from_static("unknown"));
        assert!(policy.resolve(&tcp("10.1.2.3"), &headers).is_err());

        let too_many = std::iter::repeat_n("10.0.0.1", X_FORWARDED_FOR_MAX_HOPS + 1)
            .collect::<Vec<_>>()
            .join(",");
        headers.insert("x-forwarded-for", HeaderValue::from_str(&too_many).unwrap());
        assert!(policy.resolve(&tcp("10.1.2.3"), &headers).is_err());
    }

    #[test]
    fn x_forwarded_for_enforces_byte_boundary_minus_exact_and_plus_one() {
        let policy = policy(&["10.0.0.0/8"], ForwardedHeader::XForwardedFor);
        let make_value = |length: usize| {
            let left = "203.0.113.1,";
            let right = "198.51.100.8";
            assert!(length >= left.len() + right.len());
            HeaderValue::from_str(&format!(
                "{left}{}{right}",
                " ".repeat(length - left.len() - right.len())
            ))
            .unwrap()
        };

        for length in [X_FORWARDED_FOR_MAX_BYTES - 1, X_FORWARDED_FOR_MAX_BYTES] {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", make_value(length));
            assert_eq!(
                policy.resolve(&tcp("10.1.2.3"), &headers).unwrap(),
                SourceIdentity::Tcp("198.51.100.8".parse().unwrap())
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", make_value(X_FORWARDED_FOR_MAX_BYTES + 1));
        assert!(policy.resolve(&tcp("10.1.2.3"), &headers).is_err());
    }

    #[test]
    fn x_forwarded_for_enforces_hop_boundary_minus_exact_and_plus_one() {
        let policy = policy(&["10.0.0.0/8"], ForwardedHeader::XForwardedFor);
        for count in [X_FORWARDED_FOR_MAX_HOPS - 1, X_FORWARDED_FOR_MAX_HOPS] {
            let value = std::iter::repeat_n("198.51.100.8", count)
                .collect::<Vec<_>>()
                .join(",");
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", HeaderValue::from_str(&value).unwrap());
            assert!(policy.resolve(&tcp("10.1.2.3"), &headers).is_ok());
        }

        let value = std::iter::repeat_n("198.51.100.8", X_FORWARDED_FOR_MAX_HOPS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(&value).unwrap());
        assert!(policy.resolve(&tcp("10.1.2.3"), &headers).is_err());
    }

    #[test]
    fn x_real_ip_requires_one_strict_address_from_a_trusted_peer() {
        let policy = policy(&["10.0.0.0/8"], ForwardedHeader::XRealIp);
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.9"));
        assert_eq!(
            policy.resolve(&tcp("10.1.2.3"), &headers).unwrap(),
            SourceIdentity::Tcp("203.0.113.9".parse().unwrap())
        );
        headers.append("x-real-ip", HeaderValue::from_static("203.0.113.10"));
        assert!(policy.resolve(&tcp("10.1.2.3"), &headers).is_err());
    }

    #[test]
    fn unix_peer_identity_is_never_derived_from_headers() {
        let policy = policy(&["0.0.0.0/0"], ForwardedHeader::XForwardedFor);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        let expected = SourceIdentity::Unix {
            uid: 1000,
            gid: 100,
            pid: 42,
        };
        assert_eq!(
            policy
                .resolve(&PeerIdentity::unix(1000, 100, 42), &headers)
                .unwrap(),
            expected
        );
        assert_eq!(expected.to_string(), "unix:uid=1000,gid=100,pid=42");
    }

    #[test]
    fn unix_security_source_groups_process_and_group_churn_by_uid() {
        let first = SourceIdentity::Unix {
            uid: 1000,
            gid: 100,
            pid: 41,
        };
        let same_principal = SourceIdentity::Unix {
            uid: 1000,
            gid: 200,
            pid: 9001,
        };
        let different_principal = SourceIdentity::Unix {
            uid: 1001,
            gid: 100,
            pid: 41,
        };

        assert_eq!(first, same_principal);
        assert_ne!(first, different_principal);
        let sources = HashSet::from([first, same_principal, different_principal]);
        assert_eq!(sources.len(), 2);
        // 中文：Display 仍保留内核凭据，限流聚合不能牺牲审计上下文。
        // English: Display retains kernel credentials so limiter grouping does not erase audit context.
        assert_eq!(same_principal.to_string(), "unix:uid=1000,gid=200,pid=9001");
    }

    #[test]
    fn proxy_policy_requires_allowlist_and_header_together() {
        assert!(TrustedProxyPolicy::new(vec![], None).is_ok());
        assert!(TrustedProxyPolicy::new(vec![], Some(ForwardedHeader::XRealIp)).is_err());
        assert!(TrustedProxyPolicy::new(vec!["127.0.0.1".parse().unwrap()], None).is_err());
    }
}
