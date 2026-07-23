//! 由 TCP 监听器固定的远端 IP 身份。
//!
//! 请求来源只取自内核返回的 TCP 对端地址。应用不解析代理转发头，也不
//! 接受 Unix-domain 凭据，因此认证、限流与访问日志始终共用同一个远端 IP。

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

/// 连接接收时固定的直接 TCP 对端。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PeerIdentity(IpAddr);

impl PeerIdentity {
    pub(crate) fn tcp(addr: SocketAddr) -> Self {
        Self(addr.ip())
    }

    pub(crate) fn direct_source(self) -> SourceIdentity {
        SourceIdentity(self.0)
    }
}

/// 认证、限流与日志共用的远端 IP。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct SourceIdentity(IpAddr);

impl From<IpAddr> for SourceIdentity {
    fn from(address: IpAddr) -> Self {
        Self(address)
    }
}

impl fmt::Display for SourceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_source_uses_only_the_remote_ip() {
        let first = PeerIdentity::tcp("192.0.2.8:1234".parse().unwrap());
        let second = PeerIdentity::tcp("192.0.2.8:5678".parse().unwrap());

        assert_eq!(first, second);
        assert_eq!(first.direct_source(), second.direct_source());
        assert_eq!(first.direct_source().to_string(), "192.0.2.8");
    }
}
