//! 启动时固定的文件系统对象身份，以及连接接收时固定的网络来源身份。
//!
//! Stable filesystem-object identities captured at startup and transport-source
//! identities captured when a connection is accepted.

mod path;
mod source;

pub(crate) use path::{ObjectIdentity, OutputPathIdentity, PathIdentity, ServedPathIdentity};
pub(crate) use source::{
    ForwardedHeader, IpCidr, PeerIdentity, SourceIdentity, TrustedProxyPolicy,
};
