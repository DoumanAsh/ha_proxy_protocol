//![HAProxy protocol](https://www.haproxy.org/download/3.4/doc/proxy-protocol.txt) implementation.

#![no_std]
#![warn(missing_docs)]
#![allow(clippy::style)]

use core::{fmt, ptr};
use core::net::{self, SocketAddr};

mod utils;
pub use utils::BufSlice;
mod error;
pub use error::ParseError;
pub mod v1;
pub mod v2;
pub mod tlv;

#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq)]
///Unix socket address
pub struct UnixAddr(utils::StrBuf<108>);

impl UnixAddr {
    #[inline(always)]
    ///Creates new address from raw bytes
    pub const fn new(addr: [u8; 108]) -> Self {
        Self(utils::StrBuf::new(addr))
    }

    #[inline(always)]
    ///Creates new address, trimming on overflow
    pub const fn new_str(addr: &str) -> Self {
        let mut buf = [0; 108];
        let len = if addr.len() > buf.len() {
            buf.len()
        } else {
            addr.len()
        };
        unsafe {
            ptr::copy_nonoverlapping(addr.as_ptr(), buf.as_mut_ptr(), len);
        };
        Self::new(buf)
    }

    #[inline(always)]
    ///Gets reference to raw buffer
    pub const fn raw(&self) -> &[u8; 108] {
        self.0.raw()
    }

    #[inline(always)]
    ///Returns address
    pub const fn addr(&self) -> &[u8] {
        self.0.content()
    }

    #[inline(always)]
    ///Attempts to interpret path as utf-8 string, returning raw address bytes in case of error
    pub const fn to_str_or(&self) -> Result<&str, &[u8]> {
        self.0.to_str_or()
    }

    #[inline(always)]
    ///Attempts to interpret path as utf-8 string, returning `None` if addr is not valid string
    pub const fn to_str(&self) -> Option<&str> {
        self.0.to_str()
    }
}

impl fmt::Debug for UnixAddr {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl fmt::Display for UnixAddr {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, fmt)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
///Generic proxy Address
pub enum Addr {
    ///Network address
    Inet(SocketAddr),
    ///Unix socket address
    Unix(UnixAddr),
}

impl fmt::Debug for Addr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(addr) => fmt::Debug::fmt(addr, fmt),
            Self::Unix(addr) => fmt::Debug::fmt(addr, fmt),
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet(addr) => fmt::Display::fmt(addr, fmt),
            Self::Unix(addr) => fmt::Display::fmt(addr, fmt),
        }
    }
}

impl From<net::SocketAddrV4> for Addr {
    #[inline(always)]
    fn from(value: net::SocketAddrV4) -> Self {
        Self::Inet(SocketAddr::V4(value))
    }
}

impl From<net::SocketAddrV6> for Addr {
    #[inline(always)]
    fn from(value: net::SocketAddrV6) -> Self {
        Self::Inet(SocketAddr::V6(value))
    }
}

impl From<SocketAddr> for Addr {
    #[inline(always)]
    fn from(value: SocketAddr) -> Self {
        Self::Inet(value)
    }
}

impl From<UnixAddr> for Addr {
    #[inline(always)]
    fn from(value: UnixAddr) -> Self {
        Self::Unix(value)
    }
}

impl PartialEq<SocketAddr> for Addr {
    #[inline(always)]
    fn eq(&self, other: &SocketAddr) -> bool {
        match self {
            Self::Inet(addr) => other == addr,
            Self::Unix(_) => false
        }
    }
}

impl PartialEq<net::SocketAddrV4> for Addr {
    #[inline(always)]
    fn eq(&self, other: &net::SocketAddrV4) -> bool {
        match self {
            Self::Inet(SocketAddr::V4(addr)) => other == addr,
            _ => false
        }
    }
}

impl PartialEq<net::SocketAddrV6> for Addr {
    #[inline(always)]
    fn eq(&self, other: &net::SocketAddrV6) -> bool {
        match self {
            Self::Inet(SocketAddr::V6(addr)) => other == addr,
            _ => false
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Result of proxy parsing enumerating possible versions
pub enum ProxyParseResult<'a> {
    ///[v1] result
    V1(v1::ProxyParseResult),
    ///[v2] result
    V2(v2::ProxyParseResult, Option<tlv::TlvsSlice<'a>>),
}

impl ProxyParseResult<'_> {
    #[inline(always)]
    ///Extract proxy parsing result into generic result
    pub fn into_generic(self) -> (Option<v2::Proxy>, usize) {
        match self {
            Self::V1(result) => (result.info.map(Into::into), result.len),
            Self::V2(result, _) => (result.info, result.len),
        }
    }
}

#[inline(always)]
///Parses proxy protocol in `buf` returning result if `buf` content matches any known protocol version
pub fn parse(buf: &[u8]) -> Result<ProxyParseResult<'_>, ParseError> {
    match v1::parse(buf) {
        Ok(result) => Ok(ProxyParseResult::V1(result)),
        Err(ParseError::InvalidProxySig) => v2::parse(buf).map(|(info, tlvs)| ProxyParseResult::V2(info, tlvs)),
        Err(error) => Err(error)
    }
}
