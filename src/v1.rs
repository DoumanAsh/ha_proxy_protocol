//! Version 1 protocol definition
//!
//! This protocol defined as text prefixed with `PROXY`

use core::net;
use crate::error::ParseError;
use crate::utils::unlikely;

const SIG: [u8; 6] = *b"PROXY ";
const LINE_ENDING: [u8; 2] = *b"\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Proxy protocol descriptor
pub struct Proxy {
    ///Source address
    pub src: net::SocketAddr,
    ///Destination address
    pub dst: net::SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Result of [Proxy] parsing containing number of bytes consumed
pub struct ProxyParseResult {
    ///Proxy information extraction
    ///
    ///If address type is UNKNOWN, then [Proxy] `info` will be `None`
    pub info: Option<Proxy>,
    ///Number of bytes consumed
    pub len: usize,
}

fn parse_proxy(buf: &[u8]) -> Result<ProxyParseResult, ParseError> {
    let (len, buf) = match buf.windows(2).position(|buf: &[u8]| *buf == LINE_ENDING) {
        Some(line_len) => (line_len + LINE_ENDING.len(), &buf[..line_len]),
        None => return Err(ParseError::Incomplete),
    };

    let proxy_line = match core::str::from_utf8(buf) {
        Ok(proxy_line) => proxy_line,
        Err(_) => return Err(unlikely(ParseError::InvalidProxy1Str)),
    };
    let mut proxy_line_parts = proxy_line.splitn(6, ' ');
    let (src_ip, dst_ip) = match proxy_line_parts.next() {
        Some("TCP4") => {
            let src_ip = proxy_line_parts.next().ok_or(ParseError::MissingSrcAddr)?;
            let dst_ip = proxy_line_parts.next().ok_or(ParseError::MissingSrcAddr)?;

            let src_ip = net::IpAddr::V4(src_ip.parse().map_err(|_| ParseError::InvalidSrcIpv4)?);
            let dst_ip = net::IpAddr::V4(dst_ip.parse().map_err(|_| ParseError::InvalidDstIpv4)?);
            (src_ip, dst_ip)
        },
        Some("TCP6") => {
            let src_ip = proxy_line_parts.next().ok_or(ParseError::MissingSrcAddr)?;
            let dst_ip = proxy_line_parts.next().ok_or(ParseError::MissingSrcAddr)?;

            let src_ip = net::IpAddr::V6(src_ip.parse().map_err(|_| ParseError::InvalidSrcIpv6)?);
            let dst_ip = net::IpAddr::V6(dst_ip.parse().map_err(|_| ParseError::InvalidDstIpv6)?);
            (src_ip, dst_ip)
        },
        Some("UNKNOWN") => {
            let info = None;
            //Even if it is UNKNOWN, make sure no one supplised something weird, just in case
            for _ in 0..4 {
                if proxy_line_parts.next().is_none() {
                    return Ok(ProxyParseResult { info, len })
                }
            }

            if let Some(_part) = proxy_line_parts.next() {
                return Err(unlikely(ParseError::InvalidProxy1Overflow));
            } else {
                return Ok(ProxyParseResult { info, len })
            }
        },
        _ => return Err(ParseError::InvalidTransport),
    };

    let src_port = proxy_line_parts.next().ok_or(ParseError::MissingSrcPort)?.parse().map_err(|_| ParseError::InvalidSrcPort)?;
    let dst_port = proxy_line_parts.next().ok_or(ParseError::MissingDstPort)?.parse().map_err(|_| ParseError::InvalidDstPort)?;

    //Make sure input is done, before considering it valid
    if let Some(_part) = proxy_line_parts.next() {
        return Err(unlikely(ParseError::InvalidProxy1Overflow));
    }

    let src = net::SocketAddr::new(src_ip, src_port);
    let dst = net::SocketAddr::new(dst_ip, dst_port);

    let info = Some(Proxy {
        src,
        dst,
    });
    return Ok(ProxyParseResult { info, len })
}

#[inline]
///Parses `PROXY <type> <src_ip> <dst_ip> <src_port> <dst_port>\r\n` returning [ProxyParseResult]
pub fn parse(buf: &[u8]) -> Result<ProxyParseResult, ParseError> {
    match buf.strip_prefix(&SIG) {
        Some(buf) => {
            let mut result = parse_proxy(buf)?;
            result.len += SIG.len();
            Ok(result)
        },
        None if buf.len() >= SIG.len() => return Err(ParseError::InvalidProxySig),
        None => Err(unlikely(ParseError::Incomplete))
    }
}
