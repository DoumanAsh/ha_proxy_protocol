//! Version 2 protocol definition
//!
//! This protocol defined as binary prefixed with `[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]`

use core::{mem, net};

use crate::v1;
use crate::{Addr, UnixAddr};
use crate::error::ParseError;
use crate::utils::{unlikely, get_aligned_chunk_ref};

const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

///Simple extractor that relies on Self to be directly mapped from bytes
unsafe trait RawExtractor: Copy + Sized + Into<Addr> {
    const EXTRACT_SIZE: usize = mem::size_of::<Self>() * 2;

    fn extract_proxy_info(payload: &[u8]) -> Result<Proxy, ParseError> {
        if Self::EXTRACT_SIZE > payload.len() {
            return Err(unlikely(ParseError::InvalidTransportSize));
        }

        let src: Self = *get_aligned_chunk_ref(payload, 0);
        let dst: Self = *get_aligned_chunk_ref(payload, mem::size_of::<Self>());

        Ok(Proxy {
            src: src.into(),
            dst: dst.into(),
        })
    }
}

unsafe impl RawExtractor for UnixAddr {
}

//Extractor for network addresses requiring IpAddr octets and port
unsafe trait NetExtractor: Copy + Sized + Into<net::IpAddr>  {
    const EXTRACT_SIZE: usize = (mem::size_of::<Self>() + mem::size_of::<u16>()) * 2;

    fn extract_proxy_info(payload: &[u8]) -> Result<(Proxy, usize), ParseError> {
        if Self::EXTRACT_SIZE > payload.len() {
            return Err(unlikely(ParseError::InvalidTransportSize));
        }

        let src_ip_bytes: Self = *get_aligned_chunk_ref(payload, 0);
        let src_ip = src_ip_bytes.into();

        let dst_ip_bytes: Self = *get_aligned_chunk_ref(payload, mem::size_of::<Self>());
        let dst_ip = dst_ip_bytes.into();

        let src_port_bytes = *get_aligned_chunk_ref(payload, mem::size_of::<Self>() * 2);
        let src_port = u16::from_be_bytes(src_port_bytes);

        let dst_port_bytes = *get_aligned_chunk_ref(payload, mem::size_of::<Self>() * 2 + mem::size_of::<u16>());
        let dst_port = u16::from_be_bytes(dst_port_bytes);

        debug_assert_eq!(mem::size_of_val(&src_ip_bytes) + mem::size_of_val(&dst_ip_bytes) + mem::size_of::<u16>() * 2, Self::EXTRACT_SIZE);

        let src = net::SocketAddr::from((src_ip, src_port)).into();
        let dst = net::SocketAddr::from((dst_ip, dst_port)).into();

        Ok((Proxy {
            src,
            dst
        }, Self::EXTRACT_SIZE))
    }
}

unsafe impl NetExtractor for [u8; 4] {
}

unsafe impl NetExtractor for [u8; 16] {
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
///Possible transport protocols
pub enum TransportProtocol {
    ///Unknown, only the case for LOCAL proxy
    Unknown,
    ///Streaming based transports like TCP
    Stream,
    ///Datagram based transports like UDP
    Datagram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Proxy protocol descriptor
pub struct Proxy {
    ///Source address
    pub src: Addr,
    ///Destination address
    pub dst: Addr,
}

impl From<v1::Proxy> for Proxy {
    #[inline(always)]
    fn from(value: v1::Proxy) -> Self {
        let v1::Proxy { src, dst } = value;
        Self {
            src: Addr::Inet(src),
            dst: Addr::Inet(dst),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Result of [Proxy] parsing containing number of bytes consumed
pub struct ProxyParseResult {
    ///Transport protocol indicated by the proxy.
    pub protocol: TransportProtocol,
    ///Proxy information extraction
    ///
    ///If address type is UNKNOWN, then [Proxy] `info` will be `None`
    pub info: Option<Proxy>,
    ///Number of bytes consumed
    pub len: usize,
}

fn parse_proxy(buf: &[u8]) -> Result<ProxyParseResult, ParseError> {
    //command + family + len(2)
    const HEADER_LEN: usize = 4;

    //15 + 16 bytes contain length in BE order
    //So use it to extract rest of the payload
    #[inline(always)]
    fn get_payload(buf: &[u8]) -> Result<&[u8], ParseError> {
        match (buf.get(2), buf.get(3)) {
            (Some(b1), Some(b2)) => {
                let len = u16::from_be_bytes([*b1, *b2]) as usize;
                buf.get(HEADER_LEN..len+HEADER_LEN).ok_or(ParseError::Incomplete)
            },
            _ => return Err(ParseError::Incomplete),
        }
    }

    //Ensure it is valid version 2 signature and get command indicator
    let command = match buf.get(0) {
        Some(version) if version & 0xF0 == 0x20 => version & 0x0F,
        _ => return Err(unlikely(ParseError::Incomplete)),
    };
    //The 14th byte contains the transport protocol and address family. The highest 4 bits contain the address family, the lowest 4 bits contain the protocol.
    let (protocol, info, len, tlvs) = match buf.get(1) {
        //Unspec (only LOCAL is allowed to use it)
        //We inspect no data inside as it is not supposed to be sent
        Some(0) => if command == 0 {
            let payload = get_payload(buf)?;
            return Ok(ProxyParseResult {
                protocol: TransportProtocol::Unknown,
                info: None,
                len: payload.len() + HEADER_LEN
            });
        } else {
            return Err(unlikely(ParseError::InvalidProxy2WrongLocalCmd))
        },
        //TCP IPv4
        Some(0x11) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = <[u8; 4]>::extract_proxy_info(payload)?;
            (TransportProtocol::Stream, Some(info), payload.len(), payload.get(extracted_len..))
        },
        //UDP IPv4
        Some(0x12) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = <[u8; 4]>::extract_proxy_info(payload)?;
            (TransportProtocol::Datagram, Some(info), payload.len(), payload.get(extracted_len..))
        },

        //TCP IPv6
        Some(0x21) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = <[u8; 16]>::extract_proxy_info(payload)?;
            (TransportProtocol::Stream, Some(info), payload.len(), payload.get(extracted_len..))
        },
        //UDP IPv6
        Some(0x22) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = <[u8; 16]>::extract_proxy_info(payload)?;
            (TransportProtocol::Datagram, Some(info), payload.len(), payload.get(extracted_len..))
        },

        //Unix stream
        Some(0x31) => {
            let payload = get_payload(buf)?;
            let info = UnixAddr::extract_proxy_info(payload)?;
            (TransportProtocol::Stream, Some(info), payload.len(), payload.get(UnixAddr::EXTRACT_SIZE..))
        },
        //Unix datagram
        Some(0x32) => {
            let payload = get_payload(buf)?;
            let info = UnixAddr::extract_proxy_info(payload)?;
            (TransportProtocol::Datagram, Some(info), payload.len(), payload.get(UnixAddr::EXTRACT_SIZE..))
        },

        Some(_) => return Err(ParseError::InvalidTransport),
        None => return Err(unlikely(ParseError::Incomplete)),
    };

    Ok(ProxyParseResult {
        protocol,
        info,
        len: len + HEADER_LEN
    })
}

#[inline]
///Parses binary protocol version 2 prefixed with `[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]`
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
