//! Version 2 protocol definition
//!
//! This protocol defined as binary prefixed with `[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]`

use core::{mem, net};

use crate::v1;
use crate::{Addr, UnixAddr};
use crate::error::ParseError;
use crate::utils::{unlikely, get_aligned_chunk_ref, try_get_aligned_chunk_ref};
use crate::utils::BufSlice;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
///Descriptor of CRC32 checksum within TLV payload
///
///Checksum itself is always 4 bytes
pub struct TlvCrc32 {
    ///Checksum
    pub checksum: u32,
    ///Position within `tlv_payload` where checksum bytes start
    pub checksum_start: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
///Group of additional fields that might be optionally present in v2 header
pub struct Tlvs<'a> {
    ///Full slice within proxy version payload containing TLV data
    pub tlv_payload: &'a [u8],
    ///Reference to byte string within buffer with ALPN text identification
    pub alpn: Option<BufSlice<'a>>,
    ///Reference to byte string within buffer with authority text identification
    pub authority: Option<BufSlice<'a>>,
    ///Checksum of the `tlv_payload` with crc bytes zeroed
    pub crc32c: Option<TlvCrc32>,
    ///Reference to unique identifier as arbitrary bytes up 128 in length
    pub unique_id: Option<&'a [u8]>,
    ///Reference to byte string within buffer with network namespace
    pub netns: Option<BufSlice<'a>>,
}

impl<'a> Tlvs<'a> {
    ///Attempts to reinterpret `tlv_payload` aborting on malformed input
    pub fn slice_from(tlv_payload: &'a [u8]) -> Result<Self, ParseError> {
        let mut result = Tlvs {
            tlv_payload,
            alpn: None,
            authority: None,
            crc32c: None,
            unique_id: None,
            netns: None,
        };

        let mut offset = 0;
        while !tlv_payload.is_empty() {
            //TLV always have 3 bytes for type + length
            let tlv_header = match try_get_aligned_chunk_ref::<[u8; 3]>(tlv_payload, offset) {
                Some(header) => header,
                None => return Err(unlikely(ParseError::MalformedTlv))
            };
            let tlv_type = tlv_header[0];
            let tlv_length = u16::from_be_bytes([tlv_header[1], tlv_header[2]]);

            let tlv_value_offset = offset + tlv_header.len();
            let tlv_value = match tlv_payload.get(tlv_value_offset..tlv_value_offset+tlv_length as usize) {
                Some(value) => value,
                None => return Err(unlikely(ParseError::MalformedTlv))
            };

            offset = tlv_value_offset + tlv_value.len();

            match tlv_type {
                //PP2_TYPE_ALPN
                0x01 => {
                    result.alpn = Some(BufSlice(tlv_value));
                },
                //PP2_TYPE_AUTHORITY
                0x02 => {
                    result.authority = Some(BufSlice(tlv_value));
                },
                //PP2_TYPE_CRC32C
                0x03 => {
                    if tlv_value.len() != 4 {
                        return Err(unlikely(ParseError::MalformedTlv));
                    }
                    let crc32_bytes = get_aligned_chunk_ref(tlv_value, 0);
                    let checksum = u32::from_be_bytes(*crc32_bytes);
                    result.crc32c = Some(TlvCrc32 {
                        checksum,
                        checksum_start: tlv_value_offset
                    })
                },

                //PP2_TYPE_NOOP can be skipped
                //0x04

                //PP2_TYPE_UNIQUE_ID
                0x05 => {
                    if tlv_value.len() >= 128 {
                        return Err(unlikely(ParseError::MalformedTlv));
                    }
                    result.unique_id = Some(tlv_value);
                },

                //PP2_TYPE_SSL
                0x20 => {
                    todo!();
                },

                //PP2_TYPE_NETNS
                0x30 => {
                    result.netns = Some(BufSlice(tlv_value));
                },

                //Skip NOOP/unknown TLV
                _ => continue,
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Reference to TLV payload
pub struct TlvsSlice<'a>(&'a [u8]);

impl<'a> TlvsSlice<'a> {
    #[inline(always)]
    const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            Some(Self(bytes))
        }
    }

    ///Access raw bytes
    pub const fn raw(&self) -> &'a [u8] {
        self.0
    }

    ///Extracts raw payload into [Tlvs]
    pub fn extract(self) -> Result<Tlvs<'a>, ParseError> {
        Tlvs::slice_from(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Result of [Proxy] parsing containing number of bytes consumed
pub struct ProxyParseResult {
    ///Transport protocol indicated by the proxy.
    pub protocol: TransportProtocol,
    ///Proxy information extraction
    ///
    ///If protocol type is unknown (due to LOCAL proxy), then [Proxy] `info` will be `None`
    pub info: Option<Proxy>,
    ///Number of bytes consumed
    pub len: usize,
}

fn parse_proxy(buf: &[u8]) -> Result<(ProxyParseResult, Option<TlvsSlice<'_>>), ParseError> {
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
            return Ok((ProxyParseResult {
                protocol: TransportProtocol::Unknown,
                info: None,
                len: payload.len() + HEADER_LEN
            }, None));
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

    let tlvs = tlvs.and_then(TlvsSlice::new);
    let result = ProxyParseResult {
        protocol,
        info,
        len: len + HEADER_LEN,
    };
    Ok((result, tlvs))
}

#[inline]
///Parses binary protocol version 2 prefixed with `[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]`
///
///This immediately parse available proxy return and returns optional reference to [TlvsSlice] which can be further parsed via [TlvsSlice::extract]
pub fn parse(buf: &[u8]) -> Result<(ProxyParseResult, Option<TlvsSlice<'_>>), ParseError> {
    match buf.strip_prefix(&SIG) {
        Some(buf) => {
            let mut result = parse_proxy(buf)?;
            result.0.len += SIG.len();
            Ok(result)
        },
        None if buf.len() >= SIG.len() => return Err(ParseError::InvalidProxySig),
        None => Err(unlikely(ParseError::Incomplete))
    }
}
