//! Version 2 protocol definition
//!
//! This protocol defined as binary prefixed with `[0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A]`

use core::{mem, net, ptr};

use crate::{tlv, v1};
use crate::{Addr, UnixAddr};
use crate::error::ParseError;
use crate::utils::{unlikely, get_aligned_chunk_ref};

const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];
//command + family + len(2)
const HEADER_LEN: usize = 4;

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

impl Proxy {
    ///Max required length to hold [Proxy]
    pub const MAX_LEN: usize = 232;
    ///Max required length to hold [Proxy] with IP addresses only
    pub const MAX_IP_LEN: usize = 57;
    #[inline]
    ///Returns required buffer size to hold [Proxy] encoded in proxy version 2 without TLV
    ///
    ///In debug build it asserts that [Proxy] is constructed correctly (i.e. src and dst are the same type of address)
    pub const fn required_buffer_size(&self) -> usize {
        match self.src {
            Addr::Unix(_) => {
                debug_assert!(matches!(self.dst, Addr::Unix(_)));
                Self::MAX_LEN
            },
            Addr::Inet(net::SocketAddr::V4(_)) => {
                debug_assert!(matches!(self.dst, Addr::Inet(net::SocketAddr::V4(_))));
                28
            },
            Addr::Inet(net::SocketAddr::V6(_)) => {
                debug_assert!(matches!(self.dst, Addr::Inet(net::SocketAddr::V6(_))));
                Self::MAX_IP_LEN
            },
        }
    }

    ///Attempts to encode [Proxy] into `out` returning number of bytes written.
    ///
    ///All `tlvs` will be attempted to be written in addition to the [Proxy] payload
    ///
    ///Returns `0` if `out` buffer has insufficient size
    pub fn encode_uninit_with_tlv<'a>(&self, transport: TransportProtocol, out: &mut [mem::MaybeUninit<u8>], tlvs: impl Iterator<Item = tlv::Tlv<'a>>) -> usize {
        macro_rules! write_signature {
            ($out:ident) => {
                unsafe {
                    ptr::copy_nonoverlapping(SIG.as_ptr(), $out.as_mut_ptr() as _, SIG.len());
                }
            };
        }

        macro_rules! write_header {
            ($out:ident, $cmd:expr, $family:expr, $len:expr) => {
                $out[SIG.len()] = mem::MaybeUninit::new($cmd);
                $out[SIG.len() + 1] = mem::MaybeUninit::new($family);
                let len_bytes = ($len).to_be_bytes();
                $out[SIG.len() + 2] = mem::MaybeUninit::new(len_bytes[0]);
                $out[SIG.len() + 3] = mem::MaybeUninit::new(len_bytes[1]);
            };
        }

        macro_rules! write_inet {
            ($src:expr, $dst:expr) => {
                let src_ip = $src.ip().octets();
                let dst_ip = $dst.ip().octets();
                unsafe {
                    ptr::copy_nonoverlapping(src_ip.as_ptr(), out.as_mut_ptr().add(SIG.len() + HEADER_LEN) as _, src_ip.len());
                    ptr::copy_nonoverlapping(dst_ip.as_ptr(), out.as_mut_ptr().add(SIG.len() + HEADER_LEN + src_ip.len()) as _, dst_ip.len());
                }

                let src_port = $src.port().to_be_bytes();
                let dst_port = $dst.port().to_be_bytes();
                unsafe {
                    ptr::copy_nonoverlapping(src_port.as_ptr(), out.as_mut_ptr().add(SIG.len() + HEADER_LEN + src_ip.len() + dst_ip.len()) as _, src_port.len());
                    ptr::copy_nonoverlapping(dst_port.as_ptr(), out.as_mut_ptr().add(SIG.len() + HEADER_LEN + src_ip.len() + dst_ip.len() + src_port.len()) as _, dst_port.len());
                }
            };
        }
        //should be called guarded by length check
        fn encode_local(out: &mut [mem::MaybeUninit<u8>]) -> usize {
            write_signature!(out);
            write_header!(out, 0x20, 0x00, 0x00u16);
            SIG.len() + HEADER_LEN
        }

        let (family, mut len) = match (self.src, self.dst) {
            (Addr::Unix(src), Addr::Unix(dst)) => {
                let len = 232;
                if out.len() < len {
                    return 0
                } else {
                    let family = match transport {
                        TransportProtocol::Stream => 0x31,
                        TransportProtocol::Datagram => 0x32,
                        TransportProtocol::Unknown => return encode_local(out),
                    };

                    unsafe {
                        ptr::copy_nonoverlapping(src.raw().as_ptr(), out.as_mut_ptr().add(SIG.len() + HEADER_LEN) as _, src.raw().len());
                        ptr::copy_nonoverlapping(dst.raw().as_ptr(), out.as_mut_ptr().add(SIG.len() + HEADER_LEN + src.raw().len()) as _, dst.raw().len());
                    }
                    (family, len)
                }
            },
            (Addr::Inet(net::SocketAddr::V4(src)), Addr::Inet(net::SocketAddr::V4(dst))) => {
                let len = 28;
                if out.len() < len {
                    return 0
                } else {
                    let family = match transport {
                        TransportProtocol::Stream => 0x11,
                        TransportProtocol::Datagram => 0x12,
                        TransportProtocol::Unknown => return encode_local(out),
                    };

                    write_inet!(src, dst);
                    (family, len)
                }

            },
            (Addr::Inet(net::SocketAddr::V6(src)), Addr::Inet(net::SocketAddr::V6(dst))) => {
                let len = 52;
                if out.len() < len {
                    return 0
                } else {
                    let family = match transport {
                        TransportProtocol::Stream => 0x21,
                        TransportProtocol::Datagram => 0x22,
                        TransportProtocol::Unknown => return encode_local(out),
                    };

                    write_inet!(src, dst);
                    (family, len)
                }

            },
            #[cfg(debug_assertions)]
            _ => panic!("Mismatch between src and "),
            #[cfg(not(debug_assertions))]
            _ => return 0,
        }; // match src

        for tlv in tlvs {
            let written = tlv.encode_uninit(&mut out[len..]);
            if written == 0 {
                return 0;
            }

            len += written;
        }

        write_signature!(out);
        write_header!(out, 0x21, family, (len - SIG.len() - HEADER_LEN) as u16);
        len
    }

    #[inline(always)]
    ///Attempts to encode [Proxy] into `out` returning number of bytes written.
    ///
    ///Returns `0` if `out` buffer has insufficient size
    pub fn encode_uninit(&self, transport: TransportProtocol, out: &mut [mem::MaybeUninit<u8>]) -> usize {
        self.encode_uninit_with_tlv(transport, out, [].into_iter())
    }

    #[inline]
    ///Attempts to encode [Proxy] into `out` returning number of bytes written.
    ///
    ///All `tlvs` will be attempted to be written in addition to the [Proxy] payload
    ///
    ///Returns `0` if `out` buffer has insufficient size
    pub fn encode_with_tlv<'a>(&self, transport: TransportProtocol, out: &mut [u8], tlvs: impl Iterator<Item = tlv::Tlv<'a>>) -> usize {
        let out = unsafe {
            core::slice::from_raw_parts_mut(out.as_mut_ptr() as _, out.len())
        };
        self.encode_uninit_with_tlv(transport, out, tlvs)
    }

    #[inline]
    ///Attempts to encode [Proxy] into `out` returning number of bytes written.
    ///
    ///Returns `0` if `out` buffer has insufficient size
    pub fn encode(&self, transport: TransportProtocol, out: &mut [u8]) -> usize {
        let out = unsafe {
            core::slice::from_raw_parts_mut(out.as_mut_ptr() as _, out.len())
        };
        self.encode_uninit_with_tlv(transport, out, [].into_iter())
    }
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
    ///If protocol type is unknown (due to LOCAL proxy), then [Proxy] `info` will be `None`
    pub info: Option<Proxy>,
    ///Number of bytes consumed
    pub len: usize,
}

fn parse_proxy(buf: &[u8]) -> Result<(ProxyParseResult, Option<tlv::TlvsSlice<'_>>), ParseError> {
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

    let tlvs = tlvs.and_then(tlv::TlvsSlice::new);
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
///This immediately parse available proxy return and returns optional reference to [TlvsSlice](../tlv/struct.TlvsSlice.html) which can be further parsed via iteration.
pub fn parse(buf: &[u8]) -> Result<(ProxyParseResult, Option<tlv::TlvsSlice<'_>>), ParseError> {
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
