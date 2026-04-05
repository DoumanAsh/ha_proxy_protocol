use core::{mem, net};
use crate::{Proxy, UnixAddr, ProxyParseResult, TransportProtocol};
use crate::error::ParseError;
use crate::utils::{unlikely, get_aligned_chunk_ref};

const SIG: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

pub fn parse_proxy(buf: &[u8]) -> Result<ProxyParseResult, ParseError> {
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

    fn extract_proxy_info_v4(payload: &[u8]) -> (Proxy, usize) {
        let src_ip_bytes = *get_aligned_chunk_ref(payload, 0);
        let src_ip = net::Ipv4Addr::from_octets(src_ip_bytes);
        let mut len = mem::size_of_val(&src_ip_bytes);

        let dst_ip_bytes = *get_aligned_chunk_ref(payload, len);
        let dst_ip = net::Ipv4Addr::from_octets(dst_ip_bytes);
        len += mem::size_of_val(&dst_ip_bytes);

        let src_port_bytes = *get_aligned_chunk_ref(payload, len);
        let src_port = u16::from_be_bytes(src_port_bytes);
        len += mem::size_of_val(&src_port_bytes);

        let dst_port_bytes = *get_aligned_chunk_ref(payload, len);
        let dst_port = u16::from_be_bytes(dst_port_bytes);
        len += mem::size_of_val(&dst_port_bytes);

        let proxy = Proxy {
            src: net::SocketAddrV4::new(src_ip, src_port).into(),
            dst: net::SocketAddrV4::new(dst_ip, dst_port).into(),
        };
        (proxy, len)
    }

    fn extract_proxy_info_v6(payload: &[u8]) -> (Proxy, usize) {
        let src_ip_bytes = *get_aligned_chunk_ref(payload, 0);
        let src_ip = net::Ipv6Addr::from_octets(src_ip_bytes);
        let mut len = mem::size_of_val(&src_ip_bytes);

        let dst_ip_bytes = *get_aligned_chunk_ref(payload, len);
        let dst_ip = net::Ipv6Addr::from_octets(dst_ip_bytes);
        len += mem::size_of_val(&dst_ip_bytes);

        let src_port_bytes = *get_aligned_chunk_ref(payload, len);
        let src_port = u16::from_be_bytes(src_port_bytes);
        len += mem::size_of_val(&src_port_bytes);

        let dst_port_bytes = *get_aligned_chunk_ref(payload, len);
        let dst_port = u16::from_be_bytes(dst_port_bytes);
        len += mem::size_of_val(&dst_port_bytes);

        let proxy = Proxy {
            src: net::SocketAddrV6::new(src_ip, src_port, 0, 0).into(),
            dst: net::SocketAddrV6::new(dst_ip, dst_port, 0, 0).into(),
        };
        (proxy, len)
    }

    fn extract_proxy_info_unix(payload: &[u8]) -> (Proxy, usize) {
        let src_bytes = *get_aligned_chunk_ref(payload, 0);
        let src = UnixAddr::new(src_bytes).into();
        let mut len = mem::size_of_val(&src_bytes);

        let dst_bytes = *get_aligned_chunk_ref(payload, len);
        let dst = UnixAddr::new(dst_bytes).into();
        len += mem::size_of_val(&dst_bytes);

        let proxy = Proxy {
            src,
            dst,
        };
        (proxy, len)
    }

    //Ensure it is valid version 2 signature and get command indicator
    let command = match buf.get(0) {
        Some(version) if version & 0xF0 == 0x20 => version & 0x0F,
        _ => return Err(unlikely(ParseError::Incomplete)),
    };
    //The 14th byte contains the transport protocol and address family. The highest 4 bits contain the address family, the lowest 4 bits contain the protocol.
    match buf.get(1) {
        //Unspec (only LOCAL is allowed to use it)
        Some(0) => if command == 0 {
            let payload = get_payload(buf)?;
            Ok(ProxyParseResult::new_v2(TransportProtocol::Unknown, None, payload.len() + HEADER_LEN))
        } else {
            Err(unlikely(ParseError::InvalidProxy2WrongLocalCmd))
        },
        //TCP IPv4
        Some(0x11) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = extract_proxy_info_v4(payload);
            Ok(ProxyParseResult::new_v2(TransportProtocol::Stream, Some(info), payload.len() + HEADER_LEN))
        },
        //UDP IPv4
        Some(0x12) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = extract_proxy_info_v4(payload);
            Ok(ProxyParseResult::new_v2(TransportProtocol::Datagram, Some(info), payload.len() + HEADER_LEN))
        },

        //TCP IPv6
        Some(0x21) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = extract_proxy_info_v6(payload);
            Ok(ProxyParseResult::new_v2(TransportProtocol::Stream, Some(info), payload.len() + HEADER_LEN))
        },
        //UDP IPv6
        Some(0x22) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = extract_proxy_info_v6(payload);
            Ok(ProxyParseResult::new_v2(TransportProtocol::Datagram, Some(info), payload.len() + HEADER_LEN))
        },

        //Unix stream
        Some(0x31) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = extract_proxy_info_unix(payload);
            Ok(ProxyParseResult::new_v2(TransportProtocol::Stream, Some(info), payload.len() + HEADER_LEN))
        },
        //Unix datagram
        Some(0x32) => {
            let payload = get_payload(buf)?;
            let (info, extracted_len) = extract_proxy_info_unix(payload);
            Ok(ProxyParseResult::new_v2(TransportProtocol::Datagram, Some(info), payload.len() + HEADER_LEN))
        },
        Some(_) => Err(ParseError::InvalidTransport),
        None => Err(unlikely(ParseError::Incomplete)),
    }
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
