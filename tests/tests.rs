use core::net;

use ha_proxy_protocol::{parse, parse_v1};
use ha_proxy_protocol::{Addr, UnixAddr, Proxy, ParseError, ProxyVersion, TransportProtocol};

fn create_v4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> Addr {
    net::SocketAddrV4::new(net::Ipv4Addr::new(a, b, c, d), port).into()
}

fn create_v6_addr(text: &str, port: u16) -> Addr {
    net::SocketAddrV6::new(text.parse().unwrap(), port, 0, 0).into()
}

#[test]
fn should_verify_unix_addr() {
    let addr = UnixAddr::new([b'\0'; 108]);
    assert_eq!(addr.addr(), []);
    let addr = UnixAddr::new([b'1'; 108]);
    assert_eq!(addr.addr(), [b'1'; 108]);
    assert_eq!(addr.to_str().unwrap().len(), 108);
}

#[test]
fn should_parse_valid_version1() {
    let inputs = [
        ("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n", Proxy { src: create_v4_addr(255, 255, 255, 255, 65535), dst: create_v4_addr(255, 255, 255, 255, 65535)  }),
        ("PROXY TCP4 127.0.0.1 255.255.255.255 80 65535\r\n", Proxy { src: create_v4_addr(127, 0, 0, 1, 80), dst: create_v4_addr(255, 255, 255, 255, 65535)  }),
        ("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n", Proxy { src: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535), dst: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535)  }),
        ("PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 80 65535\r\n", Proxy { src: create_v6_addr("::1", 80), dst: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535)  }),
    ];

    for (input, expected_info) in inputs {
        let result = match parse(input.as_bytes()) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{input:?}' but got error: {error}"),
        };
        assert_eq!(result.len, input.len());
        let info = result.info.unwrap();
        assert_eq!(result.info.unwrap(), expected_info, "Expected {expected_info:#?} but got {info:#?}");
        assert_eq!(result.version, ProxyVersion::V1);
    }
}

#[test]
fn should_parse_unknown_version1() {
    let inputs = [
        "PROXY UNKNOWN 255.255.255.255 255.255.255.255 65535 65535\r\n",
        "PROXY UNKNOWN 255.255.255.255 255.255.255.255 65535 \r\n",
        "PROXY UNKNOWN 255.255.255.255 255.255.255.255 \r\n",
        "PROXY UNKNOWN 255.255.255.255 \r\n",
        "PROXY UNKNOWN  \r\n",
        "PROXY UNKNOWN\r\n",
    ];

    for input in inputs {
        let result = match parse(input.as_bytes()) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{input:?}' but got error: {error}"),
        };
        assert_eq!(result.len, input.len());
        let info = result.info;
        assert!(info.is_none(), "info should be None but got {info:#?}");
        assert_eq!(result.version, ProxyVersion::V1);
    }
}

#[test]
fn should_handle_error_version1() {
    let inputs = [
        ("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535 1\r\n", ParseError::InvalidProxy1Overflow),
        ("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65539\r\n", ParseError::InvalidDstPort),
        ("PROXY TCP4 255.255.255.255 255.255.255.255 65535 -\r\n", ParseError::InvalidDstPort),
        ("PROXY TCP4 255.255.255.255 255.255.255.255 65539 \r\n", ParseError::InvalidSrcPort),
        ("PROXY TCP4 255.255.255.255 255.255.255.255 - \r\n", ParseError::InvalidSrcPort),
        ("PROXY TCP4 255.255.255.255 255.255.255.256 \r\n", ParseError::InvalidDstIpv4),
        ("PROXY TCP4 255.255.255.255 ::1 \r\n", ParseError::InvalidDstIpv4),
        ("PROXY TCP4 ::1 \r\n", ParseError::InvalidSrcIpv4),
        ("PROXY TCP5 ::1 \r\n", ParseError::InvalidTransport),

        ("PROXY TCP6 ::1 ::1 65535 65535 1\r\n", ParseError::InvalidProxy1Overflow),
        ("PROXY TCP6 ::1 ::1 65535 65539\r\n", ParseError::InvalidDstPort),
        ("PROXY TCP6 ::1 ::1 65535 -\r\n", ParseError::InvalidDstPort),
        ("PROXY TCP6 ::1 ::1 65539 \r\n", ParseError::InvalidSrcPort),
        ("PROXY TCP6 ::1 ::1 - \r\n", ParseError::InvalidSrcPort),
        ("PROXY TCP6 ::1 ::: \r\n", ParseError::InvalidDstIpv6),
        ("PROXY TCP6 ::1 - \r\n", ParseError::InvalidDstIpv6),
        ("PROXY TCP6 ::1: \r\n", ParseError::InvalidSrcIpv6),
        ("PROXY TCP6 - \r\n", ParseError::InvalidSrcIpv6),

        ("PROXY UNKNOWN ::1 ::1 65535 65539 OVERFLOW\r\n", ParseError::InvalidProxy1Overflow),
        ("PROX", ParseError::Incomplete),
        ("PROXGGGGGG", ParseError::InvalidProxySig),
    ];

    for (input, expected_error) in inputs {
        match parse_v1(input.as_bytes()) {
            Ok(result) => panic!("Should not parse {input:?}, but successfully got {result:?}"),
            Err(error) => assert_eq!(error, expected_error, "{input:?} should return {expected_error} but got {error}"),
        };
    }
}

#[test]
fn should_parse_valid_version2() {
    let tcp4 = [
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10,
        //command + family
        33, 17,
        //len
        0, 12,
        //src
        255, 255, 255, 255,
        //dst
        127, 0, 0, 1,
        //src port 443
        1, 187,
        //dst port
        255, 255
    ];
    let mut udp4 = tcp4;
    udp4[13] += 1;

    let tcp6 = [
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10,
        //command + family
        33, 33,
        //len
        0, 36,
        //src
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        //dst
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        //src port 443
        1, 187,
        //dst port
        255, 255
    ];
    let mut udp6 = tcp6;
    udp6[13] += 1;

    let src_path = UnixAddr::new_str("/tmp/src");
    let dst_path = UnixAddr::new_str("/tmp/dst");

    let mut unix_stream = Vec::new();
    unix_stream.extend_from_slice(&[13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10]);
    //command + family
    unix_stream.extend_from_slice(&[33, 49]);
    //len
    let payload_len = src_path.raw().len() + dst_path.raw().len();
    unix_stream.extend_from_slice(&(payload_len as u16).to_be_bytes());
    unix_stream.extend_from_slice(src_path.raw());
    unix_stream.extend_from_slice(dst_path.raw());

    let mut unix_datagram = unix_stream.clone();
    unix_datagram[13] += 1;

    let inputs = [
        (tcp4.as_slice(), TransportProtocol::Stream, Proxy { src: create_v4_addr(255, 255, 255, 255, 443), dst: create_v4_addr(127, 0, 0, 1, 65535)  }),
        (udp4.as_slice(), TransportProtocol::Datagram, Proxy { src: create_v4_addr(255, 255, 255, 255, 443), dst: create_v4_addr(127, 0, 0, 1, 65535)  }),
        (tcp6.as_slice(), TransportProtocol::Stream, Proxy { src: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 443), dst: create_v6_addr("::1", 65535)  }),
        (udp6.as_slice(), TransportProtocol::Datagram, Proxy { src: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 443), dst: create_v6_addr("::1", 65535)  }),
        (unix_stream.as_slice(), TransportProtocol::Stream, Proxy { src: src_path.into(), dst: dst_path.into()  }),
    ];

    for (input, expected_transport, expected_info) in inputs {
        let result = match parse(input) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{input:?}' but got error: {error}"),
        };
        match result.version {
            ProxyVersion::V2 { transport } => {
                assert_eq!(transport, expected_transport, "{input:?}: Unexpected transport");
            },
            unexpected_version => panic!("{input:?}: Expected v2 but got {unexpected_version:?}"),
        }
        assert_eq!(result.len, input.len());
        let info = result.info.unwrap();
        assert_eq!(result.info.unwrap(), expected_info, "Expected {expected_info:#?} but got {info:#?}");
    }
}
