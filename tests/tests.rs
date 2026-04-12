use core::net;

use ha_proxy_protocol::{v1, v2, tlv, parse};
use ha_proxy_protocol::{UnixAddr, ParseError, ProxyParseResult};

fn create_v4_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> net::SocketAddr {
    net::SocketAddrV4::new(net::Ipv4Addr::new(a, b, c, d), port).into()
}

fn create_v6_addr(text: &str, port: u16) -> net::SocketAddr {
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
        ("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n", v1::Proxy { src: create_v4_addr(255, 255, 255, 255, 65535), dst: create_v4_addr(255, 255, 255, 255, 65535)  }),
        ("PROXY TCP4 127.0.0.1 255.255.255.255 80 65535\r\n", v1::Proxy { src: create_v4_addr(127, 0, 0, 1, 80), dst: create_v4_addr(255, 255, 255, 255, 65535)  }),
        ("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n", v1::Proxy { src: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535), dst: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535)  }),
        ("PROXY TCP6 ::1 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 80 65535\r\n", v1::Proxy { src: create_v6_addr("::1", 80), dst: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535)  }),
    ];

    for (input, expected_info) in inputs {
        let result = match parse(input.as_bytes()) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{input:?}' but got error: {error}"),
        };
        let result = match result {
            ProxyParseResult::V1(result) => result,
            unexpected => panic!("expected v1 but got {unexpected:#?}"),
        };
        assert_eq!(result.len, input.len());
        let info = result.info.unwrap();
        assert_eq!(result.info.unwrap(), expected_info, "Expected {expected_info:#?} but got {info:#?}");
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
        let result = match result {
            ProxyParseResult::V1(result) => result,
            unexpected => panic!("expected v1 but got {unexpected:#?}"),
        };

        assert_eq!(result.len, input.len());
        let info = result.info;
        assert!(info.is_none(), "info should be None but got {info:#?}");
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
        match v1::parse(input.as_bytes()) {
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
        (tcp4.as_slice(), v2::TransportProtocol::Stream, v2::Proxy { src: create_v4_addr(255, 255, 255, 255, 443).into(), dst: create_v4_addr(127, 0, 0, 1, 65535).into() }),
        (udp4.as_slice(), v2::TransportProtocol::Datagram, v2::Proxy { src: create_v4_addr(255, 255, 255, 255, 443).into(), dst: create_v4_addr(127, 0, 0, 1, 65535).into()  }),
        (tcp6.as_slice(), v2::TransportProtocol::Stream, v2::Proxy { src: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 443).into(), dst: create_v6_addr("::1", 65535).into() }),
        (udp6.as_slice(), v2::TransportProtocol::Datagram, v2::Proxy { src: create_v6_addr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 443).into(), dst: create_v6_addr("::1", 65535).into() }),
        (unix_stream.as_slice(), v2::TransportProtocol::Stream, v2::Proxy { src: src_path.into(), dst: dst_path.into()  }),
        (unix_datagram.as_slice(), v2::TransportProtocol::Datagram, v2::Proxy { src: src_path.into(), dst: dst_path.into()  }),
    ];

    for (input, expected_transport, expected_info) in inputs {
        let result = match parse(input) {
            Ok(result) => result,
            Err(error) => panic!("Should parse '{input:?}' but got error: {error}"),
        };
        let result = match result {
            ProxyParseResult::V2(result, tlvs) => {
                assert!(tlvs.is_none(), "Should have no TLVS");
                result
            },
            unexpected => panic!("expected v2 but got {unexpected:#?}"),
        };

        assert_eq!(result.protocol, expected_transport, "{input:?}: Unexpected transport");
        assert_eq!(result.len, input.len());
        let info = result.info.unwrap();
        assert_eq!(result.info.unwrap(), expected_info, "Expected {expected_info:#?} but got {info:#?}");
    }
}

#[test]
fn should_parse_invalid_version2() {
    let wrong_family_v6 = [
        13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10,
        //command + family
        33, 33,
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

    let inputs = [
        (wrong_family_v6.as_slice(), ParseError::InvalidTransportSize)
    ];

    for (input, expected_error) in inputs {
        match v2::parse(input) {
            Ok(result) => panic!("Should fail to parse '{input:?}' but got success: {result:#?}"),
            Err(error) => assert_eq!(error, expected_error),
        }
    }
}

fn build_base_proxy_version2(tlv_type: u8, tlv_bytes: &[u8]) -> Vec<u8> {
    let len = 12 + 3 + tlv_bytes.len();
    let len_bytes = (len as u16).to_be_bytes();
    let mut out = [
        13u8, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10,
        //command + family
        33, 17,
        //len
        len_bytes[0], len_bytes[1],
        //src
        255, 255, 255, 255,
        //dst
        127, 0, 0, 1,
        //src port 443
        1, 187,
        //dst port
        255, 255
    ].to_vec();

    out.push(tlv_type);
    let len = tlv_bytes.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(tlv_bytes);
    out
}

#[test]
fn should_parse_tlv_alpn_version2() {
    let expected_alpn = "http/1.1";

    let input = build_base_proxy_version2(0x01, expected_alpn.as_bytes());
    let (_, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let mut tlv_iter = tlv.iter();
    let alpn = tlv_iter.next().unwrap().expect("parse alpn");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after ALPN, but got {missing:?}");

    match alpn {
        tlv::Tlv::Alpn(bytes) => {
            let alpn = bytes.to_str().expect("should be valid string");
            assert_eq!(alpn, expected_alpn);
        },
        unexpected => panic!("Expected Alpn but got {unexpected:?}"),
    }
}

#[test]
fn should_parse_tlv_authority_version2() {
    let expected_authority = "test.com";

    let input = build_base_proxy_version2(0x02, expected_authority.as_bytes());
    let (_, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse authority");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after authority, but got {missing:?}");

    match tlv {
        tlv::Tlv::Authority(bytes) => {
            let tlv = bytes.to_str().expect("should be valid string");
            assert_eq!(tlv, expected_authority);
        },
        unexpected => panic!("Expected Authority but got {unexpected:?}"),
    }
}

#[test]
fn should_parse_tlv_unique_id_version2() {
    let expected_unique_id = b"123451234659";

    let input = build_base_proxy_version2(0x05, expected_unique_id.as_slice());
    let (_, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse unique id");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after unique id, but got {missing:?}");

    match tlv {
        tlv::Tlv::UniqueId(tlv) => {
            assert_eq!(tlv, expected_unique_id);
        },
        unexpected => panic!("Expected unique id but got {unexpected:?}"),
    }
}

#[test]
fn should_parse_tlv_netns_version2() {
    let expected_netns = "netns/example";

    let input = build_base_proxy_version2(0x30, expected_netns.as_bytes());
    let (_, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse netns");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after netns, but got {missing:?}");

    match tlv {
        tlv::Tlv::Netns(bytes) => {
            let tlv = bytes.to_str().expect("should be valid string");
            assert_eq!(tlv, expected_netns);
        },
        unexpected => panic!("Expected Netns but got {unexpected:?}"),
    }
}

#[test]
fn should_parse_tlv_noop_version2() {
    let input = build_base_proxy_version2(0x04, [0, 0, 0].as_slice());
    let (_, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let mut tlv_iter = tlv.iter();
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after NOOP, but got {missing:?}");
}
