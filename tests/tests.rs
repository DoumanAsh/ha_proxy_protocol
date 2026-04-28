use core::net;

use ha_proxy_protocol::{v1, v2, tlv, parse};
use ha_proxy_protocol::{UnixAddr, ParseError, ProxyParseResult, Buffer};

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

    let mut buffer = Buffer::new_v1();
    for (input, expected_info) in inputs {
        assert_eq!(buffer.extend_from_slice(input.as_bytes()), input.len());

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
        //Check fmt without line ending
        assert_eq!(input[..input.len()-2], expected_info.to_string());

        let v1_result = buffer.parse_v1().expect("to parse v1");
        assert_eq!(result, v1_result);

        assert_eq!(buffer.as_slice().len(), 0);

        buffer.clear();
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

    let mut buffer = Buffer::new_v1();
    for (input, expected_error) in inputs {
        assert_eq!(buffer.extend_from_slice(input.as_bytes()), input.len());

        match buffer.parse_v1() {
            Ok(result) => panic!("Should not parse {input:?}, but successfully got {result:?}"),
            Err(error) => assert_eq!(error, expected_error, "{input:?} should return {expected_error} but got {error}"),
        };

        //error will not reset buffer as we cannot know when to finish
        assert_eq!(buffer.as_slice(), input.as_bytes());
        buffer.clear();
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

    let mut buffer = Buffer::new_v2();
    let mut temp_buf = [0; 256];
    for (input, expected_transport, expected_info) in inputs {
        assert_eq!(buffer.extend_from_slice(input), input.len());

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
        assert_eq!(info, expected_info, "Expected {expected_info:#?} but got {info:#?}");
        let len = info.encode(expected_transport, &mut temp_buf);
        assert_eq!(result.len, len);
        assert_eq!(temp_buf[..len], *input, "Encoding should producing equivalent output to input: {expected_transport:?} {expected_info:#?}");

        let (v2_proxy, tlv) = buffer.parse_v2().expect("to parse v2");
        assert!(tlv.is_none());
        assert_eq!(v2_proxy, result);

        buffer.clear();
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

    let mut buffer = Buffer::new_v2_ip();
    for (input, expected_error) in inputs {
        assert_eq!(buffer.extend_from_slice(input), input.len());

        match buffer.parse_v2() {
            Ok(result) => panic!("Should fail to parse '{input:?}' but got success: {result:#?}"),
            Err(error) => assert_eq!(error, expected_error),
        }

        assert_eq!(buffer.as_slice(), input);
        buffer.clear();
    }
}

fn build_base_proxy_version2(tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let len =  tlvs.iter().fold(12usize, |acc, (_, value)| acc + 3 + value.len());
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

    for (tlv_type, tlv_bytes) in tlvs {
        out.push(*tlv_type);
        let len = tlv_bytes.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(tlv_bytes);
    }
    out
}

#[test]
fn should_parse_tlv_alpn_version2() {
    let expected_alpn = "http/1.1";

    let input = build_base_proxy_version2(&[(0x04, [0, 0, 0].as_slice()), (0x04, [0, 0, 0].as_slice()), (0x01, expected_alpn.as_bytes())]);
    let (proxy, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let tlv_raw = tlv.raw();
    let mut tlv_iter = tlv.iter();
    let alpn = tlv_iter.next().unwrap().expect("parse alpn");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after ALPN, but got {missing:?}");

    assert_eq!(alpn.required_buffer_size(), 3 + expected_alpn.len());
    let mut insufficient_buffer = [0; 10];
    let mut encoded_buffer = [0; 256];
    assert_eq!(alpn.encode(&mut insufficient_buffer), 0);
    assert_eq!(alpn.encode(&mut encoded_buffer), 11);
    //skip NOOP
    assert_eq!(encoded_buffer[..11], tlv_raw[12..]);

    match alpn {
        tlv::Tlv::Alpn(bytes) => {
            let alpn = bytes.to_str().expect("should be valid string");
            assert_eq!(alpn, expected_alpn);
        },
        unexpected => panic!("Expected Alpn but got {unexpected:?}"),
    }

    //Ensure we can encode it correctly
    let proxy_info = proxy.info.unwrap();
    assert_eq!(proxy_info.encode_with_tlv(v2::TransportProtocol::Datagram, &mut encoded_buffer, [alpn].into_iter()), proxy_info.required_buffer_size() + alpn.required_buffer_size());
    let (encoded_proxy, encoded_tlv) = v2::parse(&encoded_buffer[..proxy_info.required_buffer_size() + alpn.required_buffer_size()]).expect("to parse");
    assert_eq!(encoded_proxy.protocol, v2::TransportProtocol::Datagram);
    assert_eq!(encoded_proxy.info, Some(proxy_info));
    let encoded_tlv = encoded_tlv.expect("to have tlv");
    let mut encoded_tlvs = encoded_tlv.iter();
    let encoded_tlv = encoded_tlvs.next().expect("to have tlv").expect("to parse tlv");
    assert!(encoded_tlvs.next().is_none());
    assert_eq!(encoded_tlv, alpn);
}

#[test]
fn should_parse_tlv_authority_version2() {
    let expected_authority = "test.com";

    let input = build_base_proxy_version2(&[(0x04, [0, 0, 0].as_slice()), (0x02, expected_authority.as_bytes())]);
    let (proxy, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let tlv_raw = tlv.raw();
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse authority");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after authority, but got {missing:?}");

    assert_eq!(tlv.required_buffer_size(), 3 + expected_authority.len());
    let mut insufficient_buffer = [0; 10];
    let mut encoded_buffer = [0; 256];
    assert_eq!(tlv.encode(&mut insufficient_buffer), 0);
    assert_eq!(tlv.encode(&mut encoded_buffer), 11);
    //skip NOOP
    assert_eq!(encoded_buffer[..11], tlv_raw[6..]);

    match tlv {
        tlv::Tlv::Authority(bytes) => {
            let tlv = bytes.to_str().expect("should be valid string");
            assert_eq!(tlv, expected_authority);
        },
        unexpected => panic!("Expected Authority but got {unexpected:?}"),
    }

    //Ensure we can encode it correctly
    let proxy_info = proxy.info.unwrap();
    assert_eq!(proxy_info.encode_with_tlv(v2::TransportProtocol::Datagram, &mut encoded_buffer, [tlv].into_iter()), proxy_info.required_buffer_size() + tlv.required_buffer_size());
    let (encoded_proxy, encoded_tlv) = v2::parse(&encoded_buffer[..proxy_info.required_buffer_size() + tlv.required_buffer_size()]).expect("to parse");
    assert_eq!(encoded_proxy.protocol, v2::TransportProtocol::Datagram);
    assert_eq!(encoded_proxy.info, Some(proxy_info));
    let encoded_tlv = encoded_tlv.expect("to have tlv");
    let mut encoded_tlvs = encoded_tlv.iter();
    let encoded_tlv = encoded_tlvs.next().expect("to have tlv").expect("to parse tlv");
    assert!(encoded_tlvs.next().is_none());
    assert_eq!(encoded_tlv, tlv);
}

#[test]
fn should_parse_tlv_unique_id_version2() {
    let expected_unique_id = b"123451234659";

    let input = build_base_proxy_version2(&[(0x04, [0, 0, 0].as_slice()), (0x05, expected_unique_id.as_slice())]);
    let (proxy, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let tlv_raw = tlv.raw();
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse unique id");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after unique id, but got {missing:?}");

    assert_eq!(tlv.required_buffer_size(), 3 + expected_unique_id.len());
    let mut insufficient_buffer = [0; 13];
    let mut encoded_buffer = [0; 256];
    assert_eq!(tlv.encode(&mut insufficient_buffer), 0);
    assert_eq!(tlv.encode(&mut encoded_buffer), 15);
    //skip NOOP
    assert_eq!(encoded_buffer[..15], tlv_raw[6..]);

    match tlv {
        tlv::Tlv::UniqueId(tlv) => {
            assert_eq!(tlv, expected_unique_id);
        },
        unexpected => panic!("Expected unique id but got {unexpected:?}"),
    }

    //Ensure we can encode it correctly
    let proxy_info = proxy.info.unwrap();
    assert_eq!(proxy_info.encode_with_tlv(v2::TransportProtocol::Datagram, &mut encoded_buffer, [tlv].into_iter()), proxy_info.required_buffer_size() + tlv.required_buffer_size());
    let (encoded_proxy, encoded_tlv) = v2::parse(&encoded_buffer[..proxy_info.required_buffer_size() + tlv.required_buffer_size()]).expect("to parse");
    assert_eq!(encoded_proxy.protocol, v2::TransportProtocol::Datagram);
    assert_eq!(encoded_proxy.info, Some(proxy_info));
    let encoded_tlv = encoded_tlv.expect("to have tlv");
    let mut encoded_tlvs = encoded_tlv.iter();
    let encoded_tlv = encoded_tlvs.next().expect("to have tlv").expect("to parse tlv");
    assert!(encoded_tlvs.next().is_none());
    assert_eq!(encoded_tlv, tlv);
}

#[test]
fn should_parse_tlv_netns_version2() {
    let expected_netns = "netns/example";

    let input = build_base_proxy_version2(&[(0x04, [0, 0, 0].as_slice()), (0x30, expected_netns.as_bytes())]);
    let (proxy, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let tlv_raw = tlv.raw();
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse netns");
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after netns, but got {missing:?}");

    assert_eq!(tlv.required_buffer_size(), 3 + expected_netns.len());
    let mut insufficient_buffer = [0; 13];
    let mut encoded_buffer = [0; 256];
    assert_eq!(tlv.encode(&mut insufficient_buffer), 0);
    assert_eq!(tlv.encode(&mut encoded_buffer), 16);
    //skip NOOP
    assert_eq!(encoded_buffer[..16], tlv_raw[6..]);

    match tlv {
        tlv::Tlv::Netns(bytes) => {
            let tlv = bytes.to_str().expect("should be valid string");
            assert_eq!(tlv, expected_netns);
        },
        unexpected => panic!("Expected Netns but got {unexpected:?}"),
    }

    //Ensure we can encode it correctly
    let proxy_info = proxy.info.unwrap();
    assert_eq!(proxy_info.encode_with_tlv(v2::TransportProtocol::Datagram, &mut encoded_buffer, [tlv].into_iter()), proxy_info.required_buffer_size() + tlv.required_buffer_size());
    let (encoded_proxy, encoded_tlv) = v2::parse(&encoded_buffer[..proxy_info.required_buffer_size() + tlv.required_buffer_size()]).expect("to parse");
    assert_eq!(encoded_proxy.protocol, v2::TransportProtocol::Datagram);
    assert_eq!(encoded_proxy.info, Some(proxy_info));
    let encoded_tlv = encoded_tlv.expect("to have tlv");
    let mut encoded_tlvs = encoded_tlv.iter();
    let encoded_tlv = encoded_tlvs.next().expect("to have tlv").expect("to parse tlv");
    assert!(encoded_tlvs.next().is_none());
    assert_eq!(encoded_tlv, tlv);
}

#[test]
fn should_parse_tlv_ssl_version2() {
    let tls_version = "TLSv1.3";
    let tls_cipher = "ECDHE-RSA-AES128-GCM-SHA256";
    let tls_sig_alg = "SHA256";
    let tls_key_alg = "RSA4096";
    let tls_cn = "hostname.com";

    let verify = 0u32.to_be_bytes();
    let mut expected_ssl = [
        0x01 | 0x02,
        verify[0], verify[1], verify[2], verify[3],
    ].to_vec();

    let tlvs = [
        (0x21, tls_version),
        (0x22, tls_cn),
        (0x23, tls_cipher),
        (0x24, tls_sig_alg),
        (0x25, tls_key_alg),
    ];
    for (tlv_type, tlv_value) in tlvs {
        expected_ssl.push(tlv_type);
        let len = (tlv_value.len() as u16).to_be_bytes();
        expected_ssl.extend_from_slice(&len);
        expected_ssl.extend_from_slice(tlv_value.as_bytes());
    }

    let input = build_base_proxy_version2(&[(0x04, [0, 0, 0].as_slice()), (0x20, expected_ssl.as_slice())]);
    let (proxy, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let tlv_payload = tlv.raw();
    assert_eq!(tlv_payload.len(), 88);
    let mut tlv_iter = tlv.iter();
    let tlv = tlv_iter.next().unwrap().expect("parse ssl info");
    let tlv_len = tlv.required_buffer_size();
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after ssl info, but got {missing:?}");

    assert_eq!(expected_ssl.len(), 79);
    assert_eq!(tlv_len, expected_ssl.len() + 3);
    let mut insufficient_buffer = [0; 81];
    let mut sufficient_buffer = [0; 256];

    assert_eq!(tlv.encode(&mut insufficient_buffer), 0);
    assert_eq!(tlv.encode(&mut sufficient_buffer), 82);
    //Skip NOOP
    assert_eq!(sufficient_buffer[..82], tlv_payload[6..]);

    let mut tlv_ssl_payload_len = 0;
    let tlv_ssl = match tlv {
        tlv_ssl @ tlv::Tlv::Ssl(info) => {
            assert!(info.client.is_ssl());
            assert!(info.client.is_cert_conn());
            assert!(!info.client.is_cert_session());

            for tlv in info {
                let tlv = tlv.expect("Parse tlv");
                let tlv_len = tlv.required_buffer_size();
                let buffer_len = match tlv {
                    tlv::TlvSsl::Cn(tlv) => {
                        let len = tlv.0.len();
                        let tlv = tlv.to_str().expect("CN must be string");
                        assert_eq!(tlv, tls_cn);
                        len
                    },
                    tlv::TlvSsl::Version(tlv) => {
                        let len = tlv.0.len();
                        let tlv = tlv.to_str().expect("Version must be string");
                        assert_eq!(tlv, tls_version);
                        len
                    },
                    tlv::TlvSsl::Cipher(tlv) => {
                        let len = tlv.0.len();
                        let tlv = tlv.to_str().expect("Cipher must be string");
                        assert_eq!(tlv, tls_cipher);
                        len
                    },
                    tlv::TlvSsl::SigAlg(tlv) => {
                        let len = tlv.0.len();
                        let tlv = tlv.to_str().expect("SigAlg must be string");
                        assert_eq!(tlv, tls_sig_alg);
                        len
                    },
                    tlv::TlvSsl::KeyALg(tlv) => {
                        let len = tlv.0.len();
                        let tlv = tlv.to_str().expect("KeyALg must be string");
                        assert_eq!(tlv, tls_key_alg);
                        len
                    },
                    unexpected => panic!("Unexpected SslTlv {unexpected:?}"),
                };
                tlv_ssl_payload_len += tlv_len;
                assert_eq!(tlv_len, buffer_len + 3);
            } //for tlv

            tlv_ssl
        },
        unexpected => panic!("Expected SslInfo but got {unexpected:?}"),
    }; // match tlv

    // payload + header(3) + SSL sub-tlv header(5)
    assert_eq!(tlv_len, tlv_ssl_payload_len + 8);
    let proxy_info = proxy.info.expect("to have proxy_info");

    //Ensure we can encode it correctly
    assert_eq!(proxy_info.encode_with_tlv(v2::TransportProtocol::Datagram, &mut sufficient_buffer, [tlv_ssl].into_iter()), proxy_info.required_buffer_size() + tlv_ssl.required_buffer_size());
    let (proxy, tlv) = v2::parse(&sufficient_buffer[..proxy_info.required_buffer_size() + tlv_ssl.required_buffer_size()]).expect("to parse");
    assert_eq!(proxy.protocol, v2::TransportProtocol::Datagram);
    assert_eq!(proxy.info, Some(proxy_info));
    let tlv = tlv.expect("to have tlv");
    let mut tlvs = tlv.iter();
    let encoded_tlv_ssl = tlvs.next().expect("to have tlv").expect("to parse tlv");
    assert!(tlvs.next().is_none());
    assert_eq!(encoded_tlv_ssl, tlv_ssl);
}

#[test]
fn should_parse_tlv_noop_version2() {
    let input = build_base_proxy_version2(&[(0x04, [0, 0, 0].as_slice())]);
    let (_, tlv) = v2::parse(&input).expect("to parse");
    let tlv = tlv.expect("TLS should be present");
    let mut tlv_iter = tlv.iter();
    let missing = tlv_iter.next();
    assert!(missing.is_none(), "No more TLV should be after NOOP, but got {missing:?}");
}

#[test]
fn should_verify_buffer_after_parse() {
    let input = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nHEAD / HTTP/1.1\r\nHost: host:port\r\nConnection: close\r\n\r\n";
    let expected_proxy = v1::Proxy { src: create_v4_addr(255, 255, 255, 255, 65535), dst: create_v4_addr(255, 255, 255, 255, 65535)  };

    let mut buffer = Buffer::<256>::new();
    assert_eq!(buffer.extend_from_slice(input.as_bytes()), input.len());

    let proxy = buffer.parse_v1().expect("to parse v1");
    let proxy = proxy.info.unwrap();
    assert_eq!(proxy, expected_proxy);

    let remaining = core::str::from_utf8(buffer.as_slice()).expect("valid utf-8");
    assert_eq!(remaining, "HEAD / HTTP/1.1\r\nHost: host:port\r\nConnection: close\r\n\r\n");

    assert_eq!(buffer.extend_from_slice("TEST".as_bytes()), 4);
    let remaining = core::str::from_utf8(buffer.as_slice()).expect("valid utf-8");
    assert_eq!(remaining, "HEAD / HTTP/1.1\r\nHost: host:port\r\nConnection: close\r\n\r\nTEST");

    buffer.clear();
    assert!(buffer.as_slice().is_empty());
}
#[test]
fn should_verify_buffer_after_overflow() {
    let input = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nHEAD / HTTP/1.1\r\nHost: host:port\r\nConnection: close\r\n\r\n";
    let expected_proxy = v1::Proxy { src: create_v4_addr(255, 255, 255, 255, 65535), dst: create_v4_addr(255, 255, 255, 255, 65535)  };

    let mut buffer = Buffer::<110>::new();
    assert_eq!(input.len(), 111);
    assert_eq!(buffer.extend_from_slice(input.as_bytes()), input.len() - 1);
    assert_eq!(buffer.remaining(), 0);

    let proxy = buffer.parse_v1().expect("to parse v1");
    let proxy = proxy.info.unwrap();
    assert_eq!(proxy, expected_proxy);

    let remaining = core::str::from_utf8(buffer.as_slice()).expect("valid utf-8");
    assert_eq!(remaining, "HEAD / HTTP/1.1\r\nHost: host:port\r\nConnection: close\r\n\r");

    assert_eq!(buffer.extend_from_slice(input.as_bytes()), 0);
    let remaining = core::str::from_utf8(buffer.as_slice()).expect("valid utf-8");
    assert_eq!(remaining, "HEAD / HTTP/1.1\r\nHost: host:port\r\nConnection: close\r\n\r");

    buffer.clear();
    assert!(buffer.as_slice().is_empty());
}
