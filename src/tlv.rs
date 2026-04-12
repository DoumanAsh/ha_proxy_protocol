//!TLV module
use core::{mem, fmt};

use crate::utils::BufSlice;
use crate::utils::{unlikely, get_aligned_chunk_ref, try_get_aligned_chunk_ref};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
///Client bit field indicating TLS connection properties
pub struct SslClient(pub u8);

impl SslClient {
    #[inline(always)]
    ///Checks if `bit` is set
    pub const fn get(&self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    ///Indicates client connected over SSL/TLS
    ///
    ///Corresponding to PP2_CLIENT_SSL flag in protocol description
    pub const fn is_ssl(&self) -> bool {
        self.get(0x01)
    }

    ///Indicates client provided certificate for current SSL/TLS connection
    ///
    ///Corresponding to PP2_CLIENT_CERT_CONN flag in protocol description
    pub const fn is_cert_conn(&self) -> bool {
        self.get(0x02)
    }

    ///Indicates client provided certificate for duration SSL/TLS session (aka across multiple connections)
    ///
    ///Corresponding to PP2_CLIENT_CERT_SESS flag in protocol description
    pub const fn is_cert_session(&self) -> bool {
        self.get(0x04)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
///SSL information within TLV
pub struct TlvSslInfo<'a> {
    ///Bit field describing [TlvSslInfo] content
    pub client: SslClient,
    ///Indicates whether client presented certificate and successfully verified it
    pub is_verified: bool,
    ///Raw TLV within [TlvSslInfo]
    pub payload: &'a [u8]
}

impl<'a> TlvSslInfo<'a> {
    #[inline(always)]
    ///Creates iterator [TlvSslIter]
    pub const fn iter(&self) -> TlvSslIter<'a> {
        TlvSslIter::new(self)
    }
}

impl<'a> IntoIterator for TlvSslInfo<'a> {
    type Item = Result<TlvSsl<'a>, TlvError>;
    type IntoIter = TlvSslIter<'a>;
    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
///TLV value within [TlvSslInfo]
pub enum TlvSsl<'a> {
    ///Reference to byte string within buffer with SSL version identifier
    Version(BufSlice<'a>),
    ///Reference to byte string within buffer with CN identifier
    Cn(BufSlice<'a>),
    ///Reference to byte string within buffer with Cipher identifier
    Cipher(BufSlice<'a>),
    ///Reference to byte string within buffer with Algorithm identifier used to sign client's certificate
    SigAlg(BufSlice<'a>),
    ///Reference to byte string within buffer with Algorithm identifier used to generate key of client's certificate
    KeyALg(BufSlice<'a>),
    ///Reference to byte string within buffer with Key Exchange Algorithm identifier used to establish client's connection
    Group(BufSlice<'a>),
    ///Reference to byte string within buffer with Algorithm identifier used to sign ServerKeyExchange or CertificateVerify message
    SigSheme(BufSlice<'a>),
    ///Reference to DER encoded client's certificate
    ClientCert(&'a [u8]),
}

///Iterator over [TlvSslInfo] payload
pub struct TlvSslIter<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> TlvSslIter<'a> {
    #[inline(always)]
    ///Creates iterator instance out of [TlvSslInfo]
    pub const fn new(tlv_ssl: &TlvSslInfo<'a>) -> Self {
        Self {
            buf: tlv_ssl.payload,
            offset: 0,
        }
    }
}

impl<'a> Iterator for TlvSslIter<'a> {
    type Item = Result<TlvSsl<'a>, TlvError>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        while self.buf.len() > self.offset {
            //TLV always have 3 bytes for type + length
            let tlv_header = match try_get_aligned_chunk_ref::<[u8; 3]>(self.buf, self.offset) {
                Some(header) => header,
                None => return Some(Err(unlikely(TlvError::new_malformed(self.offset))))
            };

            let tlv_type = tlv_header[0];
            let tlv_length = u16::from_be_bytes([tlv_header[1], tlv_header[2]]);

            let tlv_value_offset = self.offset + tlv_header.len();
            let tlv_value = match self.buf.get(tlv_value_offset..tlv_value_offset+tlv_length as usize) {
                Some(value) => value,
                None => return Some(Err(unlikely(TlvError::new_malformed(self.offset))))
            };

            self.offset = tlv_value_offset + tlv_value.len();

            match tlv_type {
                0x21 => return Some(Ok(TlvSsl::Version(BufSlice(tlv_value)))),
                0x22 => return Some(Ok(TlvSsl::Cn(BufSlice(tlv_value)))),
                0x23 => return Some(Ok(TlvSsl::Cipher(BufSlice(tlv_value)))),
                0x24 => return Some(Ok(TlvSsl::SigAlg(BufSlice(tlv_value)))),
                0x25 => return Some(Ok(TlvSsl::KeyALg(BufSlice(tlv_value)))),
                0x26 => return Some(Ok(TlvSsl::Group(BufSlice(tlv_value)))),
                0x27 => return Some(Ok(TlvSsl::SigSheme(BufSlice(tlv_value)))),
                0x28 => return Some(Ok(TlvSsl::ClientCert(tlv_value))),
                _ => continue
            }
        }

        None
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
///Possible parsing errors
enum TlvErrorKind {
    ///Indicates corrupted TLV payload.
    MalformedTlv,
    ///Checksum is not valid within TLV
    MalformedChecksum
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
///Possible errors parsing TLV
pub struct TlvError {
    ///Offset where error occurred
    pub offset: usize,
    kind: TlvErrorKind,
}

impl TlvError {
    fn new_malformed(offset: usize) -> Self {
        Self {
            offset,
            kind: TlvErrorKind::MalformedTlv,
        }
    }

    fn new_malformed_checksum(offset: usize) -> Self {
        Self {
            offset,
            kind: TlvErrorKind::MalformedChecksum,
        }
    }

}

impl fmt::Display for TlvError {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { offset, kind } = self;
        match kind {
            TlvErrorKind::MalformedTlv => fmt.write_fmt(format_args!("Malformed TLV payload at offset {offset}")),
            TlvErrorKind::MalformedChecksum => fmt.write_fmt(format_args!("Malformed checksum at offset {offset}")),
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
///Possible TLV values
pub enum Tlv<'a> {
    ///Reference to byte string within buffer with ALPN identifier
    Alpn(BufSlice<'a>),
    ///Reference to byte string within buffer with Authority text
    Authority(BufSlice<'a>),
    ///Checksum of the `tlv_payload` with crc bytes zeroed
    Crc32c(TlvCrc32),
    ///Reference to unique identifier as arbitrary bytes up to 128 in length
    UniqueId(&'a [u8]),
    ///SSL information associated with the connection
    Ssl(TlvSslInfo<'a>),
    ///Reference to byte string within buffer with network namespace
    Netns(BufSlice<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///Reference to TLV payload
pub struct TlvsSlice<'a>(&'a [u8]);

impl<'a> TlvsSlice<'a> {
    #[inline(always)]
    ///Creates new instance checking if `bytes` is empty or not
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty() {
            None
        } else {
            Some(Self(bytes))
        }
    }

    #[inline(always)]
    ///Access raw bytes
    pub const fn raw(&self) -> &'a [u8] {
        self.0
    }

    #[inline(always)]
    ///Access iterator
    pub const fn iter(&self) -> TlvsIter<'a> {
        TlvsIter::new(self)
    }
}

impl<'a> IntoIterator for TlvsSlice<'a> {
    type Item = Result<Tlv<'a>, TlvError>;
    type IntoIter = TlvsIter<'a>;

    #[inline(always)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

///Iterator over [TlvsSlice] returning [Tlv] while skipping unknown values
pub struct TlvsIter<'a> {
    buf: &'a [u8],
    offset: usize
}

impl<'a> TlvsIter<'a> {
    #[inline(always)]
    ///Creates new instance
    pub const fn new(tlvs: &TlvsSlice<'a>) -> Self {
        Self {
            buf: tlvs.0,
            offset: 0,
        }
    }
}

impl<'a> Iterator for TlvsIter<'a> {
    type Item = Result<Tlv<'a>, TlvError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while self.buf.len() > self.offset {
            //TLV always have 3 bytes for type + length
            let tlv_header = match try_get_aligned_chunk_ref::<[u8; 3]>(self.buf, self.offset) {
                Some(header) => header,
                None => return Some(Err(unlikely(TlvError::new_malformed(self.offset))))
            };

            let tlv_type = tlv_header[0];
            let tlv_length = u16::from_be_bytes([tlv_header[1], tlv_header[2]]);

            let tlv_value_offset = self.offset + tlv_header.len();
            let tlv_value = match self.buf.get(tlv_value_offset..tlv_value_offset+tlv_length as usize) {
                Some(value) => value,
                None => return Some(Err(unlikely(TlvError::new_malformed(self.offset))))
            };

            self.offset = tlv_value_offset + tlv_value.len();

            match tlv_type {
                //PP2_TYPE_ALPN
                0x01 => return Some(Ok(Tlv::Alpn(BufSlice(tlv_value)))),
                //PP2_TYPE_AUTHORITY
                0x02 => return Some(Ok(Tlv::Authority(BufSlice(tlv_value)))),
                //PP2_TYPE_CRC32C
                0x03 => {
                    if tlv_value.len() != 4 {
                        return Some(Err(unlikely(TlvError::new_malformed_checksum(tlv_value_offset))))
                    }
                    let crc32_bytes = get_aligned_chunk_ref(tlv_value, 0);
                    let checksum = u32::from_be_bytes(*crc32_bytes);
                    return Some(Ok(Tlv::Crc32c(TlvCrc32 {
                        checksum,
                        checksum_start: tlv_value_offset
                    })))
                },

                //PP2_TYPE_NOOP can be skipped
                //0x04

                //PP2_TYPE_UNIQUE_ID
                0x05 => {
                    if tlv_value.len() >= 128 {
                        return Some(Err(unlikely(TlvError::new_malformed(tlv_value_offset))))
                    }
                    return Some(Ok(Tlv::UniqueId(tlv_value)));
                },

                //PP2_TYPE_SSL
                0x20 => {
                    //You need at lest client(u8) and verify(u32) fields for correct ssl info
                    if tlv_value.len() < 5 {
                        return Some(Err(unlikely(TlvError::new_malformed(tlv_value_offset))))
                    } else {
                        let client: SslClient = *get_aligned_chunk_ref(tlv_value, 0);
                        let verify = u32::from_be_bytes(*get_aligned_chunk_ref(tlv_value, mem::size_of_val(&client)));
                        return Some(Ok(Tlv::Ssl(TlvSslInfo {
                            client,
                            is_verified: verify == 0,
                            payload: &tlv_value[5..],
                        })));
                    }
                },

                //PP2_TYPE_NETNS
                0x30 => return Some(Ok(Tlv::Netns(BufSlice(tlv_value)))),
                _ => continue,
            }
        } //while payload

        None
    }
}
