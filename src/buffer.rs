use crate::{v1, v2, tlv, ProxyParseResult};
use crate::error::ParseError;
use core::{slice, mem, fmt, ptr};

#[derive(Copy, Clone)]
///Static buffer suitable to hold unparsed proxy version input
pub struct Buffer<const N: usize> {
    inner: [mem::MaybeUninit<u8>; N],
    len: u16,
    offset: u16,
}

impl Buffer<{v1::Proxy::MAX_LEN}> {
    #[inline(always)]
    ///Creates new buffer with enough space for [v1] proxy version
    pub const fn new_v1() -> Self {
        Self::new()
    }
}

impl Buffer<{v2::Proxy::MAX_IP_LEN}> {
    #[inline(always)]
    ///Creates new buffer with enough space for [v2] proxy version with IP addresses
    pub const fn new_v2_ip() -> Self {
        Self::new()
    }
}

impl Buffer<{v2::Proxy::MAX_LEN}> {
    #[inline(always)]
    ///Creates new buffer with enough space for all possible [v2] proxy version
    pub const fn new_v2() -> Self {
        Self::new()
    }
}

impl<const N: usize> Buffer<N> {
    const LEN_LIMIT: () = {
        if N > u16::MAX as usize {
            panic!("Buffer capacity should not exceed u16::MAX");
        }
    };

    const LEN_FIT_V1: () = {
        if N < v1::Proxy::MAX_LEN {
            panic!("Buffer capacity should be enough to hold v1::Proxy::MAX_LEN");
        }
    };

    const LEN_FIT_V2: () = {
        if N < v2::Proxy::MAX_IP_LEN {
            panic!("Buffer capacity should be enough to hold v1::Proxy::MAX_IP_LEN");
        }
    };

    #[inline(always)]
    ///Creates new buffer
    pub const fn new() -> Self {
        let _ = Self::LEN_LIMIT;
        Self {
            inner: [mem::MaybeUninit::uninit(); N],
            len: 0,
            offset: 0
        }
    }

    #[inline(always)]
    ///Return spare capacity size
    pub const fn remaining(&self) -> usize {
        N - (self.offset + self.len) as usize
    }

    #[inline(always)]
    ///Return buffer's current length
    pub const fn len(&self) -> usize {
        self.len as _
    }

    #[inline(always)]
    ///Returns pointer to buffer data
    pub const fn as_ptr(&self) -> *const u8 {
        unsafe {
            self.inner.as_ptr().add(self.offset as _) as _
        }
    }

    #[inline(always)]
    ///Returns available bytes
    pub const fn as_slice(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.as_ptr(), self.len as _)
        }
    }

    #[inline(always)]
    ///Returns unwritten part of the buffer
    pub const fn spare_capacity_mut(&mut self) -> &mut [mem::MaybeUninit<u8>] {
        let offset = self.offset + self.len;
        unsafe {
            slice::from_raw_parts_mut(self.inner.as_mut_ptr().add(offset as _), N - offset as usize)
        }
    }

    #[inline(always)]
    ///Clears buffer
    pub const fn clear(&mut self) {
        self.len = 0;
        self.offset = 0;
    }

    #[inline(always)]
    ///Explicitly set length
    pub const unsafe fn set_len(&mut self, len: u16) {
        assert!(N >= len as _, "len cannot be greater than buffer capacity");
        self.len = len;
    }

    #[inline(always)]
    ///Explicitly set number of bytes consumed, adjusting slice returned by `as_slice` not to include bytes before `offset`
    pub const fn set_offset(&mut self, offset: u16) {
        assert!(offset <= self.len as _, "offset cannot be greater than buffer length");
        self.offset = offset;
        self.len = self.len - offset;
    }

    ///Extend the buffer by copying bytes from `src`
    ///
    ///Returns number of bytes copied which is always in range of `0..=src.len()`
    ///
    ///If `0` is returned then you exceeded buffer capacity and no longer able to write unless you clear buffer
    pub const fn extend_from_slice(&mut self, src: &[u8]) -> usize {
        let mut len = src.len();
        let spare_capacity_mut = self.spare_capacity_mut();
        if spare_capacity_mut.len() < len {
            len = spare_capacity_mut.len();
        }
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), spare_capacity_mut.as_mut_ptr() as _, len);
        }
        self.len = self.len + len as u16;

        len
    }

    ///Parses available data, modifying internal offset on success based on [v1::ProxyParseResult::len]
    ///
    ///Requires that buffer size is at least [v1::Proxy::MAX_LEN]
    pub fn parse_v1(&mut self) -> Result<v1::ProxyParseResult, ParseError> {
        let _ = Self::LEN_FIT_V1;

        match v1::parse(self.as_slice()) {
            Ok(result) => {
                self.set_offset(self.offset + result.len as u16);
                Ok(result)
            },
            Err(error) => Err(error),
        }
    }

    ///Parses available data, modifying internal offset on success based on [v2::ProxyParseResult::len]
    ///
    ///Requires that buffer size is at least [v2::Proxy::MAX_LEN]
    pub fn parse_v2(&mut self) -> Result<(v2::ProxyParseResult, Option<tlv::TlvsSlice<'_>>), ParseError> {
        let _ = Self::LEN_FIT_V2;

        let data = unsafe {
            slice::from_raw_parts(self.as_ptr(), self.len as _)
        };
        match v2::parse(data) {
            Ok(result) => {
                self.set_offset(self.offset + result.0.len as u16);
                Ok(result)
            },
            Err(error) => Err(error),
        }
    }

    ///Parses available data, modifying internal offset on success based on [ProxyParseResult::len]
    pub fn parse(&mut self) -> Result<ProxyParseResult<'_>, ParseError> {
        let _ = Self::LEN_FIT_V1;

        let data = unsafe {
            slice::from_raw_parts(self.as_ptr(), self.len as _)
        };
        match crate::parse(data) {
            Ok(result) => {
                self.set_offset(self.offset + result.len() as u16);
                Ok(result)
            },
            Err(error) => Err(error),
        }
    }
}

impl<const N: usize> PartialEq for Buffer<N> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> Eq for Buffer<N> {
}

impl<const N: usize> fmt::Debug for Buffer<N> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), fmt)
    }
}
