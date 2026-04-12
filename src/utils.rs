use core::{fmt, mem, marker};

#[repr(transparent)]
pub struct Type<T>(marker::PhantomData<T>);

impl<T> Type<T> {
    ///Returns object size
    #[inline(always)]
    pub const fn size() -> usize {
        mem::size_of::<T>()
    }

    ///Returns minimum alignment
    #[inline(always)]
    pub const fn align() -> usize {
        mem::align_of::<T>()
    }

    #[inline(always)]
    ///Returns whether type is ZST
    pub const fn is_zst() -> bool {
        Self::size() == 0
    }
}

#[repr(transparent)]
pub struct Assert<T>(marker::PhantomData<T>);

impl<T> Assert<T> {
    pub const IS_NOT_ZST: () = assert!(!Type::<T>::is_zst());
}

#[repr(transparent)]
pub struct Assert2<L, R>(marker::PhantomData<(L, R)>);

impl<L, R> Assert2<L, R> {
    pub const IS_SAME_ALIGN: () = assert!(Type::<L>::align() == Type::<R>::align());
}

#[cold]
#[inline(never)]
pub fn unlikely<T>(value: T) -> T {
    value
}

#[track_caller]
#[inline(always)]
pub const fn get_aligned_chunk_ref<T: Copy>(input: &[u8], offset: usize) -> &T {
    let _ = Assert::<T>::IS_NOT_ZST;
    let _ = Assert2::<u8, T>::IS_SAME_ALIGN;

    debug_assert!(mem::size_of::<T>() <= input.len().saturating_sub(offset)); //Must fit

    unsafe {
        &*(input.as_ptr().add(offset) as *const T)
    }
}

#[inline(always)]
pub const fn try_get_aligned_chunk_ref<T: Copy>(input: &[u8], offset: usize) -> Option<&T> {
    let _ = Assert::<T>::IS_NOT_ZST;
    let _ = Assert2::<u8, T>::IS_SAME_ALIGN;

    if mem::size_of::<T>() <= input.len().saturating_sub(offset) {
        Some(unsafe {
            &*(input.as_ptr().add(offset) as *const T)
        })
    } else {
        None
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Eq)]
///Reference to slice of bytes within buffer
pub struct BufSlice<'a>(pub &'a [u8]);

impl<'a> BufSlice<'a> {
    #[inline(always)]
    ///Returns actual content excluding null terminating character
    pub const fn content(self) -> &'a [u8] {
        let mut idx = 0;

        while idx < self.0.len() && self.0[idx] != b'\0' {
            idx += 1
        }

        unsafe {
            core::slice::from_raw_parts(self.0.as_ptr(), idx)
        }
    }

    #[inline(always)]
    ///Attempts to interpret path as utf-8 string, returning raw content bytes in case of error
    pub const fn to_str_or(self) -> Result<&'a str, &'a [u8]> {
        let bytes = self.content();
        match core::str::from_utf8(bytes) {
            Ok(text) => Ok(text),
            Err(_) => Err(bytes),
        }
    }

    #[inline(always)]
    ///Attempts to interpret content as utf-8 string, returning `None` if content is not valid string
    pub const fn to_str(self) -> Option<&'a str> {
        match core::str::from_utf8(self.content()) {
            Ok(text) => Some(text),
            Err(_) => None,
        }
    }
}

impl PartialEq for BufSlice<'_> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.content() == other.content()
    }
}

impl fmt::Debug for BufSlice<'_> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_str_or() {
            Ok(text) => fmt::Debug::fmt(text, fmt),
            Err(bytes) => fmt::Debug::fmt(bytes, fmt),
        }
    }
}

impl fmt::Display for BufSlice<'_> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_str_or() {
            Ok(text) => fmt::Display::fmt(text, fmt),
            Err(bytes) => {
                for byte in bytes {
                    fmt.write_fmt(format_args!("{:02x}", byte))?;
                }
                Ok(())
            },
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Eq)]
pub struct StrBuf<const N: usize>([u8; N]);

impl<const N: usize> StrBuf<N> {
    #[inline(always)]
    pub const fn new(buf: [u8; N]) -> Self {
        Self(buf)
    }

    #[inline(always)]
    ///Gets reference to raw buffer
    pub const fn raw(&self) -> &[u8; N] {
        &self.0
    }

    #[inline(always)]
    ///Returns actual content excluding null terminating character
    pub const fn content(&self) -> &[u8] {
        BufSlice(self.0.as_slice()).content()
    }

    #[inline(always)]
    ///Attempts to interpret path as utf-8 string, returning raw content bytes in case of error
    pub const fn to_str_or(&self) -> Result<&str, &[u8]> {
        BufSlice(self.0.as_slice()).to_str_or()
    }

    #[inline(always)]
    ///Attempts to interpret content as utf-8 string, returning `None` if content is not valid string
    pub const fn to_str(&self) -> Option<&str> {
        BufSlice(self.0.as_slice()).to_str()
    }
}

impl<const N: usize> PartialEq for StrBuf<N> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        BufSlice(self.0.as_slice()) == BufSlice(other.0.as_slice())
    }
}

impl<const N: usize> fmt::Debug for StrBuf<N> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&BufSlice(self.0.as_slice()), fmt)
    }
}

impl<const N: usize> fmt::Display for StrBuf<N> {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&BufSlice(self.0.as_slice()), fmt)
    }
}
