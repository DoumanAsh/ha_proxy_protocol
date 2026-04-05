use core::mem;

#[cold]
#[inline(never)]
pub fn unlikely<T>(value: T) -> T {
    value
}

#[track_caller]
#[inline(always)]
pub const fn get_aligned_chunk_ref<T: Copy>(input: &[u8], offset: usize) -> &T {
    debug_assert!(mem::size_of::<T>() > 0); //Size MUST be positive
    debug_assert!(mem::size_of::<T>() <= input.len().saturating_sub(offset)); //Must fit

    unsafe {
        &*(input.as_ptr().add(offset) as *const T)
    }
}
