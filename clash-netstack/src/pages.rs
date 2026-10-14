//! A TCP socket's send buffer in pages of its own (our fork): mapped as
//! they are first used, and given back when the connection closes and
//! whenever the buffer is empty again after carrying data.
//!
//! From the allocator, the pages a buffer had used stayed resident for as
//! long as the connection was open, and after it closed until the
//! allocator reused them: smoltcp moves a buffer back to its start only
//! when it is empty as data comes in, which it rarely is during a
//! download (the app has not acknowledged the last segments yet), so each
//! connection that had carried a download kept its whole send buffer
//! (128 KiB on iOS), and a burst of connections left an iOS packet tunnel
//! that much larger.

/// Pages for one buffer.
pub(crate) struct Pages {
    ptr: *mut u8,
    len: usize,
    /// Without an anonymous mapping: an allocation, which `release` keeps.
    heap: Option<Box<[u8]>>,
}

// The buffer is used by the thread that owns its socket.
unsafe impl Send for Pages {}

impl Pages {
    pub(crate) fn new(len: usize) -> Self {
        #[cfg(unix)]
        if let Some(ptr) = map(std::ptr::null_mut(), len, 0) {
            return Self {
                ptr,
                len,
                heap: None,
            };
        }
        let mut heap = vec![0u8; len].into_boxed_slice();
        Self {
            ptr: heap.as_mut_ptr(),
            len,
            heap: Some(heap),
        }
    }

    /// The buffer, for a smoltcp socket.
    ///
    /// # Safety
    /// The socket must be gone before these pages are, and the buffer is
    /// used through it alone.
    pub(crate) unsafe fn buffer(&self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Gives the pages back: the next use maps zeroed ones. Only while the
    /// buffer holds nothing to read and is not in use.
    pub(crate) fn release(&self) {
        #[cfg(unix)]
        if self.heap.is_none() {
            // A new mapping in place of the old one drops its pages.
            let _ = map(self.ptr, self.len, libc::MAP_FIXED);
        }
    }
}

impl Drop for Pages {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.heap.is_none() {
            unsafe { libc::munmap(self.ptr.cast(), self.len) };
        }
    }
}

#[cfg(unix)]
fn map(at: *mut u8, len: usize, flags: i32) -> Option<*mut u8> {
    let ptr = unsafe {
        libc::mmap(
            at.cast(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | flags,
            -1,
            0,
        )
    };
    (ptr != libc::MAP_FAILED).then_some(ptr.cast())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn resident(pages: &Pages) -> usize {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mut vec = vec![0 as libc::c_char; pages.len.div_ceil(page)];
        unsafe {
            libc::mincore(pages.ptr.cast(), pages.len, vec.as_mut_ptr().cast())
        };
        vec.iter().filter(|v| **v & 1 != 0).count()
    }

    #[test]
    fn mapped_as_used_and_given_back() {
        let pages = Pages::new(256 * 1024);
        assert_eq!(resident(&pages), 0);
        let buffer = unsafe { pages.buffer() };
        buffer.fill(7);
        assert!(resident(&pages) > 0);
        pages.release();
        assert_eq!(resident(&pages), 0);
        // Usable again, zeroed.
        assert!(buffer.iter().all(|b| *b == 0));
        buffer[100] = 1;
        assert_eq!(buffer[100], 1);
    }
}
