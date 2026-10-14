use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering},
};

pub struct LockFreeRingBuffer {
    buffer: UnsafeCell<Box<[u8]>>,
    capacity: usize,
    /// The read position (high 32 bits, moved by the consumer) and the
    /// write position (low 32 bits, moved by the producer), together: the
    /// producer moves both back to the start when the ring is empty (our
    /// fork), so data that is read as it comes keeps to the first pages.
    /// Going round the whole ring made all of it resident: each connection
    /// that had carried more than the ring's size kept that much memory per
    /// direction until it closed.
    positions: AtomicU64,
}

unsafe impl Send for LockFreeRingBuffer {}
unsafe impl Sync for LockFreeRingBuffer {}

fn unpack(positions: u64) -> (usize, usize) {
    (
        (positions >> 32) as usize,
        (positions & 0xffff_ffff) as usize,
    )
}

fn pack(read_pos: usize, write_pos: usize) -> u64 {
    (read_pos as u64) << 32 | write_pos as u64
}

impl LockFreeRingBuffer {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity <= u32::MAX as usize);
        Self {
            buffer: UnsafeCell::new(vec![0u8; capacity].into_boxed_slice()),
            capacity,
            positions: AtomicU64::new(0),
        }
    }

    /// Sets one position, keeping the other as the other side moves it.
    fn store(
        &self,
        mut current: u64,
        read_pos: Option<usize>,
        write_pos: Option<usize>,
    ) {
        loop {
            let (r, w) = unpack(current);
            let next = pack(read_pos.unwrap_or(r), write_pos.unwrap_or(w));
            match self.positions.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(now) => current = now,
            }
        }
    }

    // The producer calls this (one thread at a time)
    pub fn enqueue_slice(&self, data: &[u8]) -> usize {
        let mut current = self.positions.load(Ordering::Acquire);
        let (mut read_pos, mut write_pos) = unpack(current);
        // Empty: start over at the beginning. The consumer moves the read
        // position only past data it read, so it holds none now.
        if read_pos == write_pos
            && write_pos != 0
            && self
                .positions
                .compare_exchange(current, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            (current, read_pos, write_pos) = (0, 0, 0);
        }

        // Calculate available space
        let available = if read_pos <= write_pos {
            self.capacity - write_pos + read_pos - 1
        } else {
            read_pos - write_pos - 1
        };

        let to_write = std::cmp::min(data.len(), available);
        if to_write == 0 {
            return 0;
        }

        unsafe {
            let buffer = &mut *self.buffer.get();

            // Handle wrap-around
            if write_pos + to_write <= self.capacity {
                // No wrap
                buffer[write_pos..write_pos + to_write]
                    .copy_from_slice(&data[..to_write]);
            } else {
                // Wrap around
                let first_part = self.capacity - write_pos;
                buffer[write_pos..].copy_from_slice(&data[..first_part]);
                buffer[..to_write - first_part]
                    .copy_from_slice(&data[first_part..to_write]);
            }
        }

        // Update write position
        let new_write_pos = (write_pos + to_write) % self.capacity;
        self.store(current, None, Some(new_write_pos));

        to_write
    }

    // The consumer calls this (one thread at a time)
    pub fn dequeue_slice(&self, buf: &mut [u8]) -> usize {
        let current = self.positions.load(Ordering::Acquire);
        let (read_pos, write_pos) = unpack(current);

        // Calculate available data
        let available = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.capacity - read_pos + write_pos
        };

        let to_read = std::cmp::min(buf.len(), available);
        if to_read == 0 {
            return 0;
        }

        unsafe {
            let buffer = &*self.buffer.get();

            // Handle wrap-around
            if read_pos + to_read <= self.capacity {
                // No wrap
                buf[..to_read]
                    .copy_from_slice(&buffer[read_pos..read_pos + to_read]);
            } else {
                // Wrap around
                let first_part = self.capacity - read_pos;
                buf[..first_part].copy_from_slice(&buffer[read_pos..]);
                buf[first_part..to_read]
                    .copy_from_slice(&buffer[..to_read - first_part]);
            }
        }

        // Update read position. The producer does not start over meanwhile:
        // the ring is not empty until this.
        let new_read_pos = (read_pos + to_read) % self.capacity;
        self.store(current, Some(new_read_pos), None);

        to_read
    }

    pub fn is_empty(&self) -> bool {
        let (read_pos, write_pos) = unpack(self.positions.load(Ordering::Acquire));
        read_pos == write_pos
    }

    pub fn is_full(&self) -> bool {
        let (read_pos, write_pos) = unpack(self.positions.load(Ordering::Acquire));
        ((write_pos + 1) % self.capacity) == read_pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_over_when_empty() {
        let ring = LockFreeRingBuffer::new(16);
        let mut out = [0u8; 16];
        assert_eq!(ring.enqueue_slice(b"0123456789"), 10);
        assert_eq!(ring.dequeue_slice(&mut out[..4]), 4);
        // Not empty: written after the data.
        assert_eq!(ring.enqueue_slice(b"ab"), 2);
        assert_eq!(unpack(ring.positions.load(Ordering::Relaxed)), (4, 12));
        assert_eq!(ring.dequeue_slice(&mut out), 8);
        assert_eq!(&out[..8], b"456789ab");
        // Empty: the next data goes to the start.
        assert!(ring.is_empty());
        assert_eq!(ring.enqueue_slice(b"xyz"), 3);
        assert_eq!(unpack(ring.positions.load(Ordering::Relaxed)), (0, 3));
        // Wrapping round still works; the ring holds one byte less.
        assert_eq!(ring.enqueue_slice(&[7u8; 20]), 12);
        assert!(ring.is_full());
        assert_eq!(ring.dequeue_slice(&mut out), 15);
        assert_eq!(&out[..3], b"xyz");
        assert_eq!(ring.enqueue_slice(b"q"), 1);
        assert_eq!(unpack(ring.positions.load(Ordering::Relaxed)), (0, 1));
    }

    #[test]
    fn one_producer_one_consumer() {
        let ring = std::sync::Arc::new(LockFreeRingBuffer::new(4096));
        let total = 4 << 20;
        let producer = {
            let ring = ring.clone();
            std::thread::spawn(move || {
                let mut next = 0usize;
                while next < total {
                    let chunk: Vec<u8> =
                        (next..(next + 1000).min(total)).map(|i| i as u8).collect();
                    next += ring.enqueue_slice(&chunk);
                }
            })
        };
        let mut seen = 0usize;
        let mut buf = [0u8; 700];
        while seen < total {
            let n = ring.dequeue_slice(&mut buf);
            for (i, b) in buf[..n].iter().enumerate() {
                assert_eq!(*b, (seen + i) as u8, "at {}", seen + i);
            }
            seen += n;
        }
        producer.join().unwrap();
    }
}
