use core::fmt::{Debug, Formatter};
use core::hash::Hasher;

/// Hasher for computing a hash digest of a stream of bytes.
///
/// This hasher is *not* cryptographically secure.
///
/// Due the to the reference design not specifying unbounded streams,
/// the output is not guaranteed to be deterministic between versions of this
/// crate.
///
/// If you are simply hashing a slice,
/// consider using the shorter [`crate::v3::hash()`] function instead.
///
/// If you need a stable stream hasher, check the source code of
/// this hasher for inspiration to design your own streaming hash function.
#[derive(Clone)]
pub struct Mx3Hasher {
    seed: u64,
    state: u64,
    buf: [u8; 1024],
    buf_filled: usize,
}

impl Mx3Hasher {
    /// Construct a hasher with the given seed for a stream of bytes.
    ///
    /// This constructor is not compatible with the reference design due to
    /// the length of the stream being unknown.
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            state: crate::v3::mix(seed),
            buf: [0u8; 1024],
            buf_filled: 0,
        }
    }
}

impl Hasher for Mx3Hasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut remain = bytes;

        while !remain.is_empty() {
            let amount = bytes.len().min(self.buf.len() - self.buf_filled);
            let (left, right) = bytes.split_at(amount);

            self.buf[self.buf_filled..self.buf_filled + amount].copy_from_slice(left);
            self.buf_filled += amount;

            debug_assert!(self.buf_filled <= self.buf.len());

            if self.buf_filled == self.buf.len() {
                self.state ^= crate::v3::hash(&self.buf, self.seed);
                self.buf_filled = 0;
            }

            remain = right;
        }
    }

    fn finish(&self) -> u64 {
        let mut output = self.state;

        if self.buf_filled > 0 {
            output ^= crate::v3::hash(&self.buf[0..self.buf_filled], self.seed);
        }

        output
    }
}

impl Debug for Mx3Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mx3Hasher {{...}}")
    }
}

impl Default for Mx3Hasher {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mx3hasher() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let mut hasher = Mx3Hasher::new(123456789);

        for _ in 0..100 {
            hasher.write(input);
        }

        assert_eq!(hasher.finish(), 8878623092709932526);
    }

    #[test]
    fn test_mx3hasher_empty() {
        let input = b"";
        let mut hasher = Mx3Hasher::new(123456789);
        hasher.write(input);
        assert_eq!(hasher.finish(), 0x95bd1de6327dae0a);
    }

    #[test]
    fn test_debug() {
        let hasher = Mx3Hasher::default();
        format_args!("{:?}", hasher);
    }

    #[test]
    fn test_clone() {
        let mut hasher = Mx3Hasher::default();
        hasher.write(b"abc");

        let hasher2 = hasher.clone();

        assert_eq!(hasher.finish(), hasher2.finish());
    }
}
