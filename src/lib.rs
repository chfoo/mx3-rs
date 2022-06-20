//! Rust implementation of the [mx3 algorithm](https://github.com/jonmaiga/mx3/)
//! providing a bit mixer, pseudo-random number generator, and hash function.
//!
//! The crate is *not* intended for cryptographically secure purposes.
//!
//! The crate implements versions 1, 2, and 3.
//!
//! ## Examples
//!
//! ### Mixing bits
//!
//! ```rust
//! let mixed_bits = mx3::v3::mix(123456789);
//! println!("{:x}", mixed_bits);
//! ```
//!
//! ### Random number generation
//!
//! ```rust
//! use rand::prelude::*;
//!
//! let mut rng = mx3::v3::Mx3Rng::new(123456789);
//! let random_number = rng.gen::<f64>();
//! println!("{}", random_number);
//! ```
//!
//! ### Hashing
//!
//! ```rust
//! let hash_digest = mx3::v3::hash(b"Hello world!", 123456789);
//! println!("{:x}", hash_digest);
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![no_std]

pub mod v1;
pub mod v2;
pub mod v3;

use core::fmt::{Debug, Formatter};

/// Hasher for computing a hash digest of a stream of bytes.
///
/// This hasher is *not* cryptographically secure.
///
/// Due the to the reference design not specifying unbounded streams,
/// the output is not guaranteed to be deterministic between versions of this
/// crate.
///
/// If you are simply hashing a slice,
/// consider using the shorter [`v3::hash()`] function instead.
///
/// If you need a stable stream hasher, check the source code of
/// this hasher for inspiration to design your own streaming hash function.
#[cfg(feature = "hasher")]
#[derive(Clone)]
pub struct Mx3Hasher {
    seed: u64,
    state: u64,
    buf: [u8; 1024],
    buf_filled: usize,
}

#[cfg(feature = "hasher")]
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

#[cfg(feature = "hasher")]
impl core::hash::Hasher for Mx3Hasher {
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

#[cfg(feature = "hasher")]
impl Debug for Mx3Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mx3Hasher {{...}}")
    }
}

#[cfg(feature = "hasher")]
impl Default for Mx3Hasher {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
#[cfg(feature = "hasher")]
mod tests_hasher {
    use core::hash::Hasher;

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
