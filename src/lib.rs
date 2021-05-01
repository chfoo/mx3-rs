//! Rust implementation of the [mx3 algorithm](https://github.com/jonmaiga/mx3/)
//! providing a bit mixer, pseudo-random number generator, and hash function.
//!
//! The crate is *not* intended for cryptographically secure purposes.
//!
//! The crate implements revision 2 of the mx3 algorithm.
//!
//! ## Examples
//!
//! ### Mixing bits
//!
//! ```rust
//! let mixed_bits = mx3::mix(123456789);
//! println!("{:x}", mixed_bits);
//! ```
//!
//! ### Random number generation
//!
//! ```rust
//! use rand::prelude::*;
//!
//! let mut rng = mx3::Mx3Rng::new(123456789);
//! let random_number = rng.gen::<f64>();
//! println!("{}", random_number);
//! ```
//!
//! ### Hashing
//!
//! ```rust
//! let hash_digest = mx3::hash(b"Hello world!", 123456789);
//! println!("{:x}", hash_digest);
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![no_std]

mod cursor;

use core::{
    fmt::{self, Debug, Formatter},
    hash::Hasher,
};

use rand_core::{RngCore, SeedableRng};

use crate::cursor::Cursor;

const PARAMETER_C: u64 = 0xbea225f9eb34556d;

/// Mix the bits in the integer.
pub fn mix(mut x: u64) -> u64 {
    x ^= x >> 32;
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 29;
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 32;
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 29;
    x
}

/// Pseudo-random number generator with 64-bits of state and cycle of 2^64.
///
/// This RNG is *not* cryptographically secure.
#[derive(Clone)]
pub struct Mx3Rng {
    counter: u64,
}

impl Mx3Rng {
    /// Create the PRNG generator using the given seed.
    ///
    /// Unlike [`Self::from_seed()`], this constructor does not modify the seed
    /// before it is used and is equivalent to the reference constructor.
    pub fn new(seed: u64) -> Self {
        Self { counter: seed }
    }

    /// Return the state of the generator.
    ///
    /// The generator can be resumed by passing the state as a seed to the
    /// [`Self::new()`] constructor.
    pub fn state(&self) -> u64 {
        self.counter
    }
}

impl SeedableRng for Mx3Rng {
    type Seed = [u8; 8];

    fn from_seed(seed: Self::Seed) -> Self {
        let seed = u64::from_be_bytes(seed);

        Self::new(seed)
    }
}

impl RngCore for Mx3Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let value = mix(self.counter);
        self.counter = self.counter.wrapping_add(1);
        value
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl Debug for Mx3Rng {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Mx3Rng {{...}}")
    }
}

/// Hasher for computing a hash digest of a stream of bytes.
///
/// This hasher is *not* cryptographically secure.
#[derive(Clone)]
pub struct Mx3Hasher {
    state: u64,
    partial_int_buffer: [u8; 8],
    partial_int_buffer_len: usize,
}

impl Mx3Hasher {
    /// Construct a hasher with the given seed for a stream of bytes.
    ///
    /// This constructor is not compatible with the reference design due to
    /// the length of the stream being unknown.
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed,
            partial_int_buffer: [0u8; 8],
            partial_int_buffer_len: 0,
        }
    }

    /// Construct a hasher with the given seed and stream length.
    ///
    /// This constructor allows compatibility with the reference design. If you
    /// are simply hashing a slice, consider using the shorter [`hash()`]
    /// function instead.
    pub fn new_with_length(seed: u64, buffer_len: usize) -> Self {
        Self::new(seed ^ buffer_len as u64)
    }

    fn mix_stream(mut h: u64, mut x: u64) -> u64 {
        x = x.wrapping_mul(PARAMETER_C);
        x ^= (x >> 57) ^ (x >> 43);
        x = x.wrapping_mul(PARAMETER_C);
        h = h.wrapping_add(x);
        h = h.wrapping_mul(PARAMETER_C);
        h
    }

    fn write_into_partial_int_buffer(&mut self, bytes: &mut Cursor) -> usize {
        let bytes_read = bytes.read(&mut self.partial_int_buffer[self.partial_int_buffer_len..]);
        self.partial_int_buffer_len += bytes_read;
        debug_assert!(self.partial_int_buffer_len <= 8);

        bytes_read
    }

    fn apply_partial_int_buffer(&mut self) {
        debug_assert!(self.partial_int_buffer_len == 8);

        let value = self.partial_int_buffer;
        let value = u64::from_le_bytes(value);
        self.state = Self::mix_stream(self.state, value);
        self.partial_int_buffer_len = 0;
    }
}

impl Hasher for Mx3Hasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut cursor = Cursor::new(bytes);
        let mut bytes_remaining = bytes.len();

        if self.partial_int_buffer_len > 0 {
            let bytes_processed = self.write_into_partial_int_buffer(&mut cursor);
            bytes_remaining -= bytes_processed;

            if self.partial_int_buffer_len == 8 {
                self.apply_partial_int_buffer();
            } else {
                debug_assert!(bytes_remaining < 8);
                return;
            }
        }

        while bytes_remaining >= 8 {
            bytes_remaining -= 8;

            let mut value = [0u8; 8];
            cursor.read_exact(&mut value).unwrap();
            let value = u64::from_le_bytes(value);

            self.state = Self::mix_stream(self.state, value);
        }

        let bytes_processed = self.write_into_partial_int_buffer(&mut cursor);
        bytes_remaining -= bytes_processed;
        debug_assert!(bytes_processed < 8);
        debug_assert!(bytes_remaining == 0);
    }

    fn finish(&self) -> u64 {
        debug_assert!(self.partial_int_buffer_len < 8);

        let mut v = 0u64;
        let mut h = self.state;

        if self.partial_int_buffer_len >= 7 {
            v |= (self.partial_int_buffer[6] as u64) << 48;
        }
        if self.partial_int_buffer_len >= 6 {
            v |= (self.partial_int_buffer[5] as u64) << 40;
        }
        if self.partial_int_buffer_len >= 5 {
            v |= (self.partial_int_buffer[4] as u64) << 32;
        }
        if self.partial_int_buffer_len >= 4 {
            v |= (self.partial_int_buffer[3] as u64) << 24;
        }
        if self.partial_int_buffer_len >= 3 {
            v |= (self.partial_int_buffer[2] as u64) << 16;
        }
        if self.partial_int_buffer_len >= 2 {
            v |= (self.partial_int_buffer[1] as u64) << 8;
        }
        if self.partial_int_buffer_len >= 1 {
            h = Self::mix_stream(self.state, v | self.partial_int_buffer[0] as u64);
        }

        mix(h)
    }
}

impl Debug for Mx3Hasher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Mx3Hasher {{...}}")
    }
}

impl Default for Mx3Hasher {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Hash the given buffer.
///
/// This hasher is *not* cryptographically secure.
pub fn hash(buffer: &[u8], seed: u64) -> u64 {
    let mut hasher = Mx3Hasher::new_with_length(seed, buffer.len());
    hasher.write(buffer);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // C++ test program:
    /*
    #include <iostream>
    #include "mx3.h"

    int main() {
        std::cout << std::hex << mx3::mix(123456789) << std::endl;

        uint8_t b[] = "abcdefghijklmnopqrstuvwxyz";

        for (size_t len = 0; len <= 26; len++) {
            std::cout << len << "\t" << std::hex << mx3::hash(b, len, 123456789) << std::endl;
        }

        std::cout << "Rand 1" << std::endl;

        mx3::random r(1);

        std::cout << std::hex << r() << std::endl;
        std::cout << std::hex << r() << std::endl;
        std::cout << std::hex << r() << std::endl;

        return 0;
    }
    */

    #[test]
    fn test_mix() {
        assert_eq!(mix(123456789), 0x95bd1de6327dae0a);
    }

    #[test]
    fn test_hash() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let outputs: [u64; 27] = [
            0x95bd1de6327dae0a,
            0xdf8558992bfc3f87,
            0x1a21bfae9df45b48,
            0x7f3890aee60a2b23,
            0xe426b02c719dc4a1,
            0x7b18a2f70a8f5b9c,
            0x88ed8ee800c583,
            0x2d6683263a1f05f8,
            0x395caf6b87f1c933,
            0xe95331bb3b640e1,
            0x663e926235bb5969,
            0x966fbafe45ff7e50,
            0x98a407a2a3b6c878,
            0x9a161fbd700c5ef6,
            0x13992c04f5edf5e3,
            0x29a0245c892a71c5,
            0xb617dfdbea45debd,
            0x6f23ca1b5f6a551,
            0x902d9ed019625e75,
            0xacff8ed243a72810,
            0xd49326d9f1065094,
            0xc04a0cb2b523df98,
            0x76a6bae003d7b9cb,
            0xfc98e44e6e2ba3f5,
            0xa54e3589ce94a3d6,
            0x847fe0dad5593f,
            0xf1673daba637e36,
        ];

        for len in 0..=26 {
            let result = hash(&input[0..len], 123456789);
            assert_eq!(result, outputs[len]);
        }
    }

    #[test]
    fn test_mx3rng_64() {
        let mut rng = Mx3Rng::new(1);
        assert_eq!(rng.next_u64(), 0x0718_94de_00d9_981f);
        assert_eq!(rng.next_u64(), 0xef9d_9826_2a1b_46cb);
    }

    #[test]
    fn test_mx3rng_32() {
        let mut rng = Mx3Rng::new(1);
        assert_eq!(rng.next_u32(), 0x00d9981f);
        assert_eq!(rng.next_u32(), 0x2a1b46cb);
    }

    #[test]
    fn test_mx3hasher() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let mut hasher = Mx3Hasher::new(123456789 ^ input.len() as u64);
        for byte in input {
            hasher.write_u8(*byte);
        }
        assert_eq!(hasher.finish(), 0xf1673daba637e36);
    }

    #[test]
    fn test_debug() {
        let rng = Mx3Rng::new(1);
        let hasher = Mx3Hasher::default();
        format_args!("{:?} {:?}", rng, hasher);
    }

    #[test]
    fn test_clone() {
        let mut rng = Mx3Rng::new(1);
        rng.next_u64();

        let mut rng2 = rng.clone();

        assert_eq!(rng.next_u64(), rng2.next_u64());

        let mut hasher = Mx3Hasher::default();
        hasher.write(b"abc");

        let hasher2 = hasher.clone();

        assert_eq!(hasher.finish(), hasher2.finish());
    }
}
