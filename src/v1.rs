//! Version 1 implementation.
//!
//! This module contains an implementation based on [version 1](https://github.com/jonmaiga/mx3/tree/v1.0.0)
//! of the mx3 algorithm.
//!
//! The outputs are not compatible with other versions.

use core::fmt::{Debug, Formatter};

use rand_core::{RngCore, SeedableRng};

const PARAMETER_C: u64 = 0xbea225f9eb34556d;

/// Mix the bits in the integer.
pub fn mix(mut x: u64) -> u64 {
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 33;
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 29;
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 39;
    x
}

fn mix_stream(mut h: u64, mut x: u64) -> u64 {
    x = x.wrapping_mul(PARAMETER_C);
    x ^= (x >> 57) ^ (x >> 33);
    x = x.wrapping_mul(PARAMETER_C);
    h = h.wrapping_add(x);
    h = h.wrapping_mul(PARAMETER_C);
    h
}

/// Hash the given buffer.
///
/// This hasher is *not* cryptographically secure.
pub fn hash(buffer: &[u8], seed: u64) -> u64 {
    let mut output = seed ^ (buffer.len() as u64);
    let mut remain = buffer;

    while remain.len() >= 8 {
        let (left, right) = remain.split_at(8);
        remain = right;

        let mut int_buf = [0u8; 8];
        int_buf.copy_from_slice(left);

        let value = u64::from_le_bytes(int_buf);
        output = mix_stream(output, value);
    }

    let mut last_int = 0;
    if remain.len() >= 7 {
        last_int |= (remain[6] as u64) << 48;
    }
    if remain.len() >= 6 {
        last_int |= (remain[5] as u64) << 40;
    }
    if remain.len() >= 5 {
        last_int |= (remain[4] as u64) << 32;
    }
    if remain.len() >= 4 {
        last_int |= (remain[3] as u64) << 24;
    }
    if remain.len() >= 3 {
        last_int |= (remain[2] as u64) << 16;
    }
    if remain.len() >= 2 {
        last_int |= (remain[1] as u64) << 8;
    }
    if !remain.is_empty() {
        output = mix_stream(output, last_int | remain[0] as u64);
    }

    mix(output)
}

/// Pseudo-random number generator with 64-bits of state and cycle of 2^64.
///
/// This RNG is *not* cryptographically secure.
#[derive(Clone)]
pub struct Mx3Rng {
    counter: u64,
}

impl Mx3Rng {
    /// Creates the PRNG generator using the given seed.
    ///
    /// Unlike [`Self::from_seed()`], this constructor does not modify the seed
    /// before it is used and is equivalent to the reference design constructor.
    pub fn new(seed: u64) -> Self {
        Self { counter: seed }
    }

    /// Returns the state of the generator.
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
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mx3Rng {{...}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mix() {
        assert_eq!(mix(123456789), 0x566319fa1c03230f);
    }

    #[test]
    fn test_hash() {
        let input = b"abcdefghijklmnopqrstuvwxyz";
        let outputs: [u64; 27] = [
            0x566319fa1c03230f,
            0x1d4c331d9d3f2049,
            0x491f91a790cc7f0b,
            0x8e574f9a20d15f43,
            0x9cc98e8e7bcb7bab,
            0x2e014c9a9b41b79b,
            0x90874212c6dbd7d0,
            0xde1426833c7d882a,
            0x66685094340748cb,
            0xa2cc9f413d39f1bc,
            0x8a44bb7774cc3564,
            0x6e1f1e03075de002,
            0x76b37093e5d3ec,
            0x2b5350b03536f60b,
            0xcb6da1b8d49578c,
            0xb839559f09ab5c45,
            0x930b3e15662f1adb,
            0x8d3c63a40fbe05dd,
            0xb09cf7a6749ef821,
            0xb034e3927754a34,
            0x5fb9e1de0c1219f3,
            0xe3ac8d6b0d7675b0,
            0x4dc45e937a3111c7,
            0xea6df82321394835,
            0x94d8d33b442af454,
            0x113c64754ecc3ae7,
            0x1e29585a2a634374,
        ];

        for len in 0..=26 {
            let result = hash(&input[0..len], 123456789);
            assert_eq!(result, outputs[len]);
        }
    }

    #[test]
    fn test_hash_long() {
        let result = hash(b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.", 123456789);
        assert_eq!(result, 0x7b519609f3b69338);
    }

    #[test]
    fn test_mx3rng_64() {
        let mut rng = Mx3Rng::new(1);
        assert_eq!(rng.next_u64(), 0x3e1e_ad46_d36d_302b);
        assert_eq!(rng.next_u64(), 0xaaf9_08c7_32d7_0fa6);
    }

    #[test]
    fn test_mx3rng_32() {
        let mut rng = Mx3Rng::new(1);
        assert_eq!(rng.next_u32(), 0xd36d_302b);
        assert_eq!(rng.next_u32(), 0x32d7_0fa6);
    }

    #[test]
    fn test_debug() {
        let rng = Mx3Rng::new(1);
        format_args!("{:?}", rng);
    }

    #[test]
    fn test_clone() {
        let mut rng = Mx3Rng::new(1);
        rng.next_u64();

        let mut rng2 = rng.clone();

        assert_eq!(rng.next_u64(), rng2.next_u64());
    }
}
