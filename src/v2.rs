//! Version 2 implementation.
//!
//! This module contains an implementation based on [version 1](https://github.com/jonmaiga/mx3/tree/v2.0.0)
//! of the mx3 algorithm.
//!
//! The outputs are not compatible with other versions.

use core::fmt::{Debug, Formatter};

use rand_core::{RngCore, SeedableRng};

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

fn mix_stream(mut h: u64, mut x: u64) -> u64 {
    x = x.wrapping_mul(PARAMETER_C);
    x ^= (x >> 57) ^ (x >> 43);
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
    fn test_hash_long() {
        let result = hash(b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.", 123456789);
        assert_eq!(result, 0x6fd9e7bca6d66212);
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
        assert_eq!(rng.next_u32(), 0x00d9_981f);
        assert_eq!(rng.next_u32(), 0x2a1b_46cb);
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
