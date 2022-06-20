//! Version 3 implementation.
//!
//! This module contains an implementation based on [version 1](https://github.com/jonmaiga/mx3/tree/v3.0.0)
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

fn mix_stream_2(mut h: u64, mut x: u64) -> u64 {
    x = x.wrapping_mul(PARAMETER_C);
    x ^= x >> 39;
    h = h.wrapping_add(x.wrapping_mul(PARAMETER_C));
    h = h.wrapping_mul(PARAMETER_C);
    h
}

fn mix_stream_5(mut h: u64, mut a: u64, mut b: u64, mut c: u64, mut d: u64) -> u64 {
    a = a.wrapping_mul(PARAMETER_C);
    b = b.wrapping_mul(PARAMETER_C);
    c = c.wrapping_mul(PARAMETER_C);
    d = d.wrapping_mul(PARAMETER_C);

    a ^= a >> 39;
    b ^= b >> 39;
    c ^= c >> 39;
    d ^= d >> 39;

    h = h.wrapping_add(a.wrapping_mul(PARAMETER_C));
    h = h.wrapping_mul(PARAMETER_C);
    h = h.wrapping_add(b.wrapping_mul(PARAMETER_C));
    h = h.wrapping_mul(PARAMETER_C);
    h = h.wrapping_add(c.wrapping_mul(PARAMETER_C));
    h = h.wrapping_mul(PARAMETER_C);
    h = h.wrapping_add(d.wrapping_mul(PARAMETER_C));
    h = h.wrapping_mul(PARAMETER_C);

    h
}

/// Hash the given buffer.
///
/// This hasher is *not* cryptographically secure.
pub fn hash(buffer: &[u8], seed: u64) -> u64 {
    let mut output = mix_stream_2(seed, buffer.len() as u64 + 1);
    let mut remain = buffer;

    while remain.len() >= 64 {
        let (left, right) = remain.split_at(64);
        remain = right;

        let mut value_ints = [0u64; 8];

        for (int_index, value_int) in value_ints.iter_mut().enumerate() {
            let mut int_buf = [0u8; 8];
            let byte_index = int_index * 8;
            int_buf.copy_from_slice(&left[byte_index..byte_index + 8]);
            *value_int = u64::from_le_bytes(int_buf);
        }

        output = mix_stream_5(
            output,
            value_ints[0],
            value_ints[1],
            value_ints[2],
            value_ints[3],
        );
        output = mix_stream_5(
            output,
            value_ints[4],
            value_ints[5],
            value_ints[6],
            value_ints[7],
        );
    }

    while remain.len() >= 8 {
        let (left, right) = remain.split_at(8);
        remain = right;

        let mut int_buf = [0u8; 8];
        int_buf.copy_from_slice(left);

        let value = u64::from_le_bytes(int_buf);
        output = mix_stream_2(output, value);
    }

    match remain.len() {
        0 => mix(output),
        1 => mix(mix_stream_2(output, remain[0] as u64)),
        2 => mix(mix_stream_2(
            output,
            (remain[1] as u64) << 8 | remain[0] as u64,
        )),
        3 => mix(mix_stream_2(
            output,
            (remain[2] as u64) << 16 | (remain[1] as u64) << 8 | remain[0] as u64,
        )),
        4 => mix(mix_stream_2(
            output,
            (remain[3] as u64) << 24
                | (remain[2] as u64) << 16
                | (remain[1] as u64) << 8
                | remain[0] as u64,
        )),
        5 => mix(mix_stream_2(
            output,
            (remain[4] as u64) << 32
                | (remain[3] as u64) << 24
                | (remain[2] as u64) << 16
                | (remain[1] as u64) << 8
                | remain[0] as u64,
        )),
        6 => mix(mix_stream_2(
            output,
            (remain[5] as u64) << 40
                | (remain[4] as u64) << 32
                | (remain[3] as u64) << 24
                | (remain[2] as u64) << 16
                | (remain[1] as u64) << 8
                | remain[0] as u64,
        )),
        7 => mix(mix_stream_2(
            output,
            (remain[6] as u64) << 48
                | (remain[5] as u64) << 40
                | (remain[4] as u64) << 32
                | (remain[3] as u64) << 24
                | (remain[2] as u64) << 16
                | (remain[1] as u64) << 8
                | remain[0] as u64,
        )),
        _ => unreachable!(),
    }
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
    /// This constructor modifies the seed before it is used in manner that
    /// is equivalent to the reference design constructor.
    /// [`Self::from_seed()`] uses a different seed mixing function.
    pub fn new(seed: u64) -> Self {
        Self {
            counter: mix(seed.wrapping_add(PARAMETER_C)),
        }
    }

    /// Creates the PRNG generator from an existing state.
    pub fn resume(state: u64) -> Self {
        Self { counter: state }
    }

    /// Return the state of the generator.
    ///
    /// The generator can be resumed by passing the state to
    /// [`Self::resume()`] constructor.
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
            0x4e069d451e12ced8,
            0x5eb36ac9592ab1df,
            0x28aee35eb05b5e01,
            0xc84bb340afd4c59c,
            0xeeded76f960ae7a1,
            0x80a4d25e6705d3ba,
            0x76e1913cb3491d76,
            0xe2a6e400fe57f6c3,
            0x606b49ce1423ae16,
            0x79b96174f8e230a0,
            0x9e602ef1d012bb2d,
            0x9f9709e439dd8999,
            0x1503884eae03740a,
            0xf208267c7e8a461c,
            0xa08d41054b42ce80,
            0x6129ee7c45f92fff,
            0x9405c374e7cec176,
            0x9cc7a2b54b9c4478,
            0x9d0e1fca25723cac,
            0xde4e43505cedd231,
            0x91462bc2c10a62ba,
            0x1e84991efaf319c1,
            0x5c41b4a8350c9a0a,
            0xf5d4ce766a91e9bd,
            0x17dcc3722edeeee,
            0x224dc0b46df3f834,
            0x6c16bdf4571e7844,
        ];

        for len in 0..=26 {
            let result = hash(&input[0..len], 123456789);
            assert_eq!(result, outputs[len]);
        }
    }

    #[test]
    fn test_hash_long() {
        let result = hash(b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.", 123456789);
        assert_eq!(result, 0x591893507ccdbfdf);
    }

    #[test]
    fn test_mx3rng_64() {
        let mut rng = Mx3Rng::new(1);
        assert_eq!(rng.next_u64(), 0xe8eb_dbc4_39df_412a);
        assert_eq!(rng.next_u64(), 0x4d47_6d54_25a1_74d9);
    }

    #[test]
    fn test_mx3rng_32() {
        let mut rng = Mx3Rng::new(1);
        assert_eq!(rng.next_u32(), 0x39df_412a);
        assert_eq!(rng.next_u32(), 0x25a1_74d9);
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
