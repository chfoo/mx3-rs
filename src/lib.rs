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
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod v1;
pub mod v2;
pub mod v3;

#[cfg_attr(docsrs, doc(cfg(feature = "hasher")))]
#[cfg(any(feature = "hasher", doc))]
mod hasher;

#[cfg_attr(docsrs, doc(cfg(feature = "hasher")))]
#[cfg(any(feature = "hasher", doc))]
pub use hasher::*;
