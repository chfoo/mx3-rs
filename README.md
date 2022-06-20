# mx3-rs

mx3-rs is a Rust library implementing the [mx3 algorithm](https://github.com/jonmaiga/mx3/) which provides a bit mixer, pseudo-random number generator, and hash function. This crate implements versions 1, 2, and 3.

The crate is *not* intended for cryptographically secure purposes.

[![Crates.io](https://img.shields.io/crates/v/mx3)](https://crates.io/crates/mx3) [![docs.rs](https://img.shields.io/docsrs/mx3)](https://docs.rs/mx3)

## Quick start

### Mixing bits

```rust
let mixed_bits = mx3::v3::mix(123456789);
println!("{:x}", mixed_bits);
```

### Random number generation

```rust
use rand::prelude::*;

let mut rng = mx3::v3::Mx3Rng::new(123456789);
let random_number = rng.gen::<f64>();
println!("{}", random_number);
```

### Hashing

```rust
let hash_digest = mx3::v3::hash(b"Hello world!", 123456789);
println!("{:x}", hash_digest);
```

## Contributing

If you have problems or bug fixes, please use the GitHub Issues and Pull Request sections.

## License

Copyright (c) 2021-2022 Christopher Foo. Licensed under the MIT License.
