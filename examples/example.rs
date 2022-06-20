use rand::prelude::*;

fn main() {
    let mixed_bits = mx3::v3::mix(123456789);
    println!("{:x}", mixed_bits);

    let mut rng = mx3::v3::Mx3Rng::new(123456789);
    let random_number = rng.gen::<f64>();
    println!("{}", random_number);

    let hash_digest = mx3::v3::hash(b"Hello world!", 123456789);
    println!("{:x}", hash_digest);
}
