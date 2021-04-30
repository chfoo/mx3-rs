// Example program that reads from stdin and outputs the hash in hex.
//
// If running interactively, press CTRL+D to stop input or CTRL+C to exit.

use std::{hash::Hasher, io::Read};

use mx3::Mx3Hasher;

fn main() -> Result<(), std::io::Error> {
    let mut hasher = Mx3Hasher::default();

    let mut input_buffer = [0u8; 4096];
    let mut stdin = std::io::stdin();

    loop {
        let bytes_read = stdin.read(&mut input_buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.write(&input_buffer[0..bytes_read]);
    }

    println!("{:x}", hasher.finish());

    Ok(())
}
