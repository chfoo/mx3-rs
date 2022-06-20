use std::io::Write;

use mx3::v3::Mx3Rng;
use rand::RngCore;

fn main() -> Result<(), std::io::Error> {
    let mut rng = Mx3Rng::new(1);
    let mut stdout = std::io::stdout();

    loop {
        let buf = rng.next_u64().to_le_bytes();
        let size = stdout.write(&buf)?;

        if size == 0 {
            break;
        }
    }

    Ok(())
}
