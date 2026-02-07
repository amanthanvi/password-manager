use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_path = env::args()
        .nth(1)
        .ok_or("usage: lock_holder <vault_path>")?;

    let vault_path = PathBuf::from(vault_path);
    let _lock = npw_storage::acquire_vault_lock(&vault_path)?;

    println!("LOCK_ACQUIRED");
    io::stdout().flush().ok();

    // Hold the lock until stdin is closed (the parent test drops the pipe).
    let mut sink = Vec::new();
    let _ = io::stdin().read_to_end(&mut sink);
    Ok(())
}
