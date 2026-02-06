use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn read_vault(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

pub fn write_vault_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent_dir)?;

    let temp_file = parent_dir.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault"),
        unique_suffix()
    ));

    let mut handle = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_file)?;
    set_secure_permissions(&temp_file)?;
    handle.write_all(bytes)?;
    handle.sync_all()?;
    drop(handle);

    fs::rename(&temp_file, path)?;
    set_secure_permissions(path)?;

    if let Ok(directory_handle) = OpenOptions::new().read(true).open(parent_dir) {
        let _ = directory_handle.sync_all();
    }

    Ok(())
}

fn unique_suffix() -> u128 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (u128::from(std::process::id()) << 64) | nanos
}

fn set_secure_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{read_vault, write_vault_atomic};

    fn temp_path(file_name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "npw-storage-tests-{}-{file_name}",
            std::process::id()
        ))
    }

    #[test]
    fn writes_and_reads_vault_file() {
        let path = temp_path("vault.npw");
        let payload = b"encrypted-vault";
        write_vault_atomic(&path, payload).expect("write should succeed");
        let loaded = read_vault(&path).expect("read should succeed");
        fs::remove_file(path).expect("cleanup should succeed");
        assert_eq!(loaded, payload);
    }
}
