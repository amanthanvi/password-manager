use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use thiserror::Error;

const DAY_SECONDS: u64 = 24 * 60 * 60;
const WEEK_SECONDS: u64 = 7 * DAY_SECONDS;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("vault file locked by another process")]
    Locked,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupEntry {
    pub path: PathBuf,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct VaultLock {
    vault_path: PathBuf,
    _lock_file: File,
}

impl VaultLock {
    pub fn path(&self) -> &Path {
        &self.vault_path
    }
}

pub fn read_vault(path: &Path) -> Result<Vec<u8>, StorageError> {
    Ok(fs::read(path)?)
}

pub fn write_vault(path: &Path, bytes: &[u8], max_retained: usize) -> Result<(), StorageError> {
    let lock = acquire_vault_lock(path)?;
    write_vault_with_lock(&lock, bytes, max_retained)?;
    Ok(())
}

pub fn write_vault_with_lock(
    lock: &VaultLock,
    bytes: &[u8],
    max_retained: usize,
) -> Result<(), StorageError> {
    let path = lock.path();

    if path.exists() {
        create_backup(path, max_retained)?;
    }

    write_vault_atomic(path, bytes)?;
    Ok(())
}

pub fn list_backups(path: &Path) -> Result<Vec<BackupEntry>, StorageError> {
    let backup_dir = backup_directory(path);
    if !backup_dir.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();
    for entry in fs::read_dir(backup_dir)? {
        let entry = entry?;
        let entry_path = entry.path();
        if !entry_path.is_file() {
            continue;
        }
        if let Some(timestamp) = parse_backup_timestamp(&entry_path) {
            backups.push(BackupEntry {
                path: entry_path,
                timestamp,
            });
        }
    }
    backups.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    Ok(backups)
}

pub fn recover_from_backup(
    vault_path: &Path,
    backup_path: &Path,
) -> Result<Option<PathBuf>, StorageError> {
    let lock = acquire_vault_lock(vault_path)?;
    recover_from_backup_with_lock(&lock, backup_path)
}

pub fn recover_from_backup_with_lock(
    lock: &VaultLock,
    backup_path: &Path,
) -> Result<Option<PathBuf>, StorageError> {
    let vault_path = lock.path();
    let backup_bytes = fs::read(backup_path)?;
    let corrupt_path = preserve_corrupt_vault(vault_path)?;
    write_vault_atomic(vault_path, &backup_bytes)?;
    Ok(corrupt_path)
}

pub fn acquire_vault_lock(path: &Path) -> Result<VaultLock, StorageError> {
    let lock_path = lock_file_path(path);
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    match lock_file.try_lock_exclusive() {
        Ok(()) => Ok(VaultLock {
            vault_path: path.to_path_buf(),
            _lock_file: lock_file,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(StorageError::Locked),
        Err(error) => Err(StorageError::Io(error)),
    }
}

fn lock_file_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault");
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{file_name}.lock"))
}

fn create_backup(path: &Path, max_retained: usize) -> Result<(), StorageError> {
    let backup_dir = backup_directory(path);
    fs::create_dir_all(&backup_dir)?;
    let timestamp = unix_seconds_now();
    let backup_path = backup_dir.join(format!("backup-{timestamp}.npw"));
    fs::copy(path, &backup_path)?;
    set_secure_permissions(&backup_path)?;
    compact_backups(&backup_dir, max_retained, timestamp)?;
    Ok(())
}

fn backup_directory(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.npw");
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{file_name}.backups"))
}

fn preserve_corrupt_vault(vault_path: &Path) -> Result<Option<PathBuf>, StorageError> {
    if !vault_path.exists() {
        return Ok(None);
    }

    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = vault_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.npw");
    let mut corrupt_path = parent.join(format!("{file_name}.corrupt"));
    if corrupt_path.exists() {
        corrupt_path = parent.join(format!("{file_name}.corrupt-{}", unix_seconds_now()));
    }

    fs::rename(vault_path, &corrupt_path)?;
    Ok(Some(corrupt_path))
}

fn compact_backups(
    backup_dir: &Path,
    max_weekly_retained: usize,
    now_seconds: u64,
) -> Result<(), StorageError> {
    let mut backups = Vec::new();
    for entry in fs::read_dir(backup_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(timestamp) = parse_backup_timestamp(&path) {
            backups.push((path, timestamp));
        }
    }

    backups.sort_by(|left, right| right.1.cmp(&left.1));

    let mut keep = HashSet::new();
    let mut day_buckets: HashMap<u64, PathBuf> = HashMap::new();
    let mut week_buckets: HashMap<u64, PathBuf> = HashMap::new();

    for (path, timestamp) in &backups {
        let age = now_seconds.saturating_sub(*timestamp);
        if age <= DAY_SECONDS {
            keep.insert(path.clone());
            continue;
        }
        if age <= 8 * DAY_SECONDS {
            let day_bucket = age / DAY_SECONDS;
            day_buckets
                .entry(day_bucket)
                .or_insert_with(|| path.clone());
            continue;
        }
        let week_bucket = age / WEEK_SECONDS;
        week_buckets
            .entry(week_bucket)
            .or_insert_with(|| path.clone());
    }

    keep.extend(day_buckets.into_values());

    let mut weekly: Vec<PathBuf> = week_buckets.into_values().collect();
    weekly.sort_by_key(|path| {
        parse_backup_timestamp(path)
            .map(std::cmp::Reverse)
            .unwrap_or(std::cmp::Reverse(0))
    });
    for path in weekly.into_iter().take(max_weekly_retained) {
        keep.insert(path);
    }

    for (path, _) in backups {
        if !keep.contains(&path) {
            fs::remove_file(path)?;
        }
    }

    Ok(())
}

fn parse_backup_timestamp(path: &Path) -> Option<u64> {
    let file_name = path.file_name()?.to_str()?;
    if !file_name.starts_with("backup-") || !file_name.ends_with(".npw") {
        return None;
    }
    let raw = file_name.strip_prefix("backup-")?.strip_suffix(".npw")?;
    raw.parse::<u64>().ok()
}

fn write_vault_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
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

fn set_secure_permissions(_path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{
        StorageError, acquire_vault_lock, backup_directory, compact_backups, list_backups,
        lock_file_path, parse_backup_timestamp, read_vault, recover_from_backup, write_vault,
        write_vault_with_lock,
    };

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
        write_vault(&path, payload, 10).expect("write should succeed");
        let loaded = read_vault(&path).expect("read should succeed");
        fs::remove_file(path).expect("cleanup should succeed");
        assert_eq!(loaded, payload);
    }

    #[test]
    fn returns_locked_when_lock_is_held() {
        let path = temp_path("locked.npw");
        let lock_path = lock_file_path(&path);
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).expect("create lock parent");
        }
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open lock file");
        fs2::FileExt::try_lock_exclusive(&lock_file).expect("lock must succeed");

        let result = write_vault(&path, b"payload", 10);
        fs2::FileExt::unlock(&lock_file).expect("unlock lock file");

        assert!(matches!(result, Err(StorageError::Locked)));
        let _ = fs::remove_file(lock_path);
    }

    #[test]
    fn write_vault_with_lock_succeeds_when_lock_is_held() {
        let path = temp_path("write-with-lock.npw");
        let lock = acquire_vault_lock(&path).expect("acquire vault lock");
        write_vault_with_lock(&lock, b"payload", 10).expect("write with lock should succeed");
        let loaded = read_vault(&path).expect("read should succeed");
        assert_eq!(loaded, b"payload");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn compaction_keeps_expected_backup_windows() {
        let vault_path = temp_path("backup-source.npw");
        fs::write(&vault_path, b"seed").expect("seed write");
        let backup_dir = backup_directory(&vault_path);
        fs::create_dir_all(&backup_dir).expect("create backup dir");
        let now = 10_000_000_u64;
        let backup_times = [
            now - 100,
            now - 1_000,
            now - (2 * 24 * 60 * 60),
            now - (2 * 24 * 60 * 60) - 300,
            now - (10 * 24 * 60 * 60),
            now - (11 * 24 * 60 * 60),
            now - (18 * 24 * 60 * 60),
            now - (40 * 24 * 60 * 60),
        ];
        for timestamp in backup_times {
            let path = backup_dir.join(format!("backup-{timestamp}.npw"));
            fs::write(path, b"b").expect("write backup file");
        }

        compact_backups(&backup_dir, 2, now).expect("compaction should succeed");

        let mut remaining = Vec::new();
        for entry in fs::read_dir(&backup_dir).expect("read backup dir") {
            let entry = entry.expect("read backup entry");
            if let Some(timestamp) = parse_backup_timestamp(&entry.path()) {
                remaining.push(timestamp);
            }
        }
        remaining.sort_unstable();

        assert!(remaining.contains(&(now - 100)));
        assert!(remaining.contains(&(now - 1_000)));
        assert!(remaining.contains(&(now - (2 * 24 * 60 * 60))));
        assert!(!remaining.contains(&(now - (2 * 24 * 60 * 60) - 300)));

        let _ = fs::remove_dir_all(backup_dir);
        let _ = fs::remove_file(vault_path);
    }

    #[test]
    fn list_backups_returns_newest_first() {
        let vault_path = temp_path("list-backups-source.npw");
        fs::write(&vault_path, b"seed").expect("seed write");
        let backup_dir = backup_directory(&vault_path);
        fs::create_dir_all(&backup_dir).expect("create backup dir");

        for timestamp in [100_u64, 300, 200] {
            let path = backup_dir.join(format!("backup-{timestamp}.npw"));
            fs::write(path, b"backup").expect("write backup");
        }

        let backups = list_backups(&vault_path).expect("list backups");
        let timestamps: Vec<u64> = backups.iter().map(|entry| entry.timestamp).collect();
        assert_eq!(timestamps, vec![300, 200, 100]);

        let _ = fs::remove_dir_all(backup_dir);
        let _ = fs::remove_file(vault_path);
    }

    #[test]
    fn recover_from_backup_restores_and_preserves_corrupt_vault() {
        let vault_path = temp_path("recover-source.npw");
        fs::write(&vault_path, b"corrupt").expect("write corrupt vault");
        let backup_dir = backup_directory(&vault_path);
        fs::create_dir_all(&backup_dir).expect("create backup dir");
        let backup_path = backup_dir.join("backup-123.npw");
        fs::write(&backup_path, b"good").expect("write backup bytes");

        let corrupt_path =
            recover_from_backup(&vault_path, &backup_path).expect("recover should succeed");

        let restored = fs::read(&vault_path).expect("read restored vault");
        assert_eq!(restored, b"good");
        let corrupt_path = corrupt_path.expect("corrupt vault should be preserved");
        let moved = fs::read(&corrupt_path).expect("read moved corrupt vault");
        assert_eq!(moved, b"corrupt");

        let _ = fs::remove_dir_all(backup_dir);
        let _ = fs::remove_file(corrupt_path);
        let _ = fs::remove_file(vault_path);
    }
}
