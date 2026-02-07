use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use npw_storage::{StorageError, write_vault};

fn temp_vault_path() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "npw-storage-lock-test-{}-{nanos}.npw",
        std::process::id()
    ))
}

#[test]
fn write_vault_returns_locked_when_other_process_holds_lock() {
    let path = temp_vault_path();

    let mut child = Command::new(env!("CARGO_BIN_EXE_lock_holder"))
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn lock holder");

    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let start = Instant::now();
    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .expect("read lock holder output")
            == 0
        {
            panic!("lock holder exited unexpectedly");
        }
        if line.contains("LOCK_ACQUIRED") {
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("timed out waiting for lock holder");
        }
    }

    let result = write_vault(&path, b"payload", 10);
    assert!(matches!(result, Err(StorageError::Locked)));

    // Release the child cleanly by closing stdin; fall back to kill if needed.
    drop(child.stdin.take());
    let _ = child.kill();
    let _ = child.wait();

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_file_name(format!(
        ".{}.lock",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault")
    )));
}
