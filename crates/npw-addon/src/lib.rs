use std::time::{SystemTime, UNIX_EPOCH};

use napi::{Error, Result, Status};
use napi_derive::napi;
use npw_core::{
    CreateVaultInput, KdfParams, create_vault_file, parse_vault_header, unlock_vault_file,
};
use npw_storage::{read_vault, write_vault_atomic};

#[napi(object)]
pub struct VaultStatus {
    pub path: String,
    pub label: String,
    pub item_count: u32,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
}

#[napi]
pub fn core_banner() -> String {
    npw_core::bootstrap_banner()
}

#[napi]
pub fn vault_create(
    path: String,
    master_password: String,
    vault_label: Option<String>,
) -> Result<()> {
    let path_ref = std::path::Path::new(&path);
    let payload = empty_payload_cbor()?;
    let vault = create_vault_file(&CreateVaultInput {
        master_password: &master_password,
        payload_plaintext: &payload,
        item_count: 0,
        vault_label: vault_label.as_deref(),
        kdf_params: KdfParams::default(),
    })
    .map_err(|error| error_to_napi(error.to_string()))?;
    write_vault_atomic(path_ref, &vault).map_err(|error| error_to_napi(error.to_string()))?;
    Ok(())
}

#[napi]
pub fn vault_status(path: String) -> Result<VaultStatus> {
    let path_ref = std::path::Path::new(&path);
    let bytes = read_vault(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let header = parse_vault_header(&bytes).map_err(|error| error_to_napi(error.to_string()))?;
    Ok(VaultStatus {
        path,
        label: header.vault_label,
        item_count: header.item_count,
        kdf_memory_kib: header.kdf_params.memory_kib,
        kdf_iterations: header.kdf_params.iterations,
        kdf_parallelism: header.kdf_params.parallelism,
    })
}

#[napi]
pub fn vault_check(path: String, master_password: String) -> Result<VaultStatus> {
    let path_ref = std::path::Path::new(&path);
    let bytes = read_vault(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let unlocked = unlock_vault_file(&bytes, &master_password)
        .map_err(|error| error_to_napi(error.to_string()))?;
    Ok(VaultStatus {
        path,
        label: unlocked.header.vault_label,
        item_count: unlocked.header.item_count,
        kdf_memory_kib: unlocked.header.kdf_params.memory_kib,
        kdf_iterations: unlocked.header.kdf_params.iterations,
        kdf_parallelism: unlocked.header.kdf_params.parallelism,
    })
}

fn error_to_napi(message: String) -> Error {
    Error::new(Status::GenericFailure, message)
}

fn empty_payload_cbor() -> Result<Vec<u8>> {
    let payload = serde_json::json!({
        "schema": 1,
        "app": {
            "name": "npw",
            "version": env!("CARGO_PKG_VERSION")
        },
        "updated_at": unix_seconds_now(),
        "items": [],
        "tombstones": [],
        "settings": {},
        "search_index": []
    });
    let mut output = Vec::new();
    ciborium::ser::into_writer(&payload, &mut output)
        .map_err(|error| error_to_napi(error.to_string()))?;
    Ok(output)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    #[test]
    fn exposes_core_banner() {
        assert!(super::core_banner().contains("npw"));
    }
}
