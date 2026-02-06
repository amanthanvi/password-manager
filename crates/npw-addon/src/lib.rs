use std::time::{SystemTime, UNIX_EPOCH};

use napi::{Error, Result, Status};
use napi_derive::napi;
use npw_core::{
    CreateVaultInput, KdfParams, VaultItem, VaultPayload, assess_master_password,
    create_vault_file, parse_vault_header, unlock_vault_file, unlock_vault_file_with_kek,
};
use npw_storage::{read_vault, write_vault};
use zeroize::Zeroize;

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
    let assessment = assess_master_password(&master_password);
    if !assessment.meets_policy() {
        return Err(error_to_napi(assessment.rejection_message()));
    }
    let payload = VaultPayload::new("npw", env!("CARGO_PKG_VERSION"), unix_seconds_now())
        .to_cbor()
        .map_err(|error| error_to_napi(error.to_string()))?;
    let vault = create_vault_file(&CreateVaultInput {
        master_password: &master_password,
        payload_plaintext: &payload,
        item_count: 0,
        vault_label: vault_label.as_deref(),
        kdf_params: KdfParams::default(),
    })
    .map_err(|error| error_to_napi(error.to_string()))?;
    write_vault(path_ref, &vault, 10).map_err(|error| error_to_napi(error.to_string()))?;
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

#[napi(object)]
pub struct ItemSummary {
    pub id: String,
    pub item_type: String,
    pub title: String,
    pub subtitle: Option<String>,
    pub url: Option<String>,
    pub favorite: bool,
    pub has_totp: bool,
    pub updated_at: u32,
    pub tags: Vec<String>,
}

#[napi]
pub struct VaultSession {
    path: String,
    unlocked: npw_core::UnlockedVaultWithKek,
    payload: VaultPayload,
}

#[napi]
impl VaultSession {
    #[napi]
    pub fn status(&self) -> VaultStatus {
        VaultStatus {
            path: self.path.clone(),
            label: self.unlocked.header.vault_label.clone(),
            item_count: self.unlocked.header.item_count,
            kdf_memory_kib: self.unlocked.header.kdf_params.memory_kib,
            kdf_iterations: self.unlocked.header.kdf_params.iterations,
            kdf_parallelism: self.unlocked.header.kdf_params.parallelism,
        }
    }

    #[napi]
    pub fn list_items(&self, query: Option<String>) -> Vec<ItemSummary> {
        let items: Vec<&VaultItem> = match query.as_deref() {
            Some(value) => self.payload.search_items(value),
            None => self.payload.list_items(None),
        };
        let mut summaries: Vec<ItemSummary> = items.into_iter().map(summarize_item).collect();
        summaries.sort_by(|left, right| {
            right
                .favorite
                .cmp(&left.favorite)
                .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
        });
        summaries
    }

    #[napi]
    pub fn lock(&mut self) {
        self.payload = VaultPayload::new("npw", env!("CARGO_PKG_VERSION"), unix_seconds_now());
        self.unlocked.payload_plaintext.zeroize();
        self.unlocked.payload_plaintext.clear();
    }
}

#[napi]
pub fn vault_unlock(path: String, master_password: String) -> Result<VaultSession> {
    let path_ref = std::path::Path::new(&path);
    let bytes = read_vault(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let mut unlocked = unlock_vault_file_with_kek(&bytes, &master_password)
        .map_err(|error| error_to_napi(error.to_string()))?;
    let payload = VaultPayload::from_cbor(&unlocked.payload_plaintext)
        .map_err(|error| error_to_napi(error.to_string()))?;
    unlocked.payload_plaintext.zeroize();
    unlocked.payload_plaintext.clear();

    Ok(VaultSession {
        path,
        unlocked,
        payload,
    })
}

fn error_to_napi(message: String) -> Error {
    Error::new(Status::GenericFailure, message)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn summarize_item(item: &VaultItem) -> ItemSummary {
    match item {
        VaultItem::Login(value) => ItemSummary {
            id: value.id.clone(),
            item_type: "login".to_owned(),
            title: value.title.clone(),
            subtitle: value.username.clone(),
            url: value.urls.first().map(|entry| entry.url.clone()),
            favorite: value.favorite,
            has_totp: value.totp.is_some(),
            updated_at: u32::try_from(value.updated_at).unwrap_or(u32::MAX),
            tags: value.tags.clone(),
        },
        VaultItem::Note(value) => ItemSummary {
            id: value.id.clone(),
            item_type: "note".to_owned(),
            title: value.title.clone(),
            subtitle: None,
            url: None,
            favorite: value.favorite,
            has_totp: false,
            updated_at: u32::try_from(value.updated_at).unwrap_or(u32::MAX),
            tags: value.tags.clone(),
        },
        VaultItem::PasskeyRef(value) => ItemSummary {
            id: value.id.clone(),
            item_type: "passkey_ref".to_owned(),
            title: value.title.clone(),
            subtitle: Some(value.rp_id.clone()),
            url: None,
            favorite: value.favorite,
            has_totp: false,
            updated_at: u32::try_from(value.updated_at).unwrap_or(u32::MAX),
            tags: value.tags.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exposes_core_banner() {
        assert!(super::core_banner().contains("npw"));
    }
}
