use std::time::{SystemTime, UNIX_EPOCH};

use napi::{Error, Result, Status};
use napi_derive::napi;
use npw_core::{
    CreateVaultInput, KdfParams, VaultItem, VaultPayload, assess_master_password,
    create_vault_file, generate_totp, parse_vault_header, unlock_vault_file,
    unlock_vault_file_with_kek,
};
use npw_storage::{VaultLock, acquire_vault_lock, read_vault, write_vault};
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

#[napi(object)]
pub struct LoginDetail {
    pub id: String,
    pub title: String,
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub notes: Option<String>,
    pub favorite: bool,
    pub created_at: u32,
    pub updated_at: u32,
    pub tags: Vec<String>,
}

#[napi(object)]
pub struct TotpCode {
    pub code: String,
    pub period: u16,
    pub remaining: u16,
}

#[napi]
pub struct VaultSession {
    path: String,
    lock: Option<VaultLock>,
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
    pub fn get_login(&self, id: String) -> Result<LoginDetail> {
        let item = self
            .payload
            .get_item(&id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;
        let VaultItem::Login(login) = item else {
            return Err(error_to_napi("item is not a login".to_owned()));
        };

        Ok(LoginDetail {
            id: login.id.clone(),
            title: login.title.clone(),
            urls: login.urls.iter().map(|entry| entry.url.clone()).collect(),
            username: login.username.clone(),
            has_password: login.password.is_some(),
            has_totp: login.totp.is_some(),
            notes: login.notes.clone(),
            favorite: login.favorite,
            created_at: u32::try_from(login.created_at).unwrap_or(u32::MAX),
            updated_at: u32::try_from(login.updated_at).unwrap_or(u32::MAX),
            tags: login.tags.clone(),
        })
    }

    #[napi]
    pub fn get_login_password(&self, id: String) -> Result<String> {
        let item = self
            .payload
            .get_item(&id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;
        let VaultItem::Login(login) = item else {
            return Err(error_to_napi("item is not a login".to_owned()));
        };
        login
            .password
            .clone()
            .ok_or_else(|| error_to_napi("login item has no password".to_owned()))
    }

    #[napi]
    pub fn get_login_totp(&self, id: String) -> Result<TotpCode> {
        let item = self
            .payload
            .get_item(&id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;
        let VaultItem::Login(login) = item else {
            return Err(error_to_napi("item is not a login".to_owned()));
        };
        let config = login
            .totp
            .as_ref()
            .ok_or_else(|| error_to_napi("login item has no TOTP".to_owned()))?;

        let now = unix_seconds_now();
        let code = generate_totp(config, now).map_err(|error| error_to_napi(error.to_string()))?;
        let period_seconds = u64::from(config.period);
        let remaining_seconds = period_seconds - (now % period_seconds);
        let remaining = u16::try_from(remaining_seconds).unwrap_or(config.period);

        Ok(TotpCode {
            code,
            period: config.period,
            remaining,
        })
    }

    #[napi]
    pub fn lock(&mut self) {
        self.payload = VaultPayload::new("npw", env!("CARGO_PKG_VERSION"), unix_seconds_now());
        self.unlocked.payload_plaintext.zeroize();
        self.unlocked.payload_plaintext.clear();
        self.lock = None;
    }
}

#[napi]
pub fn vault_unlock(path: String, master_password: String) -> Result<VaultSession> {
    let path_ref = std::path::Path::new(&path);
    let lock = acquire_vault_lock(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let bytes = read_vault(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let mut unlocked = unlock_vault_file_with_kek(&bytes, &master_password)
        .map_err(|error| error_to_napi(error.to_string()))?;
    let payload = VaultPayload::from_cbor(&unlocked.payload_plaintext)
        .map_err(|error| error_to_napi(error.to_string()))?;
    unlocked.payload_plaintext.zeroize();
    unlocked.payload_plaintext.clear();

    Ok(VaultSession {
        path,
        lock: Some(lock),
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
    use npw_core::{LoginItem, UrlEntry, UrlMatchType, VaultItem};

    #[test]
    fn exposes_core_banner() {
        assert!(super::core_banner().contains("npw"));
    }

    #[test]
    fn summarizes_login_item_without_secrets() {
        let item = VaultItem::Login(LoginItem {
            id: "00000000-0000-0000-0000-000000000000".to_owned(),
            title: "Example".to_owned(),
            urls: vec![UrlEntry {
                url: "https://example.com".to_owned(),
                match_type: UrlMatchType::Exact,
            }],
            username: Some("user@example.com".to_owned()),
            password: Some("s3cr3t".to_owned()),
            totp: None,
            notes: Some("note".to_owned()),
            tags: vec!["prod".to_owned()],
            favorite: true,
            created_at: 1,
            updated_at: 2,
        });

        let summary = super::summarize_item(&item);
        assert_eq!(summary.id, "00000000-0000-0000-0000-000000000000");
        assert_eq!(summary.item_type, "login");
        assert_eq!(summary.title, "Example");
        assert_eq!(summary.subtitle.as_deref(), Some("user@example.com"));
        assert_eq!(summary.url.as_deref(), Some("https://example.com"));
        assert!(summary.favorite);
        assert!(!summary.has_totp);
        assert_eq!(summary.updated_at, 2);
        assert_eq!(summary.tags, vec!["prod"]);
    }
}
