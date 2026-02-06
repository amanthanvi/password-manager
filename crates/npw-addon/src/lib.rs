use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use keyring::Entry;
use napi::{Error, Result, Status};
use napi_derive::napi;
use npw_core::{
    CreateVaultInput, KdfParams, LoginItem, NoteItem, TotpAlgorithm, TotpConfig, UrlEntry,
    UrlMatchType, VaultItem, VaultPayload, assess_master_password, create_vault_file,
    decode_base32_secret, generate_totp, parse_otpauth_uri, parse_vault_header,
    reencrypt_vault_file_with_kek, unlock_vault_file, unlock_vault_file_with_existing_kek,
    unlock_vault_file_with_kek,
};
use npw_storage::{
    VaultLock, acquire_vault_lock, list_backups, read_vault, recover_from_backup, write_vault,
    write_vault_with_lock,
};
use qrcode::QrCode;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroize;

mod config;

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
        label: unlocked.header.vault_label.clone(),
        item_count: unlocked.header.item_count,
        kdf_memory_kib: unlocked.header.kdf_params.memory_kib,
        kdf_iterations: unlocked.header.kdf_params.iterations,
        kdf_parallelism: unlocked.header.kdf_params.parallelism,
    })
}

#[napi(object)]
pub struct SecurityConfig {
    pub clipboard_timeout_seconds: u32,
    pub auto_lock_minutes: u32,
    pub lock_on_suspend: bool,
    pub reveal_requires_confirm: bool,
}

#[napi(object)]
pub struct GeneratorConfig {
    pub default_mode: String,
    pub charset_length: u32,
    pub charset_uppercase: bool,
    pub charset_lowercase: bool,
    pub charset_digits: bool,
    pub charset_symbols: bool,
    pub charset_avoid_ambiguous: bool,
    pub diceware_words: u32,
    pub diceware_separator: String,
}

#[napi(object)]
pub struct LoggingConfig {
    pub level: String,
}

#[napi(object)]
pub struct BackupConfig {
    pub max_retained: u32,
}

#[napi(object)]
pub struct AppConfig {
    pub config_path: String,
    pub default_vault: Option<String>,
    pub security: SecurityConfig,
    pub generator: GeneratorConfig,
    pub logging: LoggingConfig,
    pub backup: BackupConfig,
}

#[napi]
pub fn config_load() -> Result<AppConfig> {
    let (config, config_path) =
        config::load_config(None).map_err(|error| error_to_napi(error.to_string()))?;
    Ok(app_config_view(config, config_path))
}

#[napi]
pub fn config_set(key: String, value: String) -> Result<AppConfig> {
    let (mut config, config_path) =
        config::load_config(None).map_err(|error| error_to_napi(error.to_string()))?;
    let key_trimmed = key.trim();
    if key_trimmed.is_empty() {
        return Err(error_to_napi("config key cannot be empty".to_owned()));
    }
    config::config_set(&mut config, key_trimmed, &value)
        .map_err(|error| error_to_napi(error.to_string()))?;
    config::save_config(&config, &config_path).map_err(|error| error_to_napi(error.to_string()))?;
    Ok(app_config_view(config, config_path))
}

fn app_config_view(config: config::AppConfig, config_path: std::path::PathBuf) -> AppConfig {
    let default_mode = match config.generator.default_mode {
        config::GenerateMode::Charset => "charset",
        config::GenerateMode::Diceware => "diceware",
    };
    AppConfig {
        config_path: config_path.to_string_lossy().to_string(),
        default_vault: config.default_vault,
        security: SecurityConfig {
            clipboard_timeout_seconds: config.security.clipboard_timeout_seconds,
            auto_lock_minutes: config.security.auto_lock_minutes,
            lock_on_suspend: config.security.lock_on_suspend,
            reveal_requires_confirm: config.security.reveal_requires_confirm,
        },
        generator: GeneratorConfig {
            default_mode: default_mode.to_owned(),
            charset_length: u32::try_from(config.generator.charset_length).unwrap_or(u32::MAX),
            charset_uppercase: config.generator.charset_uppercase,
            charset_lowercase: config.generator.charset_lowercase,
            charset_digits: config.generator.charset_digits,
            charset_symbols: config.generator.charset_symbols,
            charset_avoid_ambiguous: config.generator.charset_avoid_ambiguous,
            diceware_words: u32::try_from(config.generator.diceware_words).unwrap_or(u32::MAX),
            diceware_separator: config.generator.diceware_separator,
        },
        logging: LoggingConfig {
            level: config.logging.level,
        },
        backup: BackupConfig {
            max_retained: u32::try_from(config.backup.max_retained).unwrap_or(u32::MAX),
        },
    }
}

#[napi(object)]
pub struct BackupCandidate {
    pub path: String,
    pub timestamp: u32,
    pub item_count: u32,
    pub label: String,
}

#[napi(object)]
pub struct VaultRecoveryResult {
    pub corrupt_path: Option<String>,
}

#[napi]
pub fn vault_list_backups(path: String) -> Result<Vec<BackupCandidate>> {
    let path_ref = std::path::Path::new(&path);
    let backups = list_backups(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let mut candidates = Vec::new();

    for backup in backups {
        let bytes = read_vault(&backup.path).map_err(|error| error_to_napi(error.to_string()))?;
        if let Ok(header) = parse_vault_header(&bytes) {
            candidates.push(BackupCandidate {
                path: backup.path.to_string_lossy().to_string(),
                timestamp: u32::try_from(backup.timestamp).unwrap_or(u32::MAX),
                item_count: header.item_count,
                label: header.vault_label,
            });
        }
    }

    Ok(candidates)
}

#[napi]
pub fn vault_recover_from_backup(
    vault_path: String,
    backup_path: String,
) -> Result<VaultRecoveryResult> {
    let vault_path_ref = std::path::Path::new(&vault_path);
    let backup_path_ref = std::path::Path::new(&backup_path);
    let corrupt_path = recover_from_backup(vault_path_ref, backup_path_ref)
        .map_err(|error| error_to_napi(error.to_string()))?;
    Ok(VaultRecoveryResult {
        corrupt_path: corrupt_path.map(|path| path.to_string_lossy().to_string()),
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
pub struct UrlEntryView {
    pub url: String,
    pub match_type: String,
}

#[napi(object)]
pub struct LoginDetail {
    pub id: String,
    pub title: String,
    pub urls: Vec<UrlEntryView>,
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
pub struct NoteDetail {
    pub id: String,
    pub title: String,
    pub body: String,
    pub favorite: bool,
    pub created_at: u32,
    pub updated_at: u32,
    pub tags: Vec<String>,
}

#[napi(object)]
pub struct PasskeyRefDetail {
    pub id: String,
    pub title: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub credential_id_hex: String,
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

#[napi(object)]
pub struct ImportDuplicate {
    pub source_index: u32,
    pub item_type: String,
    pub title: String,
    pub username: Option<String>,
    pub primary_url: Option<String>,
    pub existing_id: String,
    pub existing_title: String,
    pub existing_username: Option<String>,
    pub existing_primary_url: Option<String>,
}

#[napi(object)]
pub struct ImportPreview {
    pub import_type: String,
    pub candidates: u32,
    pub duplicates: Vec<ImportDuplicate>,
    pub warnings: Vec<String>,
}

#[napi(object)]
pub struct ImportDuplicateDecision {
    pub source_index: u32,
    pub action: String,
}

#[napi(object)]
pub struct ImportResult {
    pub imported: u32,
    pub skipped: u32,
    pub overwritten: u32,
    pub warnings: Vec<String>,
}

#[napi(object)]
pub struct UrlEntryInput {
    pub url: String,
    pub match_type: Option<String>,
}

#[napi(object)]
pub struct AddLoginInput {
    pub title: String,
    pub urls: Option<Vec<UrlEntryInput>>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
}

#[napi(object)]
pub struct UpdateLoginInput {
    pub id: String,
    pub title: String,
    pub urls: Option<Vec<UrlEntryInput>>,
    pub username: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
}

#[napi(object)]
pub struct AddNoteInput {
    pub title: String,
    pub body: String,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
}

#[napi(object)]
pub struct UpdateNoteInput {
    pub id: String,
    pub title: String,
    pub body: String,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
}

#[napi(object)]
pub struct AddPasskeyRefInput {
    pub title: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_display_name: Option<String>,
    pub credential_id_hex: String,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
}

#[napi(object)]
pub struct UpdatePasskeyRefInput {
    pub id: String,
    pub title: String,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
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
    pub fn vault_id_hex(&self) -> String {
        hex_encode(&self.unlocked.envelope.vault_id)
    }

    #[napi]
    pub fn quick_unlock_is_enabled(&self) -> Result<bool> {
        quick_unlock_has_entry_internal(self.vault_id_hex())
    }

    #[napi]
    pub fn quick_unlock_enable(&self) -> Result<bool> {
        let vault_id_hex = self.vault_id_hex();
        let entry =
            quick_unlock_entry(&vault_id_hex).map_err(|error| error_to_napi(error.to_string()))?;
        entry
            .set_secret(self.unlocked.kek())
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(true)
    }

    #[napi]
    pub fn quick_unlock_disable(&self) -> Result<bool> {
        let vault_id_hex = self.vault_id_hex();
        let entry =
            quick_unlock_entry(&vault_id_hex).map_err(|error| error_to_napi(error.to_string()))?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(error) if is_keyring_no_entry(&error) => Ok(false),
            Err(error) => Err(error_to_napi(error.to_string())),
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
            urls: login
                .urls
                .iter()
                .map(|entry| UrlEntryView {
                    url: entry.url.clone(),
                    match_type: url_match_type_name(entry.match_type.clone()).to_owned(),
                })
                .collect(),
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
    pub fn get_note(&self, id: String) -> Result<NoteDetail> {
        let item = self
            .payload
            .get_item(&id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;
        let VaultItem::Note(note) = item else {
            return Err(error_to_napi("item is not a note".to_owned()));
        };

        Ok(NoteDetail {
            id: note.id.clone(),
            title: note.title.clone(),
            body: note.body.clone(),
            favorite: note.favorite,
            created_at: u32::try_from(note.created_at).unwrap_or(u32::MAX),
            updated_at: u32::try_from(note.updated_at).unwrap_or(u32::MAX),
            tags: note.tags.clone(),
        })
    }

    #[napi]
    pub fn get_passkey_ref(&self, id: String) -> Result<PasskeyRefDetail> {
        let item = self
            .payload
            .get_item(&id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;
        let VaultItem::PasskeyRef(passkey) = item else {
            return Err(error_to_napi("item is not a passkey reference".to_owned()));
        };

        Ok(PasskeyRefDetail {
            id: passkey.id.clone(),
            title: passkey.title.clone(),
            rp_id: passkey.rp_id.clone(),
            rp_name: passkey.rp_name.clone(),
            user_display_name: passkey.user_display_name.clone(),
            credential_id_hex: hex_encode(&passkey.credential_id),
            notes: passkey.notes.clone(),
            favorite: passkey.favorite,
            created_at: u32::try_from(passkey.created_at).unwrap_or(u32::MAX),
            updated_at: u32::try_from(passkey.updated_at).unwrap_or(u32::MAX),
            tags: passkey.tags.clone(),
        })
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
    pub fn get_login_totp_qr_svg(&self, id: String) -> Result<String> {
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

        let uri = login_totp_uri(&login.title, login.username.as_deref(), config);
        let code = QrCode::new(uri.as_bytes()).map_err(|error| error_to_napi(error.to_string()))?;
        Ok(code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(256, 256)
            .build())
    }

    #[napi]
    pub fn set_login_totp(&mut self, id: String, value: String) -> Result<bool> {
        let now = unix_seconds_now();
        let index = self
            .payload
            .items
            .iter()
            .position(|item| item.id() == id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;

        let VaultItem::Login(login) = &mut self.payload.items[index] else {
            return Err(error_to_napi("item is not a login".to_owned()));
        };

        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(error_to_napi("TOTP value is empty".to_owned()));
        }

        let config = if trimmed.starts_with("otpauth://") {
            parse_otpauth_uri(trimmed).map_err(|error| error_to_napi(error.to_string()))?
        } else {
            TotpConfig {
                seed: decode_base32_secret(trimmed)
                    .map_err(|error| error_to_napi(error.to_string()))?,
                issuer: None,
                algorithm: TotpAlgorithm::SHA1,
                digits: 6,
                period: 30,
            }
        };

        login.totp = Some(config);
        login.updated_at = now;
        login
            .validate()
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.payload.updated_at = now;
        self.payload.rebuild_search_index();
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(true)
    }

    #[napi]
    pub fn add_note(&mut self, input: AddNoteInput) -> Result<String> {
        let now = unix_seconds_now();
        let id = Uuid::new_v4().to_string();
        let note = NoteItem {
            id: id.clone(),
            title: input.title,
            body: input.body,
            tags: normalize_tags(input.tags),
            favorite: input.favorite.unwrap_or(false),
            created_at: now,
            updated_at: now,
        };

        self.payload
            .add_item(VaultItem::Note(note), now)
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(id)
    }

    #[napi]
    pub fn update_note(&mut self, input: UpdateNoteInput) -> Result<bool> {
        let now = unix_seconds_now();
        let index = self
            .payload
            .items
            .iter()
            .position(|item| item.id() == input.id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;

        let VaultItem::Note(note) = &mut self.payload.items[index] else {
            return Err(error_to_napi("item is not a note".to_owned()));
        };

        note.title = input.title;
        note.body = input.body;
        if let Some(tags) = input.tags {
            note.tags = normalize_tags(Some(tags));
        }
        if let Some(favorite) = input.favorite {
            note.favorite = favorite;
        }
        note.updated_at = now;
        note.validate()
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.payload.updated_at = now;
        self.payload.rebuild_search_index();
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(true)
    }

    #[napi]
    pub fn add_login(&mut self, input: AddLoginInput) -> Result<String> {
        let now = unix_seconds_now();
        let id = Uuid::new_v4().to_string();
        let urls = normalize_urls(input.urls)?;
        let username = input.username.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });

        let password = input
            .password
            .and_then(|value| if value.is_empty() { None } else { Some(value) });
        let notes = input
            .notes
            .and_then(|value| if value.is_empty() { None } else { Some(value) });

        let login = LoginItem {
            id: id.clone(),
            title: input.title,
            urls,
            username,
            password,
            totp: None,
            notes,
            tags: normalize_tags(input.tags),
            favorite: input.favorite.unwrap_or(false),
            created_at: now,
            updated_at: now,
        };

        self.payload
            .add_item(VaultItem::Login(login), now)
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(id)
    }

    #[napi]
    pub fn update_login(&mut self, input: UpdateLoginInput) -> Result<bool> {
        let now = unix_seconds_now();
        let index = self
            .payload
            .items
            .iter()
            .position(|item| item.id() == input.id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;

        let VaultItem::Login(login) = &mut self.payload.items[index] else {
            return Err(error_to_napi("item is not a login".to_owned()));
        };

        login.title = input.title;
        if input.urls.is_some() {
            login.urls = normalize_urls(input.urls)?;
        }
        login.username = input.username.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });
        login.notes = input
            .notes
            .and_then(|value| if value.is_empty() { None } else { Some(value) });
        if let Some(tags) = input.tags {
            login.tags = normalize_tags(Some(tags));
        }
        if let Some(favorite) = input.favorite {
            login.favorite = favorite;
        }
        login.updated_at = now;
        login
            .validate()
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.payload.updated_at = now;
        self.payload.rebuild_search_index();
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(true)
    }

    #[napi]
    pub fn update_passkey_ref(&mut self, input: UpdatePasskeyRefInput) -> Result<bool> {
        let now = unix_seconds_now();
        let index = self
            .payload
            .items
            .iter()
            .position(|item| item.id() == input.id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;

        let VaultItem::PasskeyRef(passkey) = &mut self.payload.items[index] else {
            return Err(error_to_napi("item is not a passkey reference".to_owned()));
        };

        passkey.title = input.title;
        passkey.notes = input
            .notes
            .and_then(|value| if value.is_empty() { None } else { Some(value) });
        if let Some(tags) = input.tags {
            passkey.tags = normalize_tags(Some(tags));
        }
        if let Some(favorite) = input.favorite {
            passkey.favorite = favorite;
        }
        passkey.updated_at = now;
        passkey
            .validate()
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.payload.updated_at = now;
        self.payload.rebuild_search_index();
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(true)
    }

    #[napi]
    pub fn add_passkey_ref(&mut self, input: AddPasskeyRefInput) -> Result<String> {
        let now = unix_seconds_now();
        let id = Uuid::new_v4().to_string();
        let credential_id = hex_decode(input.credential_id_hex.trim())?;
        let rp_name = input.rp_name.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });
        let user_display_name = input.user_display_name.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        });
        let notes = input
            .notes
            .and_then(|value| if value.is_empty() { None } else { Some(value) });

        let passkey = npw_core::PasskeyRefItem {
            id: id.clone(),
            title: input.title,
            rp_id: input.rp_id,
            rp_name,
            user_display_name,
            credential_id,
            notes,
            tags: normalize_tags(input.tags),
            favorite: input.favorite.unwrap_or(false),
            created_at: now,
            updated_at: now,
        };

        self.payload
            .add_item(VaultItem::PasskeyRef(passkey), now)
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(id)
    }

    #[napi]
    pub fn import_csv_preview(&self, input_path: String) -> Result<ImportPreview> {
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(&input_path)
            .map_err(|error| error_to_napi(error.to_string()))?;
        let headers = reader
            .headers()
            .map_err(|error| error_to_napi(error.to_string()))?
            .clone();
        let supported_headers = std::collections::HashSet::from([
            "type", "title", "username", "password", "url", "notes", "tags", "totp_uri",
        ]);
        let mut warnings = Vec::new();
        for header in &headers {
            if !supported_headers.contains(header) {
                warnings.push(format!("ignored unknown column `{header}`"));
            }
        }

        let login_index = build_login_duplicate_index(&self.payload);
        let mut duplicates = Vec::new();
        let mut candidates = 0_u32;

        for (row_index, result) in reader.records().enumerate() {
            let row_number = u32::try_from(row_index + 2).unwrap_or(u32::MAX);
            let row = result.map_err(|error| error_to_napi(error.to_string()))?;
            let item_type = csv_cell(&headers, &row, "type")
                .unwrap_or("login")
                .trim()
                .to_ascii_lowercase();
            let title = csv_cell(&headers, &row, "title")
                .unwrap_or_default()
                .trim()
                .to_owned();
            if title.is_empty() {
                warnings.push(format!(
                    "row {row_number} skipped: missing required `title`"
                ));
                continue;
            }

            match item_type.as_str() {
                "login" => {
                    let username = normalize_optional_cell(csv_cell(&headers, &row, "username"));
                    let primary_url = normalize_optional_cell(csv_cell(&headers, &row, "url"));
                    let key =
                        login_duplicate_key(&title, username.as_deref(), primary_url.as_deref());
                    candidates = candidates.saturating_add(1);
                    if let Some(existing_id) = login_index.get(&key)
                        && let Some(VaultItem::Login(existing)) =
                            self.payload.get_item(existing_id.as_str())
                    {
                        duplicates.push(ImportDuplicate {
                            source_index: row_number,
                            item_type: "login".to_owned(),
                            title: title.clone(),
                            username: username.clone(),
                            primary_url: primary_url.clone(),
                            existing_id: existing.id.clone(),
                            existing_title: existing.title.clone(),
                            existing_username: existing.username.clone(),
                            existing_primary_url: existing
                                .urls
                                .first()
                                .map(|entry| entry.url.clone()),
                        });
                    }
                }
                "note" => {
                    candidates = candidates.saturating_add(1);
                }
                other => {
                    warnings.push(format!(
                        "row {row_number} skipped: unsupported `type` value `{other}`"
                    ));
                }
            }
        }

        Ok(ImportPreview {
            import_type: "csv".to_owned(),
            candidates,
            duplicates,
            warnings,
        })
    }

    #[napi]
    pub fn import_csv_apply(
        &mut self,
        input_path: String,
        decisions: Vec<ImportDuplicateDecision>,
    ) -> Result<ImportResult> {
        let now = unix_seconds_now();
        let decision_map = parse_duplicate_decisions(decisions)?;

        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .from_path(&input_path)
            .map_err(|error| error_to_napi(error.to_string()))?;
        let headers = reader
            .headers()
            .map_err(|error| error_to_napi(error.to_string()))?
            .clone();
        let supported_headers = std::collections::HashSet::from([
            "type", "title", "username", "password", "url", "notes", "tags", "totp_uri",
        ]);
        let mut warnings = Vec::new();
        for header in &headers {
            if !supported_headers.contains(header) {
                warnings.push(format!("ignored unknown column `{header}`"));
            }
        }

        let mut login_index = build_login_duplicate_index(&self.payload);
        let mut imported = 0_u32;
        let mut skipped = 0_u32;
        let mut overwritten = 0_u32;

        for (row_index, result) in reader.records().enumerate() {
            let row_number = u32::try_from(row_index + 2).unwrap_or(u32::MAX);
            let row = result.map_err(|error| error_to_napi(error.to_string()))?;
            let item_type = csv_cell(&headers, &row, "type")
                .unwrap_or("login")
                .trim()
                .to_ascii_lowercase();
            let title = csv_cell(&headers, &row, "title")
                .unwrap_or_default()
                .trim()
                .to_owned();
            if title.is_empty() {
                skipped = skipped.saturating_add(1);
                warnings.push(format!(
                    "row {row_number} skipped: missing required `title`"
                ));
                continue;
            }

            match item_type.as_str() {
                "login" => {
                    let username = normalize_optional_cell(csv_cell(&headers, &row, "username"));
                    let password_field =
                        normalize_optional_cell(csv_cell(&headers, &row, "password"));
                    let primary_url = normalize_optional_cell(csv_cell(&headers, &row, "url"));
                    let notes = normalize_optional_cell(csv_cell(&headers, &row, "notes"));
                    let raw_tags =
                        parse_csv_tags(csv_cell(&headers, &row, "tags").unwrap_or_default());
                    let tags = normalize_tags(Some(raw_tags));
                    let totp_uri = normalize_optional_cell(csv_cell(&headers, &row, "totp_uri"));
                    let totp = if let Some(uri) = totp_uri {
                        match parse_otpauth_uri(&uri) {
                            Ok(config) => Some(config),
                            Err(error) => {
                                skipped = skipped.saturating_add(1);
                                warnings.push(format!(
                                    "row {row_number} skipped: invalid `totp_uri` ({error})"
                                ));
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    let urls = primary_url
                        .clone()
                        .map(|value| {
                            vec![UrlEntry {
                                url: value,
                                match_type: UrlMatchType::Exact,
                            }]
                        })
                        .unwrap_or_default();
                    let key =
                        login_duplicate_key(&title, username.as_deref(), primary_url.as_deref());

                    if let Some(existing_id) = login_index.get(&key).cloned() {
                        let action = decision_map
                            .get(&row_number)
                            .copied()
                            .unwrap_or(DuplicateAction::Skip);
                        match action {
                            DuplicateAction::Skip => {
                                skipped = skipped.saturating_add(1);
                                continue;
                            }
                            DuplicateAction::Overwrite => {
                                if let Some(VaultItem::Login(existing)) = self
                                    .payload
                                    .items
                                    .iter_mut()
                                    .find(|item| item.id() == existing_id)
                                {
                                    existing.title = title.clone();
                                    existing.urls = urls;
                                    existing.username = username;
                                    existing.password = password_field;
                                    existing.totp = totp;
                                    existing.notes = notes;
                                    existing.tags = tags;
                                    existing.favorite = false;
                                    existing.updated_at = now;
                                    overwritten = overwritten.saturating_add(1);
                                    continue;
                                }
                            }
                            DuplicateAction::KeepBoth => {}
                        }
                    }

                    let item = VaultItem::Login(LoginItem {
                        id: Uuid::new_v4().to_string(),
                        title,
                        urls,
                        username,
                        password: password_field,
                        totp,
                        notes,
                        tags,
                        favorite: false,
                        created_at: now,
                        updated_at: now,
                    });
                    let item_id = item.id().to_owned();
                    self.payload
                        .add_item(item, now)
                        .map_err(|error| error_to_napi(error.to_string()))?;
                    login_index.insert(key, item_id);
                    imported = imported.saturating_add(1);
                }
                "note" => {
                    let body = csv_cell(&headers, &row, "notes")
                        .unwrap_or_default()
                        .to_owned();
                    let raw_tags =
                        parse_csv_tags(csv_cell(&headers, &row, "tags").unwrap_or_default());
                    let tags = normalize_tags(Some(raw_tags));
                    let item = VaultItem::Note(NoteItem {
                        id: Uuid::new_v4().to_string(),
                        title,
                        body,
                        tags,
                        favorite: false,
                        created_at: now,
                        updated_at: now,
                    });
                    self.payload
                        .add_item(item, now)
                        .map_err(|error| error_to_napi(error.to_string()))?;
                    imported = imported.saturating_add(1);
                }
                other => {
                    skipped = skipped.saturating_add(1);
                    warnings.push(format!(
                        "row {row_number} skipped: unsupported `type` value `{other}`"
                    ));
                }
            }
        }

        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;

        Ok(ImportResult {
            imported,
            skipped,
            overwritten,
            warnings,
        })
    }

    #[napi]
    pub fn import_bitwarden_json_preview(&self, input_path: String) -> Result<ImportPreview> {
        let raw = std::fs::read(&input_path).map_err(|error| error_to_napi(error.to_string()))?;
        let export: BitwardenExport =
            serde_json::from_slice(&raw).map_err(|error| error_to_napi(error.to_string()))?;

        let login_index = build_login_duplicate_index(&self.payload);
        let mut duplicates = Vec::new();
        let mut warnings = Vec::new();
        let mut candidates = 0_u32;

        for (index, item) in export.items.iter().enumerate() {
            let item_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let title = item.name.trim().to_owned();
            if title.is_empty() {
                warnings.push(format!(
                    "item {item_number} skipped: missing required `name` field"
                ));
                continue;
            }
            if item.r#type != 1 && item.r#type != 2 {
                warnings.push(format!(
                    "item {item_number} skipped: unsupported Bitwarden item type `{}`",
                    item.r#type
                ));
                continue;
            }

            candidates = candidates.saturating_add(1);
            if item.r#type != 1 {
                continue;
            }

            let login = if let Some(login) = &item.login {
                login
            } else {
                warnings.push(format!(
                    "item {item_number} skipped: type=1 but missing `login` object"
                ));
                continue;
            };

            let username = normalize_optional_cell(login.username.as_deref());
            let primary_url = login.uris.as_ref().and_then(|uris| {
                uris.iter()
                    .find_map(|entry| normalize_optional_cell(entry.uri.as_deref()))
            });
            let key = login_duplicate_key(&title, username.as_deref(), primary_url.as_deref());
            if let Some(existing_id) = login_index.get(&key)
                && let Some(VaultItem::Login(existing)) =
                    self.payload.get_item(existing_id.as_str())
            {
                duplicates.push(ImportDuplicate {
                    source_index: item_number,
                    item_type: "login".to_owned(),
                    title: title.clone(),
                    username: username.clone(),
                    primary_url: primary_url.clone(),
                    existing_id: existing.id.clone(),
                    existing_title: existing.title.clone(),
                    existing_username: existing.username.clone(),
                    existing_primary_url: existing.urls.first().map(|entry| entry.url.clone()),
                });
            }
        }

        Ok(ImportPreview {
            import_type: "bitwarden-json".to_owned(),
            candidates,
            duplicates,
            warnings,
        })
    }

    #[napi]
    pub fn import_bitwarden_json_apply(
        &mut self,
        input_path: String,
        decisions: Vec<ImportDuplicateDecision>,
    ) -> Result<ImportResult> {
        let now = unix_seconds_now();
        let decision_map = parse_duplicate_decisions(decisions)?;

        let raw = std::fs::read(&input_path).map_err(|error| error_to_napi(error.to_string()))?;
        let export: BitwardenExport =
            serde_json::from_slice(&raw).map_err(|error| error_to_napi(error.to_string()))?;

        let mut warnings = Vec::new();
        let mut login_index = build_login_duplicate_index(&self.payload);
        let mut imported = 0_u32;
        let mut skipped = 0_u32;
        let mut overwritten = 0_u32;

        for (index, item) in export.items.into_iter().enumerate() {
            let item_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
            let title = item.name.trim().to_owned();
            if title.is_empty() {
                skipped = skipped.saturating_add(1);
                warnings.push(format!(
                    "item {item_number} skipped: missing required `name` field"
                ));
                continue;
            }

            match item.r#type {
                1 => {
                    let login = if let Some(login) = item.login {
                        login
                    } else {
                        skipped = skipped.saturating_add(1);
                        warnings.push(format!(
                            "item {item_number} skipped: type=1 but missing `login` object"
                        ));
                        continue;
                    };

                    let username = normalize_optional_cell(login.username.as_deref());
                    let password_field = normalize_optional_cell(login.password.as_deref());
                    let primary_url = login.uris.as_ref().and_then(|uris| {
                        uris.iter()
                            .find_map(|entry| normalize_optional_cell(entry.uri.as_deref()))
                    });
                    let notes = normalize_optional_cell(item.notes.as_deref());
                    let urls = primary_url
                        .clone()
                        .map(|value| {
                            vec![UrlEntry {
                                url: value,
                                match_type: UrlMatchType::Exact,
                            }]
                        })
                        .unwrap_or_default();

                    let totp = if let Some(raw_totp) =
                        normalize_optional_cell(login.totp.as_deref())
                    {
                        if raw_totp.starts_with("otpauth://") {
                            match parse_otpauth_uri(&raw_totp) {
                                Ok(config) => Some(config),
                                Err(error) => {
                                    warnings.push(format!(
                                            "item {item_number} ignored invalid `login.totp` URI ({error})"
                                        ));
                                    None
                                }
                            }
                        } else {
                            match decode_base32_secret(&raw_totp) {
                                Ok(seed) => Some(TotpConfig {
                                    seed,
                                    issuer: None,
                                    algorithm: TotpAlgorithm::SHA1,
                                    digits: 6,
                                    period: 30,
                                }),
                                Err(error) => {
                                    warnings.push(format!(
                                            "item {item_number} ignored invalid `login.totp` secret ({error})"
                                        ));
                                    None
                                }
                            }
                        }
                    } else {
                        None
                    };

                    let key =
                        login_duplicate_key(&title, username.as_deref(), primary_url.as_deref());
                    if let Some(existing_id) = login_index.get(&key).cloned() {
                        let action = decision_map
                            .get(&item_number)
                            .copied()
                            .unwrap_or(DuplicateAction::Skip);
                        match action {
                            DuplicateAction::Skip => {
                                skipped = skipped.saturating_add(1);
                                continue;
                            }
                            DuplicateAction::Overwrite => {
                                if let Some(VaultItem::Login(existing)) = self
                                    .payload
                                    .items
                                    .iter_mut()
                                    .find(|item| item.id() == existing_id)
                                {
                                    existing.title = title.clone();
                                    existing.urls = urls;
                                    existing.username = username;
                                    existing.password = password_field;
                                    existing.totp = totp;
                                    existing.notes = notes;
                                    existing.tags = Vec::new();
                                    existing.favorite = false;
                                    existing.updated_at = now;
                                    overwritten = overwritten.saturating_add(1);
                                    continue;
                                }
                            }
                            DuplicateAction::KeepBoth => {}
                        }
                    }

                    let item = VaultItem::Login(LoginItem {
                        id: Uuid::new_v4().to_string(),
                        title,
                        urls,
                        username,
                        password: password_field,
                        totp,
                        notes,
                        tags: Vec::new(),
                        favorite: false,
                        created_at: now,
                        updated_at: now,
                    });
                    let item_id = item.id().to_owned();
                    self.payload
                        .add_item(item, now)
                        .map_err(|error| error_to_napi(error.to_string()))?;
                    login_index.insert(key, item_id);
                    imported = imported.saturating_add(1);
                }
                2 => {
                    let item = VaultItem::Note(NoteItem {
                        id: Uuid::new_v4().to_string(),
                        title,
                        body: item.notes.unwrap_or_default(),
                        tags: Vec::new(),
                        favorite: false,
                        created_at: now,
                        updated_at: now,
                    });
                    self.payload
                        .add_item(item, now)
                        .map_err(|error| error_to_napi(error.to_string()))?;
                    imported = imported.saturating_add(1);
                }
                other => {
                    skipped = skipped.saturating_add(1);
                    warnings.push(format!(
                        "item {item_number} skipped: unsupported Bitwarden item type `{other}`"
                    ));
                }
            }
        }

        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;

        Ok(ImportResult {
            imported,
            skipped,
            overwritten,
            warnings,
        })
    }

    #[napi]
    pub fn export_csv(&self, output_path: String, include_secrets: bool) -> Result<u32> {
        ensure_output_parent(output_path.as_str())?;
        let mut writer = csv::Writer::from_path(&output_path)
            .map_err(|error| error_to_napi(error.to_string()))?;
        writer
            .write_record([
                "type",
                "title",
                "username",
                "password",
                "url",
                "notes",
                "tags",
                "totp_uri",
                "created_at",
                "updated_at",
            ])
            .map_err(|error| error_to_napi(error.to_string()))?;

        for item in &self.payload.items {
            writer
                .write_record(export_item_csv_row(item, include_secrets))
                .map_err(|error| error_to_napi(error.to_string()))?;
        }
        writer
            .flush()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(u32::try_from(self.payload.items.len()).unwrap_or(u32::MAX))
    }

    #[napi]
    pub fn export_json(&self, output_path: String, include_secrets: bool) -> Result<u32> {
        ensure_output_parent(output_path.as_str())?;
        let export = json!({
            "exported_at": unix_seconds_now(),
            "redacted": !include_secrets,
            "item_count": self.payload.items.len(),
            "items": self.payload.items.iter().map(|item| export_item_json(item, include_secrets)).collect::<Vec<_>>()
        });
        let encoded =
            serde_json::to_vec_pretty(&export).map_err(|error| error_to_napi(error.to_string()))?;
        std::fs::write(&output_path, encoded).map_err(|error| error_to_napi(error.to_string()))?;
        Ok(u32::try_from(self.payload.items.len()).unwrap_or(u32::MAX))
    }

    #[napi]
    pub fn export_encrypted(
        &self,
        output_path: String,
        export_password: String,
        redacted: bool,
    ) -> Result<u32> {
        if output_path == self.path {
            return Err(error_to_napi(
                "encrypted export output must differ from vault path".to_owned(),
            ));
        }
        let password = export_password.trim();
        if password.is_empty() {
            return Err(error_to_napi("export password cannot be empty".to_owned()));
        }
        ensure_output_parent(output_path.as_str())?;

        let mut export_payload = if redacted {
            redact_payload(self.payload.clone())
        } else {
            self.payload.clone()
        };
        export_payload.app.name = "npw-export".to_owned();
        export_payload.settings.insert(
            "export_meta.exported_at".to_owned(),
            unix_seconds_now().to_string(),
        );
        export_payload
            .settings
            .insert("export_meta.redacted".to_owned(), redacted.to_string());
        let payload_bytes = export_payload
            .to_cbor()
            .map_err(|error| error_to_napi(error.to_string()))?;

        let encrypted_export = create_vault_file(&CreateVaultInput {
            master_password: password,
            payload_plaintext: &payload_bytes,
            item_count: export_payload.item_count(),
            vault_label: Some("npw-export"),
            kdf_params: self.unlocked.header.kdf_params,
        })
        .map_err(|error| error_to_napi(error.to_string()))?;
        write_vault(std::path::Path::new(&output_path), &encrypted_export, 10)
            .map_err(|error| error_to_napi(error.to_string()))?;

        Ok(u32::try_from(export_payload.items.len()).unwrap_or(u32::MAX))
    }

    #[napi]
    pub fn login_generate_and_replace_password(&mut self, id: String) -> Result<String> {
        let now = unix_seconds_now();
        let index = self
            .payload
            .items
            .iter()
            .position(|item| item.id() == id)
            .ok_or_else(|| error_to_napi("item not found".to_owned()))?;

        let VaultItem::Login(login) = &mut self.payload.items[index] else {
            return Err(error_to_napi("item is not a login".to_owned()));
        };

        let (app_config, _config_path) =
            crate::config::load_config(None).map_err(|error| error_to_napi(error.to_string()))?;
        let (password, mode_label) = generate_password_from_config(&app_config.generator)
            .map_err(|error| error_to_napi(error.to_string()))?;

        login.password = Some(password);
        login.updated_at = now;
        login
            .validate()
            .map_err(|error| error_to_napi(error.to_string()))?;
        self.payload.updated_at = now;
        self.payload.rebuild_search_index();
        self.persist()
            .map_err(|error| error_to_napi(error.to_string()))?;
        Ok(mode_label.to_owned())
    }

    #[napi]
    pub fn delete_item(&mut self, id: String) -> Result<bool> {
        let now = unix_seconds_now();
        let deleted = self.payload.soft_delete_item(&id, now);
        if deleted {
            self.persist()
                .map_err(|error| error_to_napi(error.to_string()))?;
        }
        Ok(deleted)
    }

    #[napi]
    pub fn lock(&mut self) {
        self.payload = VaultPayload::new("npw", env!("CARGO_PKG_VERSION"), unix_seconds_now());
        self.unlocked.wipe_secrets();
        self.lock = None;
    }
}

impl VaultSession {
    fn persist(&mut self) -> std::result::Result<(), String> {
        let lock = self
            .lock
            .as_ref()
            .ok_or_else(|| "vault session is locked".to_owned())?;
        let payload_plaintext = self.payload.to_cbor().map_err(|error| error.to_string())?;
        let rewritten = reencrypt_vault_file_with_kek(
            self.unlocked.kek(),
            &payload_plaintext,
            self.payload.item_count(),
            &self.unlocked.header,
            &self.unlocked.envelope,
        )
        .map_err(|error| error.to_string())?;

        write_vault_with_lock(lock, &rewritten, 10).map_err(|error| error.to_string())?;
        self.unlocked.header.item_count = self.payload.item_count();
        Ok(())
    }
}

fn validate_vault_id_hex(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(error_to_napi("vault_id_hex cannot be empty".to_owned()));
    }
    if trimmed.len() != 32 {
        return Err(error_to_napi(
            "vault_id_hex must be 32 hex characters".to_owned(),
        ));
    }
    if !trimmed.chars().all(|value| value.is_ascii_hexdigit()) {
        return Err(error_to_napi("vault_id_hex must be hex".to_owned()));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn decode_vault_id_hex(raw: &str) -> Result<[u8; 16]> {
    let normalized = validate_vault_id_hex(raw)?;
    let bytes = normalized.as_bytes();
    let mut output = [0_u8; 16];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        let high = vault_id_hex_nibble(chunk[0])?;
        let low = vault_id_hex_nibble(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn vault_id_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(error_to_napi("vault_id_hex must be hex".to_owned())),
    }
}

fn quick_unlock_service_name(vault_id_hex: &str) -> String {
    let prefix = vault_id_hex.get(0..8).unwrap_or(vault_id_hex);
    format!("npw Quick Unlock ({prefix})")
}

fn quick_unlock_entry(vault_id_hex: &str) -> std::result::Result<Entry, keyring::Error> {
    let service = quick_unlock_service_name(vault_id_hex);
    Entry::new(service.as_str(), vault_id_hex)
}

fn is_keyring_no_entry(error: &keyring::Error) -> bool {
    matches!(error, keyring::Error::NoEntry)
}

fn quick_unlock_has_entry_internal(vault_id_hex: String) -> Result<bool> {
    let vault_id_hex = validate_vault_id_hex(vault_id_hex.as_str())?;
    let entry = quick_unlock_entry(vault_id_hex.as_str())
        .map_err(|error| error_to_napi(error.to_string()))?;
    match entry.get_secret() {
        Ok(mut value) => {
            let ok = value.len() == 32;
            value.zeroize();
            if ok {
                Ok(true)
            } else {
                Err(error_to_napi(
                    "quick unlock key is invalid length".to_owned(),
                ))
            }
        }
        Err(error) if is_keyring_no_entry(&error) => Ok(false),
        Err(error) => Err(error_to_napi(error.to_string())),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn hex_decode(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(error_to_napi(
            "credential_id_hex cannot be empty".to_owned(),
        ));
    }
    if !trimmed.len().is_multiple_of(2) {
        return Err(error_to_napi(
            "credential_id_hex must have an even number of characters".to_owned(),
        ));
    }

    let mut output = Vec::with_capacity(trimmed.len() / 2);
    let mut chars = trimmed.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let value = (hex_nibble(high)? << 4) | hex_nibble(low)?;
        output.push(value);
    }
    Ok(output)
}

fn hex_nibble(value: char) -> Result<u8> {
    match value {
        '0'..='9' => Ok(value as u8 - b'0'),
        'a'..='f' => Ok(value as u8 - b'a' + 10),
        'A'..='F' => Ok(value as u8 - b'A' + 10),
        _ => Err(error_to_napi("credential_id_hex must be hex".to_owned())),
    }
}

fn normalize_tags(raw: Option<Vec<String>>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut tags = Vec::new();
    for raw_tag in raw.unwrap_or_default() {
        let normalized = collapse_tag_whitespace(raw_tag.as_str());
        if normalized.is_empty() {
            continue;
        }
        if seen.insert(normalized.to_lowercase()) {
            tags.push(normalized);
        }
    }
    tags
}

fn collapse_tag_whitespace(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_urls(raw: Option<Vec<UrlEntryInput>>) -> Result<Vec<UrlEntry>> {
    let mut urls = Vec::new();
    for entry in raw.unwrap_or_default() {
        let trimmed = entry.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let match_type = match entry.match_type.as_deref() {
            None => UrlMatchType::Exact,
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "exact" => UrlMatchType::Exact,
                "domain" => UrlMatchType::Domain,
                "subdomain" => UrlMatchType::Subdomain,
                _ => {
                    return Err(error_to_napi(
                        "url match_type must be exact|domain|subdomain".to_owned(),
                    ));
                }
            },
        };

        urls.push(UrlEntry {
            url: trimmed.to_owned(),
            match_type,
        });
    }
    Ok(urls)
}

fn url_match_type_name(value: UrlMatchType) -> &'static str {
    match value {
        UrlMatchType::Exact => "exact",
        UrlMatchType::Domain => "domain",
        UrlMatchType::Subdomain => "subdomain",
    }
}

#[derive(Clone, Copy)]
enum DuplicateAction {
    Skip,
    Overwrite,
    KeepBoth,
}

fn parse_duplicate_decisions(
    decisions: Vec<ImportDuplicateDecision>,
) -> Result<std::collections::HashMap<u32, DuplicateAction>> {
    let mut map = std::collections::HashMap::new();
    for decision in decisions {
        let action = match decision.action.trim().to_ascii_lowercase().as_str() {
            "skip" => DuplicateAction::Skip,
            "overwrite" => DuplicateAction::Overwrite,
            "keep_both" | "keep-both" | "keepboth" => DuplicateAction::KeepBoth,
            other => {
                return Err(error_to_napi(format!(
                    "invalid duplicate action `{other}` (expected skip|overwrite|keep_both)"
                )));
            }
        };
        map.insert(decision.source_index, action);
    }
    Ok(map)
}

fn ensure_output_parent(path: &str) -> Result<()> {
    let output_path = std::path::Path::new(path);
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error_to_napi(error.to_string()))?;
    }
    Ok(())
}

fn csv_cell<'a>(
    headers: &csv::StringRecord,
    row: &'a csv::StringRecord,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .position(|header| header == name)
        .and_then(|index| row.get(index))
}

fn normalize_optional_cell(value: Option<&str>) -> Option<String> {
    let trimmed = value.unwrap_or_default().trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn parse_csv_tags(raw: &str) -> Vec<String> {
    raw.split(';')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn build_login_duplicate_index(
    payload: &VaultPayload,
) -> std::collections::HashMap<String, String> {
    let mut index = std::collections::HashMap::new();
    for item in &payload.items {
        if let VaultItem::Login(login) = item {
            let key = login_duplicate_key(
                &login.title,
                login.username.as_deref(),
                login.urls.first().map(|entry| entry.url.as_str()),
            );
            index.insert(key, login.id.clone());
        }
    }
    index
}

fn login_duplicate_key(title: &str, username: Option<&str>, primary_url: Option<&str>) -> String {
    format!(
        "{}|{}|{}",
        title.trim().to_ascii_lowercase(),
        username.unwrap_or_default().trim().to_ascii_lowercase(),
        primary_url.unwrap_or_default().trim().to_ascii_lowercase()
    )
}

fn export_item_csv_row(item: &VaultItem, include_secrets: bool) -> [String; 10] {
    match item {
        VaultItem::Login(login) => [
            "login".to_owned(),
            login.title.clone(),
            login.username.clone().unwrap_or_default(),
            if include_secrets {
                login.password.clone().unwrap_or_default()
            } else {
                String::new()
            },
            login
                .urls
                .first()
                .map(|entry| entry.url.clone())
                .unwrap_or_default(),
            if include_secrets {
                login.notes.clone().unwrap_or_default()
            } else {
                String::new()
            },
            login.tags.join(";"),
            if include_secrets {
                login
                    .totp
                    .as_ref()
                    .map(|totp| {
                        login_totp_uri(login.title.as_str(), login.username.as_deref(), totp)
                    })
                    .unwrap_or_default()
            } else {
                String::new()
            },
            login.created_at.to_string(),
            login.updated_at.to_string(),
        ],
        VaultItem::Note(note) => [
            "note".to_owned(),
            note.title.clone(),
            String::new(),
            String::new(),
            String::new(),
            if include_secrets {
                note.body.clone()
            } else {
                String::new()
            },
            note.tags.join(";"),
            String::new(),
            note.created_at.to_string(),
            note.updated_at.to_string(),
        ],
        VaultItem::PasskeyRef(passkey) => [
            "passkey_ref".to_owned(),
            passkey.title.clone(),
            passkey.user_display_name.clone().unwrap_or_default(),
            String::new(),
            passkey.rp_id.clone(),
            if include_secrets {
                passkey.notes.clone().unwrap_or_default()
            } else {
                String::new()
            },
            passkey.tags.join(";"),
            String::new(),
            passkey.created_at.to_string(),
            passkey.updated_at.to_string(),
        ],
    }
}

fn export_item_json(item: &VaultItem, include_secrets: bool) -> serde_json::Value {
    match item {
        VaultItem::Login(login) => {
            let mut value = json!({
                "type": "login",
                "id": login.id,
                "title": login.title,
                "username": login.username,
                "urls": login.urls,
                "tags": login.tags,
                "favorite": login.favorite,
                "created_at": login.created_at,
                "updated_at": login.updated_at
            });
            if include_secrets {
                value["password"] = json!(login.password);
                value["notes"] = json!(login.notes);
                value["totp_uri"] = json!(login.totp.as_ref().map(|totp| {
                    login_totp_uri(login.title.as_str(), login.username.as_deref(), totp)
                }));
            }
            value
        }
        VaultItem::Note(note) => {
            let mut value = json!({
                "type": "note",
                "id": note.id,
                "title": note.title,
                "tags": note.tags,
                "favorite": note.favorite,
                "created_at": note.created_at,
                "updated_at": note.updated_at
            });
            if include_secrets {
                value["body"] = json!(note.body);
            }
            value
        }
        VaultItem::PasskeyRef(passkey) => {
            let mut value = json!({
                "type": "passkey_ref",
                "id": passkey.id,
                "title": passkey.title,
                "rp_id": passkey.rp_id,
                "rp_name": passkey.rp_name,
                "user_display_name": passkey.user_display_name,
                "tags": passkey.tags,
                "favorite": passkey.favorite,
                "created_at": passkey.created_at,
                "updated_at": passkey.updated_at
            });
            if include_secrets {
                value["notes"] = json!(passkey.notes);
                value["credential_id"] = json!(passkey.credential_id);
            }
            value
        }
    }
}

fn redact_payload(mut payload: VaultPayload) -> VaultPayload {
    for item in &mut payload.items {
        match item {
            VaultItem::Login(login) => {
                login.password = None;
                login.notes = None;
                login.totp = None;
            }
            VaultItem::Note(note) => {
                note.body.clear();
            }
            VaultItem::PasskeyRef(passkey) => {
                passkey.notes = None;
            }
        }
    }
    payload.rebuild_search_index();
    payload
}

#[derive(Debug, Deserialize)]
struct BitwardenExport {
    #[serde(default)]
    items: Vec<BitwardenItem>,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    #[serde(default)]
    r#type: u8,
    #[serde(default)]
    name: String,
    notes: Option<String>,
    login: Option<BitwardenLogin>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BitwardenLoginUri>>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLoginUri {
    uri: Option<String>,
}

fn login_totp_uri(title: &str, username: Option<&str>, config: &npw_core::TotpConfig) -> String {
    let secret = BASE32_NOPAD.encode(&config.seed);
    let issuer = config.issuer.clone().unwrap_or_else(|| "npw".to_owned());
    let label = username
        .map(|name| format!("{issuer}:{name}"))
        .unwrap_or_else(|| format!("{issuer}:{title}"));
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm={}&digits={}&period={}",
        totp_algorithm_name(config.algorithm),
        config.digits,
        config.period
    )
}

fn totp_algorithm_name(algorithm: npw_core::TotpAlgorithm) -> &'static str {
    match algorithm {
        npw_core::TotpAlgorithm::SHA1 => "SHA1",
        npw_core::TotpAlgorithm::SHA256 => "SHA256",
        npw_core::TotpAlgorithm::SHA512 => "SHA512",
    }
}

fn generate_password_from_config(
    generator: &crate::config::GeneratorConfig,
) -> std::result::Result<(String, &'static str), String> {
    match generator.default_mode {
        crate::config::GenerateMode::Charset => {
            generate_charset_password(generator).map(|password| (password, "charset"))
        }
        crate::config::GenerateMode::Diceware => {
            generate_diceware_password(generator).map(|password| (password, "diceware"))
        }
    }
}

fn generate_charset_password(
    generator: &crate::config::GeneratorConfig,
) -> std::result::Result<String, String> {
    let length = generator.charset_length;
    if !(8..=128).contains(&length) {
        return Err(format!(
            "generator.charset_length out of bounds: {length} (expected 8..=128)"
        ));
    }

    let mut alphabet = String::new();
    if generator.charset_lowercase {
        alphabet.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if generator.charset_uppercase {
        alphabet.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if generator.charset_digits {
        alphabet.push_str("0123456789");
    }
    if generator.charset_symbols {
        alphabet.push_str("!@#$%^&*()-_=+[]{};:,.<>?/|");
    }

    if generator.charset_avoid_ambiguous {
        alphabet = alphabet
            .chars()
            .filter(|character| !matches!(*character, '0' | 'O' | 'o' | '1' | 'l' | 'I'))
            .collect();
    }

    if alphabet.is_empty() {
        return Err("charset generation needs at least one enabled character set".to_owned());
    }

    let chars: Vec<char> = alphabet.chars().collect();
    let mut output = String::with_capacity(length);
    for _ in 0..length {
        let index = sample_index(chars.len())?;
        output.push(chars[index]);
    }
    Ok(output)
}

fn generate_diceware_password(
    generator: &crate::config::GeneratorConfig,
) -> std::result::Result<String, String> {
    let words_to_generate = generator.diceware_words;
    if !(4..=10).contains(&words_to_generate) {
        return Err(format!(
            "generator.diceware_words out of bounds: {words_to_generate} (expected 4..=10)"
        ));
    }

    let separator = generator
        .diceware_separator
        .chars()
        .next()
        .ok_or_else(|| "generator.diceware_separator is required".to_owned())?;
    let wordlist = diceware_words();
    let mut words = Vec::with_capacity(words_to_generate);
    for _ in 0..words_to_generate {
        words.push(wordlist[sample_index(wordlist.len())?]);
    }
    Ok(words.join(&separator.to_string()))
}

fn sample_index(limit: usize) -> std::result::Result<usize, String> {
    if limit == 0 {
        return Err("cannot sample from an empty collection".to_owned());
    }

    let max = u64::MAX - (u64::MAX % u64::try_from(limit).expect("limit should fit in u64"));
    loop {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| "failed to generate random values".to_owned())?;
        let candidate = u64::from_le_bytes(bytes);
        if candidate < max {
            return Ok(
                (candidate % u64::try_from(limit).expect("limit should fit in u64")) as usize,
            );
        }
    }
}

fn diceware_words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../npw-cli/assets/eff_large_wordlist.txt"
            ))
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, word)| word.trim()))
            .filter(|word| !word.is_empty())
            .collect()
        })
        .as_slice()
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

#[napi]
pub fn quick_unlock_has_entry(vault_id_hex: String) -> Result<bool> {
    quick_unlock_has_entry_internal(vault_id_hex)
}

#[napi]
pub fn vault_unlock_quick(path: String, vault_id_hex: String) -> Result<VaultSession> {
    let path_ref = std::path::Path::new(&path);
    let lock = acquire_vault_lock(path_ref).map_err(|error| error_to_napi(error.to_string()))?;
    let bytes = read_vault(path_ref).map_err(|error| error_to_napi(error.to_string()))?;

    let vault_id_hex = validate_vault_id_hex(vault_id_hex.as_str())?;
    let expected_vault_id = decode_vault_id_hex(vault_id_hex.as_str())?;
    let entry = quick_unlock_entry(vault_id_hex.as_str())
        .map_err(|error| error_to_napi(error.to_string()))?;
    let mut secret = match entry.get_secret() {
        Ok(value) => value,
        Err(error) if is_keyring_no_entry(&error) => {
            return Err(error_to_napi(
                "quick unlock is not enabled for this vault".to_owned(),
            ));
        }
        Err(error) => return Err(error_to_napi(error.to_string())),
    };

    if secret.len() != 32 {
        secret.zeroize();
        return Err(error_to_napi(
            "quick unlock key is invalid length".to_owned(),
        ));
    }

    let mut kek = [0_u8; 32];
    kek.copy_from_slice(&secret);
    secret.zeroize();
    let mut unlocked = unlock_vault_file_with_existing_kek(&bytes, &kek)
        .map_err(|error| error_to_napi(error.to_string()))?;
    kek.zeroize();

    if unlocked.envelope.vault_id != expected_vault_id {
        return Err(error_to_napi(
            "quick unlock key does not match this vault".to_owned(),
        ));
    }

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
