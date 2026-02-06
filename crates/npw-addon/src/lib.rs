use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use napi::{Error, Result, Status};
use napi_derive::napi;
use npw_core::{
    CreateVaultInput, KdfParams, LoginItem, NoteItem, TotpAlgorithm, TotpConfig, UrlEntry,
    UrlMatchType, VaultItem, VaultPayload, assess_master_password, create_vault_file,
    decode_base32_secret, generate_totp, parse_otpauth_uri, parse_vault_header,
    reencrypt_vault_file_with_kek, unlock_vault_file, unlock_vault_file_with_kek,
};
use npw_storage::{
    VaultLock, acquire_vault_lock, list_backups, read_vault, recover_from_backup, write_vault,
    write_vault_with_lock,
};
use qrcode::QrCode;
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
        label: unlocked.header.vault_label,
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
        self.unlocked.payload_plaintext.zeroize();
        self.unlocked.payload_plaintext.clear();
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
