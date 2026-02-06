use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{fs, ops::RangeInclusive};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GenerateMode {
    #[default]
    Charset,
    Diceware,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub default_vault: Option<String>,
    pub security: SecurityConfig,
    pub generator: GeneratorConfig,
    pub logging: LoggingConfig,
    pub backup: BackupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub clipboard_timeout_seconds: u32,
    pub auto_lock_minutes: u32,
    pub lock_on_suspend: bool,
    pub reveal_requires_confirm: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            clipboard_timeout_seconds: 30,
            auto_lock_minutes: 5,
            lock_on_suspend: true,
            reveal_requires_confirm: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorConfig {
    pub default_mode: GenerateMode,
    pub charset_length: usize,
    pub charset_uppercase: bool,
    pub charset_lowercase: bool,
    pub charset_digits: bool,
    pub charset_symbols: bool,
    pub charset_avoid_ambiguous: bool,
    pub diceware_words: usize,
    pub diceware_separator: String,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            default_mode: GenerateMode::Charset,
            charset_length: 20,
            charset_uppercase: true,
            charset_lowercase: true,
            charset_digits: true,
            charset_symbols: true,
            charset_avoid_ambiguous: false,
            diceware_words: 5,
            diceware_separator: "-".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub max_retained: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self { max_retained: 10 }
    }
}

pub fn load_config(config_override: Option<PathBuf>) -> Result<(AppConfig, PathBuf), String> {
    let config_path = match config_override {
        Some(path) => path,
        None => {
            let project_dirs = ProjectDirs::from("", "", "npw")
                .ok_or_else(|| "unable to resolve config path".to_owned())?;
            project_dirs.config_dir().join("config.toml")
        }
    };

    if !config_path.exists() {
        return Ok((AppConfig::default(), config_path));
    }

    let raw = fs::read_to_string(&config_path)
        .map_err(|error| format!("failed to read config {}: {error}", config_path.display()))?;
    let config = toml::from_str::<AppConfig>(&raw)
        .map_err(|error| format!("failed to parse config {}: {error}", config_path.display()))?;
    Ok((config, config_path))
}

pub fn save_config(config: &AppConfig, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!("failed to create config dir {}: {error}", parent.display())
        })?;
    }
    let data = toml::to_string_pretty(config)
        .map_err(|error| format!("failed to serialize config: {error}"))?;
    fs::write(path, data)
        .map_err(|error| format!("failed to write config {}: {error}", path.display()))
}

pub fn config_set(config: &mut AppConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "default_vault" => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err("default_vault cannot be empty".to_owned());
            }
            config.default_vault = Some(trimmed.to_owned());
        }
        "security.clipboard_timeout_seconds" => {
            let parsed = parse_u32(key, value)?;
            validate_u32_allow_zero(key, parsed, 10..=90)?;
            config.security.clipboard_timeout_seconds = parsed;
        }
        "security.auto_lock_minutes" => {
            let parsed = parse_u32(key, value)?;
            validate_u32_range(key, parsed, 1..=60)?;
            config.security.auto_lock_minutes = parsed;
        }
        "security.lock_on_suspend" => {
            config.security.lock_on_suspend = parse_bool(key, value)?;
        }
        "security.reveal_requires_confirm" => {
            config.security.reveal_requires_confirm = parse_bool(key, value)?;
        }
        "generator.default_mode" => {
            config.generator.default_mode = match value.trim() {
                "charset" => GenerateMode::Charset,
                "diceware" => GenerateMode::Diceware,
                _ => return Err("generator.default_mode must be charset or diceware".to_owned()),
            };
        }
        "generator.charset_length" => {
            let parsed = parse_usize(key, value)?;
            validate_usize_range(key, parsed, 8..=128)?;
            config.generator.charset_length = parsed;
        }
        "generator.charset_uppercase" => {
            config.generator.charset_uppercase = parse_bool(key, value)?;
        }
        "generator.charset_lowercase" => {
            config.generator.charset_lowercase = parse_bool(key, value)?;
        }
        "generator.charset_digits" => {
            config.generator.charset_digits = parse_bool(key, value)?;
        }
        "generator.charset_symbols" => {
            config.generator.charset_symbols = parse_bool(key, value)?;
        }
        "generator.charset_avoid_ambiguous" => {
            config.generator.charset_avoid_ambiguous = parse_bool(key, value)?;
        }
        "generator.diceware_words" => {
            let parsed = parse_usize(key, value)?;
            validate_usize_range(key, parsed, 4..=10)?;
            config.generator.diceware_words = parsed;
        }
        "generator.diceware_separator" => {
            if value.chars().count() != 1 {
                return Err("generator.diceware_separator must be one character".to_owned());
            }
            config.generator.diceware_separator = value.to_owned();
        }
        "logging.level" => match value.trim() {
            "error" | "warn" | "info" | "debug" => config.logging.level = value.trim().to_owned(),
            _ => return Err("logging.level must be error|warn|info|debug".to_owned()),
        },
        "backup.max_retained" => {
            let parsed = parse_usize(key, value)?;
            if parsed == 0 {
                return Err("backup.max_retained must be > 0".to_owned());
            }
            config.backup.max_retained = parsed;
        }
        _ => return Err("unknown config key".to_owned()),
    }

    Ok(())
}

fn parse_u32(key: &str, value: &str) -> Result<u32, String> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("invalid u32 value for {key}"))
}

fn parse_usize(key: &str, value: &str) -> Result<usize, String> {
    value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("invalid usize value for {key}"))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    value
        .trim()
        .parse::<bool>()
        .map_err(|_| format!("invalid bool value for {key}"))
}

fn validate_u32_range(key: &str, value: u32, allowed: RangeInclusive<u32>) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "{key} out of bounds: {value} (expected {}..={})",
            allowed.start(),
            allowed.end()
        ))
    }
}

fn validate_u32_allow_zero(
    key: &str,
    value: u32,
    allowed: RangeInclusive<u32>,
) -> Result<(), String> {
    if value == 0 {
        return Ok(());
    }
    validate_u32_range(key, value, allowed)
}

fn validate_usize_range(
    key: &str,
    value: usize,
    allowed: RangeInclusive<usize>,
) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "{key} out of bounds: {value} (expected {}..={})",
            allowed.start(),
            allowed.end()
        ))
    }
}
