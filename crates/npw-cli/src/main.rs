use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use data_encoding::BASE32_NOPAD;
use directories::ProjectDirs;
use npw_core::{
    CreateVaultInput, ItemTypeFilter, KdfParams, LoginItem, ModelError, NoteItem, PasskeyRefItem,
    ReencryptVaultInput, TotpAlgorithm, TotpConfig, TotpError, UrlEntry, UrlMatchType, VaultError,
    VaultItem, VaultPayload, create_vault_file, decode_base32_secret, generate_totp,
    parse_otpauth_uri, parse_vault_header, reencrypt_vault_file, unlock_vault_file,
};
use npw_storage::{
    BackupEntry, StorageError, list_backups, read_vault, recover_from_backup, write_vault,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

const JSON_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[allow(dead_code)]
enum CliExitCode {
    Success = 0,
    General = 1,
    Usage = 2,
    VaultLockedOrNoSession = 3,
    AuthFailed = 4,
    VaultFileLocked = 5,
    CorruptOrParse = 6,
    NetworkDisabled = 7,
    PermissionDenied = 8,
}

#[derive(Debug)]
struct CliError {
    code: CliExitCode,
    kind: &'static str,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: CliExitCode::Usage,
            kind: "invalid_usage",
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct CommandOutput {
    message: String,
    payload: Value,
}

#[derive(Debug, Parser)]
#[command(name = "npw")]
#[command(about = "Local-first password manager", version)]
struct Cli {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long = "no-color", global = true)]
    no_color: bool,
    #[arg(long, global = true)]
    quiet: bool,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    non_interactive: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Item {
        #[command(subcommand)]
        command: ItemCommand,
    },
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    Totp(TotpArgs),
    Recover(RecoverArgs),
    Search(SearchArgs),
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Generate(GenerateArgs),
}

#[derive(Debug, Subcommand)]
enum VaultCommand {
    Init(VaultInitArgs),
    Check(VaultPathArgs),
    Unlock(VaultPathArgs),
    Status(VaultPathArgs),
    Backup(VaultBackupArgs),
    ChangePassword(VaultChangePasswordArgs),
}

#[derive(Debug, Subcommand)]
enum ItemCommand {
    AddLogin(ItemAddLoginArgs),
    AddNote(ItemAddNoteArgs),
    AddPasskey(ItemAddPasskeyArgs),
    Get(ItemIdArgs),
    List(ItemListArgs),
    Delete(ItemIdArgs),
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Get { key: String },
    Set { key: String, value: String },
    List,
}

#[derive(Debug, Subcommand)]
enum ImportCommand {
    Csv(ImportCsvArgs),
}

#[derive(Debug, Subcommand)]
enum ExportCommand {
    Csv(ExportArgs),
    Json(ExportArgs),
    Encrypted(ExportEncryptedArgs),
}

#[derive(Debug, Args)]
struct VaultPathArgs {
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DuplicatePolicyArg {
    Skip,
    Overwrite,
    KeepBoth,
}

#[derive(Debug, Args)]
struct SearchArgs {
    path: Option<PathBuf>,
    query: String,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    path: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    auto: bool,
}

#[derive(Debug, Args)]
struct ImportCsvArgs {
    input: PathBuf,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = DuplicatePolicyArg::Skip)]
    duplicate: DuplicatePolicyArg,
}

#[derive(Debug, Args)]
struct ExportArgs {
    output: PathBuf,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    include_secrets: bool,
    #[arg(long, default_value_t = false)]
    yes: bool,
}

#[derive(Debug, Args)]
struct ExportEncryptedArgs {
    output: PathBuf,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    redacted: bool,
}

#[derive(Debug, Args)]
struct VaultInitArgs {
    path: Option<PathBuf>,
    #[arg(long)]
    label: Option<String>,
    #[arg(long, default_value_t = 512 * 1024)]
    argon_m_kib: u32,
    #[arg(long, default_value_t = 4)]
    argon_t: u32,
    #[arg(long, default_value_t = 4)]
    argon_p: u32,
}

#[derive(Debug, Args)]
struct VaultBackupArgs {
    path: Option<PathBuf>,
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct VaultChangePasswordArgs {
    path: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    rotate_vault_key: bool,
}

#[derive(Debug, Args)]
struct ItemIdArgs {
    path: Option<PathBuf>,
    id: String,
}

#[derive(Debug, Args)]
struct TotpArgs {
    id: String,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long)]
    at: Option<u64>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ItemTypeArg {
    Login,
    Note,
    PasskeyRef,
}

impl ItemTypeArg {
    fn to_filter(self) -> ItemTypeFilter {
        match self {
            Self::Login => ItemTypeFilter::Login,
            Self::Note => ItemTypeFilter::Note,
            Self::PasskeyRef => ItemTypeFilter::PasskeyRef,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TotpAlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithmArg {
    fn into_core(self) -> TotpAlgorithm {
        match self {
            Self::Sha1 => TotpAlgorithm::SHA1,
            Self::Sha256 => TotpAlgorithm::SHA256,
            Self::Sha512 => TotpAlgorithm::SHA512,
        }
    }
}

#[derive(Debug, Args)]
struct ItemListArgs {
    path: Option<PathBuf>,
    #[arg(long, value_enum)]
    item_type: Option<ItemTypeArg>,
}

#[derive(Debug, Args)]
struct ItemAddLoginArgs {
    path: Option<PathBuf>,
    #[arg(long)]
    title: String,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long = "url")]
    urls: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long)]
    totp_secret_base32: Option<String>,
    #[arg(long)]
    totp_uri: Option<String>,
    #[arg(long)]
    totp_issuer: Option<String>,
    #[arg(long, value_enum)]
    totp_algorithm: Option<TotpAlgorithmArg>,
    #[arg(long)]
    totp_digits: Option<u8>,
    #[arg(long)]
    totp_period: Option<u16>,
    #[arg(long, default_value_t = false)]
    favorite: bool,
}

#[derive(Debug, Args)]
struct ItemAddNoteArgs {
    path: Option<PathBuf>,
    #[arg(long)]
    title: String,
    #[arg(long)]
    body: String,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long, default_value_t = false)]
    favorite: bool,
}

#[derive(Debug, Args)]
struct ItemAddPasskeyArgs {
    path: Option<PathBuf>,
    #[arg(long)]
    title: String,
    #[arg(long)]
    rp_id: String,
    #[arg(long)]
    rp_name: Option<String>,
    #[arg(long)]
    user_display_name: Option<String>,
    #[arg(long)]
    credential_id: String,
    #[arg(long)]
    notes: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long, default_value_t = false)]
    favorite: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum GenerateMode {
    Charset,
    Diceware,
}

#[derive(Debug, Args)]
struct GenerateArgs {
    #[arg(long, value_enum, default_value_t = GenerateMode::Charset)]
    mode: GenerateMode,
    #[arg(long, default_value_t = 20)]
    length: usize,
    #[arg(long, default_value_t = true)]
    lowercase: bool,
    #[arg(long, default_value_t = true)]
    uppercase: bool,
    #[arg(long, default_value_t = true)]
    digits: bool,
    #[arg(long, default_value_t = true)]
    symbols: bool,
    #[arg(long, default_value_t = false)]
    avoid_ambiguous: bool,
    #[arg(long, default_value_t = 5)]
    words: usize,
    #[arg(long, default_value = "-")]
    separator: String,
    #[arg(long, default_value_t = false)]
    inject_digit_symbol: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AppConfig {
    default_vault: Option<String>,
    security: SecurityConfig,
    generator: GeneratorConfig,
    logging: LoggingConfig,
    backup: BackupConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityConfig {
    clipboard_timeout_seconds: u32,
    auto_lock_minutes: u32,
    lock_on_suspend: bool,
    reveal_requires_confirm: bool,
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
struct GeneratorConfig {
    default_mode: GenerateMode,
    charset_length: usize,
    charset_uppercase: bool,
    charset_lowercase: bool,
    charset_digits: bool,
    charset_symbols: bool,
    charset_avoid_ambiguous: bool,
    diceware_words: usize,
    diceware_separator: String,
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
struct LoggingConfig {
    level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupConfig {
    max_retained: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self { max_retained: 10 }
    }
}

#[derive(Debug, Serialize)]
struct JsonEnvelope {
    schema_version: u8,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonError>,
}

#[derive(Debug, Serialize)]
struct JsonError {
    code: u8,
    kind: String,
    message: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let _ = (cli.no_color, cli.quiet);
    match execute(&cli) {
        Ok(output) => {
            if cli.json {
                let envelope = JsonEnvelope {
                    schema_version: JSON_SCHEMA_VERSION,
                    ok: true,
                    result: Some(output.payload),
                    error: None,
                };
                println!(
                    "{}",
                    serde_json::to_string(&envelope)
                        .expect("json envelope serialization should succeed")
                );
            } else {
                println!("{}", output.message);
            }
            ExitCode::from(CliExitCode::Success as u8)
        }
        Err(error) => {
            if cli.json {
                let envelope = JsonEnvelope {
                    schema_version: JSON_SCHEMA_VERSION,
                    ok: false,
                    result: None,
                    error: Some(JsonError {
                        code: error.code as u8,
                        kind: error.kind.to_owned(),
                        message: error.message.clone(),
                    }),
                };
                println!(
                    "{}",
                    serde_json::to_string(&envelope)
                        .expect("json envelope serialization should succeed")
                );
            } else {
                eprintln!("{}", error.message);
            }
            ExitCode::from(error.code as u8)
        }
    }
}

fn execute(cli: &Cli) -> Result<CommandOutput, CliError> {
    let (mut config, config_path) = load_config(cli.config.clone())?;

    match &cli.command {
        Command::Vault { command } => match command {
            VaultCommand::Init(args) => handle_vault_init(cli, &config, args),
            VaultCommand::Check(args) => handle_vault_check(cli, &config, args),
            VaultCommand::Unlock(args) => handle_vault_unlock(cli, &config, args),
            VaultCommand::Status(args) => handle_vault_status(cli, &config, args),
            VaultCommand::Backup(args) => handle_vault_backup(cli, &config, args),
            VaultCommand::ChangePassword(args) => handle_vault_change_password(cli, &config, args),
        },
        Command::Item { command } => handle_item_command(cli, &config, command),
        Command::Import { command } => handle_import_command(cli, &config, command),
        Command::Export { command } => handle_export_command(cli, &config, command),
        Command::Totp(args) => handle_totp(cli, &config, args),
        Command::Recover(args) => handle_recover(cli, &config, args),
        Command::Search(args) => handle_search(cli, &config, args),
        Command::Config { command } => handle_config(command, &mut config, &config_path),
        Command::Generate(args) => handle_generate(args),
    }
}

fn handle_vault_init(
    cli: &Cli,
    config: &AppConfig,
    args: &VaultInitArgs,
) -> Result<CommandOutput, CliError> {
    let path = resolve_vault_path(cli, config, args.path.clone())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(map_io_error)?;
    }

    let password = read_master_password(cli.non_interactive, true)?;
    validate_master_password(&password)?;

    let payload = VaultPayload::new("npw", env!("CARGO_PKG_VERSION"), unix_seconds_now());
    let payload_cbor = payload.to_cbor().map_err(map_model_error)?;

    let kdf_params = KdfParams {
        memory_kib: args.argon_m_kib,
        iterations: args.argon_t,
        parallelism: args.argon_p,
    };
    let vault_bytes = create_vault_file(&CreateVaultInput {
        master_password: &password,
        payload_plaintext: &payload_cbor,
        item_count: 0,
        vault_label: args.label.as_deref(),
        kdf_params,
    })
    .map_err(map_vault_error)?;

    write_vault(&path, &vault_bytes, config.backup.max_retained).map_err(map_storage_error)?;

    Ok(CommandOutput {
        message: format!("Created vault at {}", path.display()),
        payload: json!({
            "path": path,
            "item_count": 0,
            "label": args.label,
            "kdf": {
                "memory_kib": kdf_params.memory_kib,
                "iterations": kdf_params.iterations,
                "parallelism": kdf_params.parallelism
            }
        }),
    })
}

fn handle_vault_check(
    cli: &Cli,
    config: &AppConfig,
    args: &VaultPathArgs,
) -> Result<CommandOutput, CliError> {
    let path = resolve_vault_path(cli, config, args.path.clone())?;
    let vault_bytes = read_vault(&path).map_err(map_storage_error)?;
    let password = read_master_password(cli.non_interactive, false)?;
    let unlocked = unlock_vault_file(&vault_bytes, &password).map_err(map_vault_error)?;

    Ok(CommandOutput {
        message: format!(
            "Vault check passed for {} ({} items)",
            path.display(),
            unlocked.header.item_count
        ),
        payload: json!({
            "path": path,
            "item_count": unlocked.header.item_count,
            "label": unlocked.header.vault_label,
            "payload_bytes": unlocked.payload_plaintext.len()
        }),
    })
}

fn handle_vault_unlock(
    cli: &Cli,
    config: &AppConfig,
    args: &VaultPathArgs,
) -> Result<CommandOutput, CliError> {
    let path = resolve_vault_path(cli, config, args.path.clone())?;
    let vault_bytes = read_vault(&path).map_err(map_storage_error)?;
    let password = read_master_password(cli.non_interactive, false)?;
    unlock_vault_file(&vault_bytes, &password).map_err(map_vault_error)?;

    Ok(CommandOutput {
        message: format!("Vault unlock successful for {}", path.display()),
        payload: json!({
            "path": path,
            "status": "unlocked"
        }),
    })
}

fn handle_vault_status(
    cli: &Cli,
    config: &AppConfig,
    args: &VaultPathArgs,
) -> Result<CommandOutput, CliError> {
    let path = resolve_vault_path(cli, config, args.path.clone())?;
    let vault_bytes = read_vault(&path).map_err(map_storage_error)?;
    let header = parse_vault_header(&vault_bytes).map_err(map_vault_error)?;

    Ok(CommandOutput {
        message: format!(
            "Vault status: {} | label='{}' | items={}",
            path.display(),
            header.vault_label,
            header.item_count
        ),
        payload: json!({
            "path": path,
            "label": header.vault_label,
            "item_count": header.item_count,
            "kdf": {
                "memory_kib": header.kdf_params.memory_kib,
                "iterations": header.kdf_params.iterations,
                "parallelism": header.kdf_params.parallelism
            }
        }),
    })
}

fn handle_vault_backup(
    cli: &Cli,
    config: &AppConfig,
    args: &VaultBackupArgs,
) -> Result<CommandOutput, CliError> {
    let path = resolve_vault_path(cli, config, args.path.clone())?;
    let vault_bytes = read_vault(&path).map_err(map_storage_error)?;
    let header = parse_vault_header(&vault_bytes).map_err(map_vault_error)?;
    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| default_backup_output_path(&path));
    if output_path == path {
        return Err(CliError::usage(
            "backup output path must differ from the vault path",
        ));
    }

    write_vault(&output_path, &vault_bytes, config.backup.max_retained)
        .map_err(map_storage_error)?;

    Ok(CommandOutput {
        message: format!("Created backup at {}", output_path.display()),
        payload: json!({
            "path": path,
            "output": output_path,
            "label": header.vault_label,
            "item_count": header.item_count
        }),
    })
}

fn handle_vault_change_password(
    cli: &Cli,
    config: &AppConfig,
    args: &VaultChangePasswordArgs,
) -> Result<CommandOutput, CliError> {
    if cli.non_interactive {
        return Err(CliError::usage(
            "vault change-password does not support --non-interactive",
        ));
    }

    let path = resolve_vault_path(cli, config, args.path.clone())?;
    let vault_bytes = read_vault(&path).map_err(map_storage_error)?;
    let current_password = read_master_password(false, false)?;
    let unlocked = unlock_vault_file(&vault_bytes, &current_password).map_err(map_vault_error)?;
    let new_password = read_master_password(false, true)?;
    validate_master_password(&new_password)?;

    let rewritten = if args.rotate_vault_key {
        create_vault_file(&CreateVaultInput {
            master_password: &new_password,
            payload_plaintext: &unlocked.payload_plaintext,
            item_count: unlocked.header.item_count,
            vault_label: Some(&unlocked.header.vault_label),
            kdf_params: unlocked.header.kdf_params,
        })
        .map_err(map_vault_error)?
    } else {
        reencrypt_vault_file(&ReencryptVaultInput {
            master_password: &new_password,
            payload_plaintext: &unlocked.payload_plaintext,
            item_count: unlocked.header.item_count,
            header: &unlocked.header,
            envelope: &unlocked.envelope,
        })
        .map_err(map_vault_error)?
    };

    write_vault(&path, &rewritten, config.backup.max_retained).map_err(map_storage_error)?;

    Ok(CommandOutput {
        message: "Master password updated".to_owned(),
        payload: json!({
            "path": path,
            "item_count": unlocked.header.item_count,
            "rotate_vault_key": args.rotate_vault_key
        }),
    })
}

fn handle_item_command(
    cli: &Cli,
    config: &AppConfig,
    command: &ItemCommand,
) -> Result<CommandOutput, CliError> {
    match command {
        ItemCommand::AddLogin(args) => handle_item_add_login(cli, config, args),
        ItemCommand::AddNote(args) => handle_item_add_note(cli, config, args),
        ItemCommand::AddPasskey(args) => handle_item_add_passkey(cli, config, args),
        ItemCommand::Get(args) => handle_item_get(cli, config, args),
        ItemCommand::List(args) => handle_item_list(cli, config, args),
        ItemCommand::Delete(args) => handle_item_delete(cli, config, args),
    }
}

fn handle_import_command(
    cli: &Cli,
    config: &AppConfig,
    command: &ImportCommand,
) -> Result<CommandOutput, CliError> {
    match command {
        ImportCommand::Csv(args) => handle_import_csv(cli, config, args),
    }
}

fn handle_export_command(
    cli: &Cli,
    config: &AppConfig,
    command: &ExportCommand,
) -> Result<CommandOutput, CliError> {
    match command {
        ExportCommand::Csv(args) => handle_export_csv(cli, config, args),
        ExportCommand::Json(args) => handle_export_json(cli, config, args),
        ExportCommand::Encrypted(args) => handle_export_encrypted(cli, config, args),
    }
}

fn handle_import_csv(
    cli: &Cli,
    config: &AppConfig,
    args: &ImportCsvArgs,
) -> Result<CommandOutput, CliError> {
    let now = unix_seconds_now();
    let (path, password, unlocked, mut payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(&args.input)
        .map_err(map_csv_error)?;
    let headers = reader.headers().map_err(map_csv_error)?.clone();
    let supported_headers = HashSet::from([
        "type", "title", "username", "password", "url", "notes", "tags", "totp_uri",
    ]);
    let mut warnings = Vec::new();
    for header in &headers {
        if !supported_headers.contains(header) {
            warnings.push(format!("ignored unknown column `{header}`"));
        }
    }

    let mut login_index = build_login_duplicate_index(&payload);
    let mut imported = 0_u32;
    let mut skipped = 0_u32;
    let mut overwritten = 0_u32;

    for (row_index, result) in reader.records().enumerate() {
        let row = result.map_err(map_csv_error)?;
        let item_type = csv_cell(&headers, &row, "type")
            .unwrap_or("login")
            .trim()
            .to_ascii_lowercase();
        let title = csv_cell(&headers, &row, "title")
            .unwrap_or_default()
            .trim()
            .to_owned();
        if title.is_empty() {
            skipped += 1;
            warnings.push(format!(
                "row {} skipped: missing required `title`",
                row_index + 2
            ));
            continue;
        }

        match item_type.as_str() {
            "login" => {
                let username = normalize_optional_cell(csv_cell(&headers, &row, "username"));
                let password_field = normalize_optional_cell(csv_cell(&headers, &row, "password"));
                let primary_url = normalize_optional_cell(csv_cell(&headers, &row, "url"));
                let notes = normalize_optional_cell(csv_cell(&headers, &row, "notes"));
                let tags = parse_csv_tags(csv_cell(&headers, &row, "tags").unwrap_or_default());
                let totp_uri = normalize_optional_cell(csv_cell(&headers, &row, "totp_uri"));
                let totp = if let Some(uri) = totp_uri {
                    match parse_otpauth_uri(&uri) {
                        Ok(config) => Some(config),
                        Err(error) => {
                            skipped += 1;
                            warnings.push(format!(
                                "row {} skipped: invalid `totp_uri` ({})",
                                row_index + 2,
                                error
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
                let key = login_duplicate_key(&title, username.as_deref(), primary_url.as_deref());

                if let Some(existing_id) = login_index.get(&key).cloned() {
                    match args.duplicate {
                        DuplicatePolicyArg::Skip => {
                            skipped += 1;
                            continue;
                        }
                        DuplicatePolicyArg::Overwrite => {
                            if let Some(VaultItem::Login(existing)) = payload
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
                                overwritten += 1;
                                continue;
                            }
                        }
                        DuplicatePolicyArg::KeepBoth => {}
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
                payload.add_item(item, now).map_err(map_model_error)?;
                login_index.insert(key, item_id);
                imported += 1;
            }
            "note" => {
                let body = csv_cell(&headers, &row, "notes")
                    .unwrap_or_default()
                    .to_owned();
                let tags = parse_csv_tags(csv_cell(&headers, &row, "tags").unwrap_or_default());
                let item = VaultItem::Note(NoteItem {
                    id: Uuid::new_v4().to_string(),
                    title,
                    body,
                    tags,
                    favorite: false,
                    created_at: now,
                    updated_at: now,
                });
                payload.add_item(item, now).map_err(map_model_error)?;
                imported += 1;
            }
            other => {
                skipped += 1;
                warnings.push(format!(
                    "row {} skipped: unsupported `type` value `{other}`",
                    row_index + 2
                ));
            }
        }
    }

    persist_vault_payload(
        &path,
        &password,
        &unlocked,
        payload,
        config.backup.max_retained,
    )?;

    Ok(CommandOutput {
        message: format!(
            "Imported {} rows from {} (skipped {}, overwritten {})",
            imported,
            args.input.display(),
            skipped,
            overwritten
        ),
        payload: json!({
            "path": path,
            "input": args.input,
            "imported": imported,
            "skipped": skipped,
            "overwritten": overwritten,
            "warnings": warnings
        }),
    })
}

fn handle_export_csv(
    cli: &Cli,
    config: &AppConfig,
    args: &ExportArgs,
) -> Result<CommandOutput, CliError> {
    confirm_plaintext_export(cli, args.include_secrets, args.yes)?;
    let (_path, _password, _unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    ensure_output_parent(&args.output)?;

    let mut writer = csv::Writer::from_path(&args.output).map_err(map_csv_error)?;
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
        .map_err(map_csv_error)?;

    for item in &payload.items {
        writer
            .write_record(export_item_csv_row(item, args.include_secrets))
            .map_err(map_csv_error)?;
    }
    writer.flush().map_err(map_io_error)?;

    Ok(CommandOutput {
        message: format!(
            "Exported {} items to {}",
            payload.items.len(),
            args.output.display()
        ),
        payload: json!({
            "output": args.output,
            "item_count": payload.items.len(),
            "redacted": !args.include_secrets,
            "format": "csv"
        }),
    })
}

fn handle_export_json(
    cli: &Cli,
    config: &AppConfig,
    args: &ExportArgs,
) -> Result<CommandOutput, CliError> {
    confirm_plaintext_export(cli, args.include_secrets, args.yes)?;
    let (_path, _password, _unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    ensure_output_parent(&args.output)?;

    let export = json!({
        "exported_at": unix_seconds_now(),
        "redacted": !args.include_secrets,
        "item_count": payload.items.len(),
        "items": payload.items.iter().map(|item| export_item_json(item, args.include_secrets)).collect::<Vec<_>>()
    });
    let encoded = serde_json::to_vec_pretty(&export).map_err(|error| CliError {
        code: CliExitCode::General,
        kind: "export_json_encode_failed",
        message: error.to_string(),
    })?;
    std::fs::write(&args.output, encoded).map_err(map_io_error)?;

    Ok(CommandOutput {
        message: format!(
            "Exported {} items to {}",
            payload.items.len(),
            args.output.display()
        ),
        payload: json!({
            "output": args.output,
            "item_count": payload.items.len(),
            "redacted": !args.include_secrets,
            "format": "json"
        }),
    })
}

fn handle_export_encrypted(
    cli: &Cli,
    config: &AppConfig,
    args: &ExportEncryptedArgs,
) -> Result<CommandOutput, CliError> {
    if cli.non_interactive {
        return Err(CliError::usage(
            "encrypted export does not support --non-interactive",
        ));
    }
    let (path, master_password, unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    if path == args.output {
        return Err(CliError::usage(
            "encrypted export output must differ from vault path",
        ));
    }
    ensure_output_parent(&args.output)?;

    let mut export_payload = if args.redacted {
        redact_payload(payload)
    } else {
        payload
    };
    export_payload.app.name = "npw-export".to_owned();
    export_payload.settings.insert(
        "export_meta.exported_at".to_owned(),
        unix_seconds_now().to_string(),
    );
    export_payload
        .settings
        .insert("export_meta.redacted".to_owned(), args.redacted.to_string());
    let payload_bytes = export_payload.to_cbor().map_err(map_model_error)?;

    let export_password = read_master_password(false, true)?;
    if export_password == master_password {
        return Err(CliError::usage(
            "export password must differ from the vault master password",
        ));
    }

    let encrypted_export = create_vault_file(&CreateVaultInput {
        master_password: &export_password,
        payload_plaintext: &payload_bytes,
        item_count: export_payload.item_count(),
        vault_label: Some("npw-export"),
        kdf_params: unlocked.header.kdf_params,
    })
    .map_err(map_vault_error)?;
    write_vault(&args.output, &encrypted_export, config.backup.max_retained)
        .map_err(map_storage_error)?;

    Ok(CommandOutput {
        message: format!(
            "Wrote encrypted export with {} items to {}",
            export_payload.item_count(),
            args.output.display()
        ),
        payload: json!({
            "output": args.output,
            "item_count": export_payload.item_count(),
            "redacted": args.redacted,
            "format": "npwx"
        }),
    })
}

fn confirm_plaintext_export(
    cli: &Cli,
    include_secrets: bool,
    acknowledged: bool,
) -> Result<(), CliError> {
    if !include_secrets {
        return Ok(());
    }
    if acknowledged {
        return Ok(());
    }
    if cli.non_interactive {
        return Err(CliError::usage(
            "--include-secrets requires --yes in --non-interactive mode",
        ));
    }

    print!("Warning: plaintext export includes passwords and note bodies. Continue? [y/N]: ");
    io::stdout().flush().map_err(map_io_error)?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(map_io_error)?;
    let confirmed = matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    if confirmed {
        Ok(())
    } else {
        Err(CliError::usage("plaintext export cancelled"))
    }
}

fn ensure_output_parent(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(map_io_error)?;
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

fn build_login_duplicate_index(payload: &VaultPayload) -> HashMap<String, String> {
    let mut index = HashMap::new();
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

fn export_item_json(item: &VaultItem, include_secrets: bool) -> Value {
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
                value["totp_uri"] = json!(login.totp.as_ref().map(|totp| login_totp_uri(
                    login.title.as_str(),
                    login.username.as_deref(),
                    totp
                )));
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

fn login_totp_uri(title: &str, username: Option<&str>, config: &TotpConfig) -> String {
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

fn handle_item_add_login(
    cli: &Cli,
    config: &AppConfig,
    args: &ItemAddLoginArgs,
) -> Result<CommandOutput, CliError> {
    let now = unix_seconds_now();
    let (path, password, unlocked, mut payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let totp = build_login_totp(args)?;
    let has_totp = totp.is_some();
    let urls = args
        .urls
        .iter()
        .map(|url| UrlEntry {
            url: url.clone(),
            match_type: UrlMatchType::Exact,
        })
        .collect();

    let item = VaultItem::Login(LoginItem {
        id: Uuid::new_v4().to_string(),
        title: args.title.clone(),
        urls,
        username: args.username.clone(),
        password: args.password.clone(),
        totp,
        notes: args.notes.clone(),
        tags: normalize_tags(&args.tags),
        favorite: args.favorite,
        created_at: now,
        updated_at: now,
    });
    let item_id = item.id().to_owned();
    payload.add_item(item, now).map_err(map_model_error)?;
    persist_vault_payload(
        &path,
        &password,
        &unlocked,
        payload,
        config.backup.max_retained,
    )?;

    Ok(CommandOutput {
        message: format!("Created login item {item_id}"),
        payload: json!({
            "id": item_id,
            "path": path,
            "type": "login",
            "has_totp": has_totp
        }),
    })
}

fn handle_item_add_note(
    cli: &Cli,
    config: &AppConfig,
    args: &ItemAddNoteArgs,
) -> Result<CommandOutput, CliError> {
    let now = unix_seconds_now();
    let (path, password, unlocked, mut payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let item = VaultItem::Note(NoteItem {
        id: Uuid::new_v4().to_string(),
        title: args.title.clone(),
        body: args.body.clone(),
        tags: normalize_tags(&args.tags),
        favorite: args.favorite,
        created_at: now,
        updated_at: now,
    });
    let item_id = item.id().to_owned();
    payload.add_item(item, now).map_err(map_model_error)?;
    persist_vault_payload(
        &path,
        &password,
        &unlocked,
        payload,
        config.backup.max_retained,
    )?;

    Ok(CommandOutput {
        message: format!("Created note item {item_id}"),
        payload: json!({
            "id": item_id,
            "path": path,
            "type": "note"
        }),
    })
}

fn handle_item_add_passkey(
    cli: &Cli,
    config: &AppConfig,
    args: &ItemAddPasskeyArgs,
) -> Result<CommandOutput, CliError> {
    let now = unix_seconds_now();
    let (path, password, unlocked, mut payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let item = VaultItem::PasskeyRef(PasskeyRefItem {
        id: Uuid::new_v4().to_string(),
        title: args.title.clone(),
        rp_id: args.rp_id.clone(),
        rp_name: args.rp_name.clone(),
        user_display_name: args.user_display_name.clone(),
        credential_id: args.credential_id.as_bytes().to_vec(),
        notes: args.notes.clone(),
        tags: normalize_tags(&args.tags),
        favorite: args.favorite,
        created_at: now,
        updated_at: now,
    });
    let item_id = item.id().to_owned();
    payload.add_item(item, now).map_err(map_model_error)?;
    persist_vault_payload(
        &path,
        &password,
        &unlocked,
        payload,
        config.backup.max_retained,
    )?;

    Ok(CommandOutput {
        message: format!("Created passkey_ref item {item_id}"),
        payload: json!({
            "id": item_id,
            "path": path,
            "type": "passkey_ref"
        }),
    })
}

fn handle_item_get(
    cli: &Cli,
    config: &AppConfig,
    args: &ItemIdArgs,
) -> Result<CommandOutput, CliError> {
    let (_path, _password, _unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let item = payload.get_item(&args.id).ok_or_else(|| CliError {
        code: CliExitCode::Usage,
        kind: "item_not_found",
        message: format!("item not found: {}", args.id),
    })?;
    let value = serde_json::to_value(item).map_err(|_| CliError {
        code: CliExitCode::General,
        kind: "item_serialize_failed",
        message: "failed to serialize item".to_owned(),
    })?;

    Ok(CommandOutput {
        message: serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "failed to serialize item".to_owned()),
        payload: json!({
            "item": value
        }),
    })
}

fn handle_item_list(
    cli: &Cli,
    config: &AppConfig,
    args: &ItemListArgs,
) -> Result<CommandOutput, CliError> {
    let (_path, _password, _unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let filter = args.item_type.map(ItemTypeArg::to_filter);
    let items = payload.list_items(filter);
    let items_json = items_to_json(&items)?;

    Ok(CommandOutput {
        message: serde_json::to_string_pretty(&items_json)
            .unwrap_or_else(|_| "failed to serialize item list".to_owned()),
        payload: json!({
            "count": items.len(),
            "items": items_json
        }),
    })
}

fn handle_item_delete(
    cli: &Cli,
    config: &AppConfig,
    args: &ItemIdArgs,
) -> Result<CommandOutput, CliError> {
    let now = unix_seconds_now();
    let (path, password, unlocked, mut payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let deleted = payload.soft_delete_item(&args.id, now);
    if !deleted {
        return Err(CliError {
            code: CliExitCode::Usage,
            kind: "item_not_found",
            message: format!("item not found: {}", args.id),
        });
    }
    persist_vault_payload(
        &path,
        &password,
        &unlocked,
        payload,
        config.backup.max_retained,
    )?;

    Ok(CommandOutput {
        message: format!("Deleted item {}", args.id),
        payload: json!({
            "id": args.id,
            "deleted": true
        }),
    })
}

fn handle_search(
    cli: &Cli,
    config: &AppConfig,
    args: &SearchArgs,
) -> Result<CommandOutput, CliError> {
    let (_path, _password, _unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let items = payload.search_items(&args.query);
    let items_json = items_to_json(&items)?;

    Ok(CommandOutput {
        message: serde_json::to_string_pretty(&items_json)
            .unwrap_or_else(|_| "failed to serialize search results".to_owned()),
        payload: json!({
            "query": args.query,
            "count": items.len(),
            "items": items_json
        }),
    })
}

fn handle_totp(cli: &Cli, config: &AppConfig, args: &TotpArgs) -> Result<CommandOutput, CliError> {
    let (_path, _password, _unlocked, payload) =
        load_vault_payload(cli, config, args.path.clone())?;
    let item = payload.get_item(&args.id).ok_or_else(|| CliError {
        code: CliExitCode::Usage,
        kind: "item_not_found",
        message: format!("item not found: {}", args.id),
    })?;
    let login = match item {
        VaultItem::Login(login) => login,
        _ => {
            return Err(CliError::usage(
                "totp can only be generated for login items",
            ));
        }
    };
    let totp = login
        .totp
        .as_ref()
        .ok_or_else(|| CliError::usage("login item has no TOTP configuration"))?;
    let at = args.at.unwrap_or_else(unix_seconds_now);
    let code = generate_totp(totp, at).map_err(map_totp_error)?;
    let remaining = u64::from(totp.period) - (at % u64::from(totp.period));

    Ok(CommandOutput {
        message: code.clone(),
        payload: json!({
            "id": args.id,
            "code": code,
            "at": at,
            "period": totp.period,
            "digits": totp.digits,
            "algorithm": totp_algorithm_name(totp.algorithm),
            "seconds_remaining": remaining
        }),
    })
}

fn handle_recover(
    cli: &Cli,
    config: &AppConfig,
    args: &RecoverArgs,
) -> Result<CommandOutput, CliError> {
    let path = resolve_vault_path(cli, config, args.path.clone())?;
    let backups = list_backups(&path).map_err(map_storage_error)?;
    if backups.is_empty() {
        return Err(CliError::usage(format!(
            "no backups found for {}",
            path.display()
        )));
    }

    let mut valid_backups = Vec::new();
    for backup in backups {
        let bytes = read_vault(&backup.path).map_err(map_storage_error)?;
        if let Ok(header) = parse_vault_header(&bytes) {
            valid_backups.push((backup, header));
        }
    }
    if valid_backups.is_empty() {
        return Err(CliError {
            code: CliExitCode::CorruptOrParse,
            kind: "no_valid_backups",
            message: "no valid backups found for recovery".to_owned(),
        });
    }

    let selected_index = if args.auto {
        0
    } else {
        if cli.non_interactive {
            return Err(CliError::usage(
                "--non-interactive requires --auto for `npw recover`",
            ));
        }
        prompt_recovery_selection(&path, &valid_backups)?
    };
    let (selected_backup, selected_header) = &valid_backups[selected_index];
    let corrupt_path =
        recover_from_backup(&path, &selected_backup.path).map_err(map_storage_error)?;

    Ok(CommandOutput {
        message: format!(
            "Recovered vault from backup {}",
            selected_backup.path.display()
        ),
        payload: json!({
            "path": path,
            "restored_from": selected_backup.path,
            "backup_timestamp": selected_backup.timestamp,
            "backup_item_count": selected_header.item_count,
            "backup_label": selected_header.vault_label,
            "auto": args.auto,
            "corrupt_path": corrupt_path
        }),
    })
}

fn prompt_recovery_selection(
    vault_path: &Path,
    valid_backups: &[(BackupEntry, npw_core::VaultHeader)],
) -> Result<usize, CliError> {
    println!("Recovery candidates for {}:", vault_path.display());
    for (index, (backup, header)) in valid_backups.iter().enumerate() {
        println!(
            "  {}. {} (timestamp={}, items={}, label='{}')",
            index + 1,
            backup.path.display(),
            backup.timestamp,
            header.item_count,
            header.vault_label
        );
    }

    print!("Select backup to restore [1-{}]: ", valid_backups.len());
    io::stdout().flush().map_err(map_io_error)?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(map_io_error)?;
    let parsed = input
        .trim()
        .parse::<usize>()
        .map_err(|_| CliError::usage("backup selection must be a positive integer"))?;
    if parsed == 0 || parsed > valid_backups.len() {
        return Err(CliError::usage(format!(
            "backup selection must be between 1 and {}",
            valid_backups.len()
        )));
    }
    Ok(parsed - 1)
}

fn load_vault_payload(
    cli: &Cli,
    config: &AppConfig,
    command_path: Option<PathBuf>,
) -> Result<(PathBuf, String, npw_core::UnlockedVault, VaultPayload), CliError> {
    let path = resolve_vault_path(cli, config, command_path)?;
    let vault_bytes = read_vault(&path).map_err(map_storage_error)?;
    let password = read_master_password(cli.non_interactive, false)?;
    let unlocked = unlock_vault_file(&vault_bytes, &password).map_err(map_vault_error)?;
    let payload = VaultPayload::from_cbor(&unlocked.payload_plaintext).map_err(map_model_error)?;
    Ok((path, password, unlocked, payload))
}

fn persist_vault_payload(
    path: &Path,
    password: &str,
    unlocked: &npw_core::UnlockedVault,
    mut payload: VaultPayload,
    max_retained: usize,
) -> Result<(), CliError> {
    payload.rebuild_search_index();
    let payload_bytes = payload.to_cbor().map_err(map_model_error)?;
    let file = reencrypt_vault_file(&ReencryptVaultInput {
        master_password: password,
        payload_plaintext: &payload_bytes,
        item_count: payload.item_count(),
        header: &unlocked.header,
        envelope: &unlocked.envelope,
    })
    .map_err(map_vault_error)?;
    write_vault(path, &file, max_retained).map_err(map_storage_error)
}

fn items_to_json(items: &[&VaultItem]) -> Result<Vec<Value>, CliError> {
    items
        .iter()
        .map(|item| {
            serde_json::to_value(item).map_err(|_| CliError {
                code: CliExitCode::General,
                kind: "item_serialize_failed",
                message: "failed to serialize item".to_owned(),
            })
        })
        .collect()
}

fn handle_config(
    command: &ConfigCommand,
    config: &mut AppConfig,
    config_path: &Path,
) -> Result<CommandOutput, CliError> {
    match command {
        ConfigCommand::Get { key } => {
            let value =
                config_get(config, key).ok_or_else(|| CliError::usage("unknown config key"))?;
            Ok(CommandOutput {
                message: value.clone(),
                payload: json!({
                    "key": key,
                    "value": value
                }),
            })
        }
        ConfigCommand::Set { key, value } => {
            config_set(config, key, value)?;
            save_config(config, config_path)?;
            Ok(CommandOutput {
                message: format!("Updated {key}"),
                payload: json!({
                    "key": key,
                    "value": value
                }),
            })
        }
        ConfigCommand::List => Ok(CommandOutput {
            message: toml::to_string_pretty(config)
                .unwrap_or_else(|_| "failed to serialize config".to_owned()),
            payload: serde_json::to_value(config).map_err(|_| CliError {
                code: CliExitCode::General,
                kind: "config_serialize_failed",
                message: "failed to serialize config".to_owned(),
            })?,
        }),
    }
}

fn handle_generate(args: &GenerateArgs) -> Result<CommandOutput, CliError> {
    match args.mode {
        GenerateMode::Charset => {
            if !(8..=128).contains(&args.length) {
                return Err(CliError::usage(
                    "charset length must be between 8 and 128 characters",
                ));
            }
            let value = generate_charset(args)?;
            Ok(CommandOutput {
                message: value.clone(),
                payload: json!({
                    "mode": "charset",
                    "value": value
                }),
            })
        }
        GenerateMode::Diceware => {
            if !(4..=10).contains(&args.words) {
                return Err(CliError::usage("diceware words must be between 4 and 10"));
            }
            if args.separator.chars().count() != 1 {
                return Err(CliError::usage(
                    "diceware separator must be exactly one character",
                ));
            }
            let value = generate_diceware(args)?;
            Ok(CommandOutput {
                message: value.clone(),
                payload: json!({
                    "mode": "diceware",
                    "value": value
                }),
            })
        }
    }
}

fn load_config(config_override: Option<PathBuf>) -> Result<(AppConfig, PathBuf), CliError> {
    let config_path = match config_override {
        Some(path) => path,
        None => {
            let project_dirs = ProjectDirs::from("", "", "npw").ok_or_else(|| CliError {
                code: CliExitCode::General,
                kind: "config_path_unavailable",
                message: "unable to resolve config path".to_owned(),
            })?;
            project_dirs.config_dir().join("config.toml")
        }
    };

    if !config_path.exists() {
        return Ok((AppConfig::default(), config_path));
    }

    let raw = std::fs::read_to_string(&config_path).map_err(map_io_error)?;
    let config = toml::from_str::<AppConfig>(&raw).map_err(|error| CliError {
        code: CliExitCode::CorruptOrParse,
        kind: "config_parse_failed",
        message: format!("failed to parse {}: {error}", config_path.display()),
    })?;
    Ok((config, config_path))
}

fn save_config(config: &AppConfig, path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(map_io_error)?;
    }
    let data = toml::to_string_pretty(config).map_err(|error| CliError {
        code: CliExitCode::General,
        kind: "config_serialize_failed",
        message: format!("failed to serialize config: {error}"),
    })?;
    std::fs::write(path, data).map_err(map_io_error)
}

fn resolve_vault_path(
    cli: &Cli,
    config: &AppConfig,
    command_path: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    if let Some(path) = command_path {
        return Ok(path);
    }
    if let Some(path) = &cli.vault {
        return Ok(path.clone());
    }
    if let Some(path) = &config.default_vault {
        return Ok(PathBuf::from(path));
    }

    Err(CliError::usage(
        "vault path is required (use --vault, command path argument, or config default_vault)",
    ))
}

fn validate_master_password(password: &str) -> Result<(), CliError> {
    let char_count = password.chars().count();
    let word_count = password.split_whitespace().count();
    if char_count >= 12 || word_count >= 4 {
        return Ok(());
    }

    Err(CliError::usage(
        "master password must be at least 12 characters or at least 4 words",
    ))
}

fn read_master_password(non_interactive: bool, confirm: bool) -> Result<String, CliError> {
    if non_interactive {
        let mut raw = String::new();
        io::stdin().read_to_string(&mut raw).map_err(map_io_error)?;
        let password = raw.lines().next().unwrap_or_default().trim().to_owned();
        if password.is_empty() {
            return Err(CliError {
                code: CliExitCode::Usage,
                kind: "missing_password",
                message: "expected password on stdin for --non-interactive mode".to_owned(),
            });
        }
        return Ok(password);
    }

    let password = rpassword::prompt_password("Master password: ").map_err(map_io_error)?;
    if confirm {
        let confirmation =
            rpassword::prompt_password("Confirm master password: ").map_err(map_io_error)?;
        if password != confirmation {
            return Err(CliError {
                code: CliExitCode::Usage,
                kind: "password_confirmation_failed",
                message: "password confirmation does not match".to_owned(),
            });
        }
    }
    Ok(password)
}

fn map_io_error(error: std::io::Error) -> CliError {
    let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
        CliExitCode::PermissionDenied
    } else {
        CliExitCode::General
    };
    CliError {
        code,
        kind: "io_error",
        message: error.to_string(),
    }
}

fn map_storage_error(error: StorageError) -> CliError {
    match error {
        StorageError::Locked => CliError {
            code: CliExitCode::VaultFileLocked,
            kind: "vault_file_locked",
            message: "vault file is locked by another process".to_owned(),
        },
        StorageError::Io(error) => map_io_error(error),
    }
}

fn map_model_error(error: ModelError) -> CliError {
    match error {
        ModelError::DecodeFailure | ModelError::UnsupportedSchema(_) => CliError {
            code: CliExitCode::CorruptOrParse,
            kind: "payload_parse_error",
            message: error.to_string(),
        },
        ModelError::InvalidField { .. } | ModelError::DuplicateItemId(_) => CliError {
            code: CliExitCode::Usage,
            kind: "payload_validation_error",
            message: error.to_string(),
        },
        ModelError::EncodeFailure => CliError {
            code: CliExitCode::General,
            kind: "payload_encode_error",
            message: error.to_string(),
        },
    }
}

fn map_totp_error(error: TotpError) -> CliError {
    match error {
        TotpError::InvalidBase32Secret
        | TotpError::InvalidOtpAuthUri(_)
        | TotpError::UnsupportedOtpAuthType => CliError {
            code: CliExitCode::Usage,
            kind: "invalid_totp_input",
            message: error.to_string(),
        },
        TotpError::InvalidConfig(_) => CliError {
            code: CliExitCode::CorruptOrParse,
            kind: "invalid_totp_config",
            message: error.to_string(),
        },
    }
}

fn map_csv_error(error: csv::Error) -> CliError {
    CliError {
        code: CliExitCode::CorruptOrParse,
        kind: "csv_error",
        message: error.to_string(),
    }
}

fn map_vault_error(error: VaultError) -> CliError {
    match error {
        VaultError::AuthFailed | VaultError::KdfFailure => CliError {
            code: CliExitCode::AuthFailed,
            kind: "auth_failed",
            message: "authentication failed".to_owned(),
        },
        VaultError::InvalidHeader(_)
        | VaultError::DecodeFailure
        | VaultError::Unsupported(_)
        | VaultError::EncodeFailure => CliError {
            code: CliExitCode::CorruptOrParse,
            kind: "vault_parse_error",
            message: error.to_string(),
        },
        other => CliError {
            code: CliExitCode::General,
            kind: "vault_error",
            message: other.to_string(),
        },
    }
}

fn config_get(config: &AppConfig, key: &str) -> Option<String> {
    match key {
        "default_vault" => config.default_vault.clone(),
        "security.clipboard_timeout_seconds" => {
            Some(config.security.clipboard_timeout_seconds.to_string())
        }
        "security.auto_lock_minutes" => Some(config.security.auto_lock_minutes.to_string()),
        "security.lock_on_suspend" => Some(config.security.lock_on_suspend.to_string()),
        "security.reveal_requires_confirm" => {
            Some(config.security.reveal_requires_confirm.to_string())
        }
        "generator.default_mode" => Some(
            serde_json::to_string(&config.generator.default_mode)
                .unwrap_or_else(|_| "\"charset\"".to_owned())
                .trim_matches('"')
                .to_owned(),
        ),
        "generator.charset_length" => Some(config.generator.charset_length.to_string()),
        "generator.charset_uppercase" => Some(config.generator.charset_uppercase.to_string()),
        "generator.charset_lowercase" => Some(config.generator.charset_lowercase.to_string()),
        "generator.charset_digits" => Some(config.generator.charset_digits.to_string()),
        "generator.charset_symbols" => Some(config.generator.charset_symbols.to_string()),
        "generator.charset_avoid_ambiguous" => {
            Some(config.generator.charset_avoid_ambiguous.to_string())
        }
        "generator.diceware_words" => Some(config.generator.diceware_words.to_string()),
        "generator.diceware_separator" => Some(config.generator.diceware_separator.clone()),
        "logging.level" => Some(config.logging.level.clone()),
        "backup.max_retained" => Some(config.backup.max_retained.to_string()),
        _ => None,
    }
}

fn config_set(config: &mut AppConfig, key: &str, value: &str) -> Result<(), CliError> {
    match key {
        "default_vault" => {
            config.default_vault = Some(value.to_owned());
        }
        "security.clipboard_timeout_seconds" => {
            config.security.clipboard_timeout_seconds = parse_u32(key, value)?;
        }
        "security.auto_lock_minutes" => {
            config.security.auto_lock_minutes = parse_u32(key, value)?;
        }
        "security.lock_on_suspend" => {
            config.security.lock_on_suspend = parse_bool(key, value)?;
        }
        "security.reveal_requires_confirm" => {
            config.security.reveal_requires_confirm = parse_bool(key, value)?;
        }
        "generator.default_mode" => {
            config.generator.default_mode = match value {
                "charset" => GenerateMode::Charset,
                "diceware" => GenerateMode::Diceware,
                _ => {
                    return Err(CliError::usage(
                        "generator.default_mode must be charset or diceware",
                    ));
                }
            };
        }
        "generator.charset_length" => {
            config.generator.charset_length = parse_usize(key, value)?;
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
            config.generator.diceware_words = parse_usize(key, value)?;
        }
        "generator.diceware_separator" => {
            if value.chars().count() != 1 {
                return Err(CliError::usage(
                    "generator.diceware_separator must be one character",
                ));
            }
            config.generator.diceware_separator = value.to_owned();
        }
        "logging.level" => match value {
            "error" | "warn" | "info" | "debug" => config.logging.level = value.to_owned(),
            _ => {
                return Err(CliError::usage(
                    "logging.level must be error|warn|info|debug",
                ));
            }
        },
        "backup.max_retained" => {
            config.backup.max_retained = parse_usize(key, value)?;
        }
        _ => return Err(CliError::usage("unknown config key")),
    }

    Ok(())
}

fn parse_u32(key: &str, value: &str) -> Result<u32, CliError> {
    value
        .parse::<u32>()
        .map_err(|_| CliError::usage(format!("invalid u32 value for {key}")))
}

fn parse_usize(key: &str, value: &str) -> Result<usize, CliError> {
    value
        .parse::<usize>()
        .map_err(|_| CliError::usage(format!("invalid usize value for {key}")))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, CliError> {
    value
        .parse::<bool>()
        .map_err(|_| CliError::usage(format!("invalid bool value for {key}")))
}

fn normalize_tags(raw_tags: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut tags = Vec::new();
    for raw_tag in raw_tags {
        let trimmed = raw_tag.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_owned();
        if seen.insert(normalized.to_lowercase()) {
            tags.push(normalized);
        }
    }
    tags
}

fn default_backup_output_path(vault_path: &Path) -> PathBuf {
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = vault_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.npw");
    parent.join(format!(
        "{file_name}.manual-backup-{}.npw",
        unix_seconds_now()
    ))
}

fn build_login_totp(args: &ItemAddLoginArgs) -> Result<Option<TotpConfig>, CliError> {
    if args.totp_secret_base32.is_some() && args.totp_uri.is_some() {
        return Err(CliError::usage(
            "provide either --totp-secret-base32 or --totp-uri, not both",
        ));
    }

    if let Some(uri) = &args.totp_uri {
        if args.totp_issuer.is_some()
            || args.totp_algorithm.is_some()
            || args.totp_digits.is_some()
            || args.totp_period.is_some()
        {
            return Err(CliError::usage(
                "--totp-uri cannot be combined with explicit TOTP field overrides",
            ));
        }
        return parse_otpauth_uri(uri).map(Some).map_err(map_totp_error);
    }

    if let Some(secret) = &args.totp_secret_base32 {
        let config = TotpConfig {
            seed: decode_base32_secret(secret).map_err(map_totp_error)?,
            issuer: args.totp_issuer.clone(),
            algorithm: args
                .totp_algorithm
                .unwrap_or(TotpAlgorithmArg::Sha1)
                .into_core(),
            digits: args.totp_digits.unwrap_or(6),
            period: args.totp_period.unwrap_or(30),
        };
        config.validate().map_err(map_model_error)?;
        return Ok(Some(config));
    }

    if args.totp_issuer.is_some()
        || args.totp_algorithm.is_some()
        || args.totp_digits.is_some()
        || args.totp_period.is_some()
    {
        return Err(CliError::usage(
            "TOTP options require --totp-secret-base32 or --totp-uri",
        ));
    }

    Ok(None)
}

fn totp_algorithm_name(algorithm: TotpAlgorithm) -> &'static str {
    match algorithm {
        TotpAlgorithm::SHA1 => "SHA1",
        TotpAlgorithm::SHA256 => "SHA256",
        TotpAlgorithm::SHA512 => "SHA512",
    }
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_charset(args: &GenerateArgs) -> Result<String, CliError> {
    let mut alphabet = String::new();

    if args.lowercase {
        alphabet.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if args.uppercase {
        alphabet.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if args.digits {
        alphabet.push_str("0123456789");
    }
    if args.symbols {
        alphabet.push_str("!@#$%^&*()-_=+[]{};:,.<>?/|");
    }

    if args.avoid_ambiguous {
        alphabet = alphabet
            .chars()
            .filter(|character| !matches!(*character, '0' | 'O' | 'o' | '1' | 'l' | 'I'))
            .collect();
    }

    if alphabet.is_empty() {
        return Err(CliError::usage(
            "charset generation needs at least one enabled character set",
        ));
    }

    let chars: Vec<char> = alphabet.chars().collect();
    let mut output = String::with_capacity(args.length);
    for _ in 0..args.length {
        let index = sample_index(chars.len())?;
        output.push(chars[index]);
    }
    Ok(output)
}

fn generate_diceware(args: &GenerateArgs) -> Result<String, CliError> {
    let wordlist = diceware_words();
    let mut words = Vec::with_capacity(args.words);
    for _ in 0..args.words {
        words.push(wordlist[sample_index(wordlist.len())?]);
    }

    let separator = args
        .separator
        .chars()
        .next()
        .ok_or_else(|| CliError::usage("separator is required"))?;
    let mut output = words.join(&separator.to_string());

    if args.inject_digit_symbol {
        let digit = char::from(b'0' + u8::try_from(sample_index(10)?).expect("index under 10"));
        let symbols = ['!', '@', '#', '$', '%', '^', '&', '*'];
        let symbol = symbols[sample_index(symbols.len())?];
        output.push(digit);
        output.push(symbol);
    }

    Ok(output)
}

fn sample_index(limit: usize) -> Result<usize, CliError> {
    if limit == 0 {
        return Err(CliError::usage("cannot sample from an empty collection"));
    }

    let max = u64::MAX - (u64::MAX % u64::try_from(limit).expect("limit should fit in u64"));
    loop {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| CliError {
            code: CliExitCode::General,
            kind: "random_failed",
            message: "failed to generate random values".to_owned(),
        })?;
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
            include_str!("../assets/eff_large_wordlist.txt")
                .lines()
                .filter_map(|line| line.split_once('\t').map(|(_, word)| word.trim()))
                .filter(|word| !word.is_empty())
                .collect()
        })
        .as_slice()
}
