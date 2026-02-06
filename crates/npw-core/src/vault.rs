use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

const MAGIC: &[u8; 4] = b"NPW1";
const FORMAT_VERSION: u16 = 1;
const HEADER_FLAGS: u16 = 0;
const KDF_ID_ARGON2ID: u8 = 1;
const AEAD_ID_XCHACHA20_POLY1305: u8 = 1;
const RESERVED_U16: u16 = 0;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MAX_LABEL_BYTES: usize = 64;
const MIN_ENV_CIPHERTEXT_LEN: u32 = 48;
const MAX_ENV_CIPHERTEXT_LEN: u32 = 4096;
const MAX_PAYLOAD_CIPHERTEXT_LEN: u64 = 256 * 1024 * 1024;
const AEAD_TAG_LEN: usize = 16;
const KDF_MEMORY_MIN_KIB: u32 = 64 * 1024;
const KDF_MEMORY_MAX_KIB: u32 = 1024 * 1024;
const KDF_ITERATIONS_MIN: u32 = 1;
const KDF_ITERATIONS_MAX: u32 = 10;
const KDF_PARALLELISM_MIN: u32 = 1;
const KDF_PARALLELISM_MAX: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 512 * 1024,
            iterations: 4,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    pub fn validate(self) -> Result<(), VaultError> {
        validate_range(
            self.memory_kib,
            KDF_MEMORY_MIN_KIB,
            KDF_MEMORY_MAX_KIB,
            "argon_m_kib",
        )?;
        validate_range(
            self.iterations,
            KDF_ITERATIONS_MIN,
            KDF_ITERATIONS_MAX,
            "argon_t",
        )?;
        validate_range(
            self.parallelism,
            KDF_PARALLELISM_MIN,
            KDF_PARALLELISM_MAX,
            "argon_p",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CreateVaultInput<'a> {
    pub master_password: &'a str,
    pub payload_plaintext: &'a [u8],
    pub item_count: u32,
    pub vault_label: Option<&'a str>,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone)]
pub struct ReencryptVaultInput<'a> {
    pub master_password: &'a str,
    pub payload_plaintext: &'a [u8],
    pub item_count: u32,
    pub header: &'a VaultHeader,
    pub envelope: &'a EnvelopePlaintext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub kdf_params: KdfParams,
    pub item_count: u32,
    pub vault_label: String,
    pub salt: [u8; SALT_LEN],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopePlaintext {
    pub vault_id: [u8; 16],
    pub vault_key: [u8; KEY_LEN],
    pub created_at: u64,
    pub kdf_hint: Option<String>,
    pub reserved: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockedVault {
    pub header: VaultHeader,
    pub envelope: EnvelopePlaintext,
    pub payload_plaintext: Vec<u8>,
}

#[derive(Debug)]
pub struct UnlockedVaultWithKek {
    pub header: VaultHeader,
    pub envelope: EnvelopePlaintext,
    pub payload_plaintext: Vec<u8>,
    kek: [u8; KEY_LEN],
}

impl UnlockedVaultWithKek {
    #[must_use]
    pub fn kek(&self) -> &[u8; KEY_LEN] {
        &self.kek
    }
}

impl Drop for UnlockedVaultWithKek {
    fn drop(&mut self) {
        self.kek.zeroize();
        self.envelope.vault_key.zeroize();
        self.payload_plaintext.zeroize();
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("unsupported vault setting: {0}")]
    Unsupported(&'static str),
    #[error("{field} out of bounds: {value} (expected {min}..={max})")]
    KdfOutOfBounds {
        field: &'static str,
        value: u32,
        min: u32,
        max: u32,
    },
    #[error("vault label too long: max 64 bytes")]
    LabelTooLong,
    #[error("password derivation failed")]
    KdfFailure,
    #[error("key expansion failed")]
    KeyExpansionFailure,
    #[error("encryption failed")]
    EncryptionFailure,
    #[error("authentication failed")]
    AuthFailed,
    #[error("encoding failed")]
    EncodeFailure,
    #[error("decoding failed")]
    DecodeFailure,
    #[error("randomness source failed")]
    RandomFailure,
}

pub fn create_vault_file(input: &CreateVaultInput<'_>) -> Result<Vec<u8>, VaultError> {
    input.kdf_params.validate()?;
    let label = input.vault_label.unwrap_or("");
    if label.len() > MAX_LABEL_BYTES {
        return Err(VaultError::LabelTooLong);
    }

    let mut salt = random_bytes::<SALT_LEN>()?;
    let mut envelope = EnvelopePlaintext {
        vault_id: random_bytes::<16>()?,
        vault_key: random_bytes::<KEY_LEN>()?,
        created_at: unix_seconds_now(),
        kdf_hint: None,
        reserved: None,
    };

    let file = build_vault_file(
        input.master_password,
        input.payload_plaintext,
        input.item_count,
        label,
        input.kdf_params,
        &salt,
        &envelope,
    );

    envelope.vault_key.zeroize();
    salt.zeroize();
    file
}

pub fn reencrypt_vault_file(input: &ReencryptVaultInput<'_>) -> Result<Vec<u8>, VaultError> {
    input.header.kdf_params.validate()?;
    build_vault_file(
        input.master_password,
        input.payload_plaintext,
        input.item_count,
        &input.header.vault_label,
        input.header.kdf_params,
        &input.header.salt,
        input.envelope,
    )
}

pub fn reencrypt_vault_file_with_kek(
    kek: &[u8; KEY_LEN],
    payload_plaintext: &[u8],
    item_count: u32,
    header: &VaultHeader,
    envelope: &EnvelopePlaintext,
) -> Result<Vec<u8>, VaultError> {
    header.kdf_params.validate()?;
    build_vault_file_with_kek(
        kek,
        payload_plaintext,
        item_count,
        &header.vault_label,
        header.kdf_params,
        &header.salt,
        envelope,
    )
}

fn build_vault_file(
    master_password: &str,
    payload_plaintext: &[u8],
    item_count: u32,
    vault_label: &str,
    kdf_params: KdfParams,
    salt: &[u8; SALT_LEN],
    envelope: &EnvelopePlaintext,
) -> Result<Vec<u8>, VaultError> {
    if vault_label.len() > MAX_LABEL_BYTES {
        return Err(VaultError::LabelTooLong);
    }

    let mut kdf_key = derive_kdf_key(master_password, salt, kdf_params)?;
    let mut kek = derive_hkdf(&kdf_key, b"NPW:v1:KEK")?;
    let file_bytes = build_vault_file_with_kek(
        &kek,
        payload_plaintext,
        item_count,
        vault_label,
        kdf_params,
        salt,
        envelope,
    );

    kdf_key.zeroize();
    kek.zeroize();

    file_bytes
}

fn build_vault_file_with_kek(
    kek: &[u8; KEY_LEN],
    payload_plaintext: &[u8],
    item_count: u32,
    vault_label: &str,
    kdf_params: KdfParams,
    salt: &[u8; SALT_LEN],
    envelope: &EnvelopePlaintext,
) -> Result<Vec<u8>, VaultError> {
    if vault_label.len() > MAX_LABEL_BYTES {
        return Err(VaultError::LabelTooLong);
    }

    let env_nonce = random_bytes::<NONCE_LEN>()?;
    let payload_nonce = random_bytes::<NONCE_LEN>()?;
    let mut payload_key = derive_hkdf(&envelope.vault_key, b"NPW:v1:PAYLOAD")?;
    let envelope_plaintext = to_cbor(&envelope)?;
    let env_ciphertext_len = ciphertext_len_u32(&envelope_plaintext)?;
    validate_env_ciphertext_len(env_ciphertext_len)?;

    let mut env_aad = Vec::new();
    push_header_prefix(
        &mut env_aad,
        vault_label,
        kdf_params,
        item_count,
        salt,
        &env_nonce,
    )?;
    push_u32_le(&mut env_aad, env_ciphertext_len);

    let env_ciphertext = encrypt(kek, &env_nonce, &envelope_plaintext, &env_aad)?;
    let payload_ciphertext_len = ciphertext_len_u64(payload_plaintext)?;
    if payload_ciphertext_len > MAX_PAYLOAD_CIPHERTEXT_LEN {
        payload_key.zeroize();
        return Err(VaultError::InvalidHeader("payload_ct_len"));
    }

    let mut payload_aad = env_aad;
    payload_aad.extend_from_slice(&env_ciphertext);
    push_u16_len(&mut payload_aad, NONCE_LEN, "payload_nonce_len")?;
    payload_aad.extend_from_slice(&payload_nonce);
    push_u64_le(&mut payload_aad, payload_ciphertext_len);

    let payload_ciphertext = encrypt(
        &payload_key,
        &payload_nonce,
        payload_plaintext,
        &payload_aad,
    )?;

    let mut file_bytes = payload_aad;
    file_bytes.extend_from_slice(&payload_ciphertext);

    payload_key.zeroize();

    Ok(file_bytes)
}

pub fn unlock_vault_file(
    vault_bytes: &[u8],
    master_password: &str,
) -> Result<UnlockedVault, VaultError> {
    let parsed = parse_vault(vault_bytes)?;

    let mut kdf_key = derive_kdf_key(
        master_password,
        &parsed.header.salt,
        parsed.header.kdf_params,
    )?;
    let mut kek = derive_hkdf(&kdf_key, b"NPW:v1:KEK")?;
    let mut envelope_plaintext = decrypt(
        &kek,
        &parsed.env_nonce,
        parsed.env_ciphertext,
        parsed.env_aad,
    )?;
    let envelope: EnvelopePlaintext = from_cbor(&envelope_plaintext)?;
    let mut payload_key = derive_hkdf(&envelope.vault_key, b"NPW:v1:PAYLOAD")?;
    let payload_plaintext = decrypt(
        &payload_key,
        &parsed.payload_nonce,
        parsed.payload_ciphertext,
        parsed.payload_aad,
    )?;

    kdf_key.zeroize();
    kek.zeroize();
    payload_key.zeroize();
    envelope_plaintext.zeroize();

    Ok(UnlockedVault {
        header: parsed.header,
        envelope,
        payload_plaintext,
    })
}

pub fn unlock_vault_file_with_kek(
    vault_bytes: &[u8],
    master_password: &str,
) -> Result<UnlockedVaultWithKek, VaultError> {
    let parsed = parse_vault(vault_bytes)?;

    let mut kdf_key = derive_kdf_key(
        master_password,
        &parsed.header.salt,
        parsed.header.kdf_params,
    )?;
    let mut kek = derive_hkdf(&kdf_key, b"NPW:v1:KEK")?;

    let mut envelope_plaintext = match decrypt(
        &kek,
        &parsed.env_nonce,
        parsed.env_ciphertext,
        parsed.env_aad,
    ) {
        Ok(value) => value,
        Err(error) => {
            kdf_key.zeroize();
            kek.zeroize();
            return Err(error);
        }
    };

    let envelope: EnvelopePlaintext = match from_cbor(&envelope_plaintext) {
        Ok(value) => value,
        Err(error) => {
            kdf_key.zeroize();
            kek.zeroize();
            envelope_plaintext.zeroize();
            return Err(error);
        }
    };
    let mut payload_key = derive_hkdf(&envelope.vault_key, b"NPW:v1:PAYLOAD")?;
    let payload_plaintext = match decrypt(
        &payload_key,
        &parsed.payload_nonce,
        parsed.payload_ciphertext,
        parsed.payload_aad,
    ) {
        Ok(value) => value,
        Err(error) => {
            kdf_key.zeroize();
            kek.zeroize();
            payload_key.zeroize();
            envelope_plaintext.zeroize();
            return Err(error);
        }
    };

    kdf_key.zeroize();
    payload_key.zeroize();
    envelope_plaintext.zeroize();

    Ok(UnlockedVaultWithKek {
        header: parsed.header,
        envelope,
        payload_plaintext,
        kek,
    })
}

pub fn parse_vault_header(vault_bytes: &[u8]) -> Result<VaultHeader, VaultError> {
    Ok(parse_vault(vault_bytes)?.header)
}

fn validate_env_ciphertext_len(len: u32) -> Result<(), VaultError> {
    if !(MIN_ENV_CIPHERTEXT_LEN..=MAX_ENV_CIPHERTEXT_LEN).contains(&len) {
        return Err(VaultError::InvalidHeader("env_ct_len"));
    }

    Ok(())
}

fn push_header_prefix(
    output: &mut Vec<u8>,
    vault_label: &str,
    kdf_params: KdfParams,
    item_count: u32,
    salt: &[u8; SALT_LEN],
    env_nonce: &[u8; NONCE_LEN],
) -> Result<(), VaultError> {
    let label_bytes = vault_label.as_bytes();
    if label_bytes.len() > MAX_LABEL_BYTES {
        return Err(VaultError::LabelTooLong);
    }

    output.extend_from_slice(MAGIC);
    push_u16_le(output, FORMAT_VERSION);
    push_u16_le(output, HEADER_FLAGS);
    output.push(KDF_ID_ARGON2ID);
    output.push(AEAD_ID_XCHACHA20_POLY1305);
    push_u16_le(output, RESERVED_U16);
    push_u32_le(output, kdf_params.memory_kib);
    push_u32_le(output, kdf_params.iterations);
    push_u32_le(output, kdf_params.parallelism);
    push_u32_le(output, item_count);
    output.push(
        label_bytes
            .len()
            .try_into()
            .map_err(|_| VaultError::LabelTooLong)?,
    );
    output.extend_from_slice(label_bytes);
    push_u16_len(output, SALT_LEN, "salt_len")?;
    output.extend_from_slice(salt);
    push_u16_len(output, NONCE_LEN, "env_nonce_len")?;
    output.extend_from_slice(env_nonce);
    Ok(())
}

fn parse_vault(bytes: &[u8]) -> Result<ParsedVault<'_>, VaultError> {
    let mut reader = Reader::new(bytes);

    let magic = reader.read_exact(4)?;
    if magic != MAGIC {
        return Err(VaultError::InvalidHeader("magic"));
    }

    let format_version = reader.read_u16_le()?;
    if format_version != FORMAT_VERSION {
        return Err(VaultError::Unsupported("format_version"));
    }

    let _header_flags = reader.read_u16_le()?;

    let kdf_id = reader.read_u8()?;
    if kdf_id != KDF_ID_ARGON2ID {
        return Err(VaultError::Unsupported("kdf_id"));
    }

    let aead_id = reader.read_u8()?;
    if aead_id != AEAD_ID_XCHACHA20_POLY1305 {
        return Err(VaultError::Unsupported("aead_id"));
    }

    let _reserved = reader.read_u16_le()?;

    let kdf_params = KdfParams {
        memory_kib: reader.read_u32_le()?,
        iterations: reader.read_u32_le()?,
        parallelism: reader.read_u32_le()?,
    };
    kdf_params.validate()?;

    let item_count = reader.read_u32_le()?;
    let label_len = usize::from(reader.read_u8()?);
    if label_len > MAX_LABEL_BYTES {
        return Err(VaultError::InvalidHeader("vault_label_len"));
    }
    let vault_label = String::from_utf8(reader.read_exact(label_len)?.to_vec())
        .map_err(|_| VaultError::InvalidHeader("vault_label"))?;

    let salt_len = usize::from(reader.read_u16_le()?);
    if salt_len != SALT_LEN {
        return Err(VaultError::InvalidHeader("salt_len"));
    }
    let mut salt = [0_u8; SALT_LEN];
    salt.copy_from_slice(reader.read_exact(SALT_LEN)?);

    let env_nonce_len = usize::from(reader.read_u16_le()?);
    if env_nonce_len != NONCE_LEN {
        return Err(VaultError::InvalidHeader("env_nonce_len"));
    }
    let mut env_nonce = [0_u8; NONCE_LEN];
    env_nonce.copy_from_slice(reader.read_exact(NONCE_LEN)?);

    let env_ct_len_u32 = reader.read_u32_le()?;
    validate_env_ciphertext_len(env_ct_len_u32)?;
    let env_ct_len =
        usize::try_from(env_ct_len_u32).map_err(|_| VaultError::InvalidHeader("env_ct_len"))?;
    let env_ct_start = reader.position;
    let env_ciphertext = reader.read_exact(env_ct_len)?;

    let payload_nonce_len = usize::from(reader.read_u16_le()?);
    if payload_nonce_len != NONCE_LEN {
        return Err(VaultError::InvalidHeader("payload_nonce_len"));
    }
    let mut payload_nonce = [0_u8; NONCE_LEN];
    payload_nonce.copy_from_slice(reader.read_exact(NONCE_LEN)?);

    let payload_ct_len_u64 = reader.read_u64_le()?;
    if payload_ct_len_u64 > MAX_PAYLOAD_CIPHERTEXT_LEN {
        return Err(VaultError::InvalidHeader("payload_ct_len"));
    }
    let payload_ct_len = usize::try_from(payload_ct_len_u64)
        .map_err(|_| VaultError::InvalidHeader("payload_ct_len"))?;
    let payload_ct_start = reader.position;
    let payload_ciphertext = reader.read_exact(payload_ct_len)?;

    if !reader.at_end() {
        return Err(VaultError::InvalidHeader("trailing_bytes"));
    }

    let header = VaultHeader {
        kdf_params,
        item_count,
        vault_label,
        salt,
    };

    Ok(ParsedVault {
        header,
        env_nonce,
        env_aad: &bytes[..env_ct_start],
        env_ciphertext,
        payload_nonce,
        payload_aad: &bytes[..payload_ct_start],
        payload_ciphertext,
    })
}

fn derive_kdf_key(
    master_password: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<[u8; KEY_LEN], VaultError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| VaultError::KdfFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut normalized_password: String = master_password.nfkc().collect();
    let mut output = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(normalized_password.as_bytes(), salt, &mut output)
        .map_err(|_| VaultError::KdfFailure)?;
    normalized_password.zeroize();
    Ok(output)
}

fn derive_hkdf(input_key: &[u8; KEY_LEN], info: &[u8]) -> Result<[u8; KEY_LEN], VaultError> {
    let hkdf = Hkdf::<Sha256>::new(None, input_key);
    let mut output = [0_u8; KEY_LEN];
    hkdf.expand(info, &mut output)
        .map_err(|_| VaultError::KeyExpansionFailure)?;
    Ok(output)
}

fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::EncryptionFailure)
}

fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| VaultError::AuthFailed)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut out = [0_u8; N];
    getrandom::fill(&mut out).map_err(|_| VaultError::RandomFailure)?;
    Ok(out)
}

fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, VaultError> {
    let mut output = Vec::new();
    ciborium::ser::into_writer(value, &mut output).map_err(|_| VaultError::EncodeFailure)?;
    Ok(output)
}

fn from_cbor<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, VaultError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| VaultError::DecodeFailure)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_range(value: u32, min: u32, max: u32, field: &'static str) -> Result<(), VaultError> {
    if !(min..=max).contains(&value) {
        return Err(VaultError::KdfOutOfBounds {
            field,
            value,
            min,
            max,
        });
    }

    Ok(())
}

fn ciphertext_len_u32(plaintext: &[u8]) -> Result<u32, VaultError> {
    let total_len = plaintext
        .len()
        .checked_add(AEAD_TAG_LEN)
        .ok_or(VaultError::InvalidHeader("ciphertext_overflow"))?;
    u32::try_from(total_len).map_err(|_| VaultError::InvalidHeader("ciphertext_overflow"))
}

fn ciphertext_len_u64(plaintext: &[u8]) -> Result<u64, VaultError> {
    let total_len = plaintext
        .len()
        .checked_add(AEAD_TAG_LEN)
        .ok_or(VaultError::InvalidHeader("ciphertext_overflow"))?;
    u64::try_from(total_len).map_err(|_| VaultError::InvalidHeader("ciphertext_overflow"))
}

fn push_u16_len(output: &mut Vec<u8>, value: usize, field: &'static str) -> Result<(), VaultError> {
    let value = u16::try_from(value).map_err(|_| VaultError::InvalidHeader(field))?;
    push_u16_le(output, value);
    Ok(())
}

fn push_u16_le(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32_le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

struct ParsedVault<'a> {
    header: VaultHeader,
    env_nonce: [u8; NONCE_LEN],
    env_aad: &'a [u8],
    env_ciphertext: &'a [u8],
    payload_nonce: [u8; NONCE_LEN],
    payload_aad: &'a [u8],
    payload_ciphertext: &'a [u8],
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn at_end(&self) -> bool {
        self.position == self.input.len()
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], VaultError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(VaultError::InvalidHeader("length_overflow"))?;
        if end > self.input.len() {
            return Err(VaultError::InvalidHeader("unexpected_eof"));
        }
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8, VaultError> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16_le(&mut self) -> Result<u16, VaultError> {
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(self.read_exact(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32_le(&mut self) -> Result<u32, VaultError> {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(self.read_exact(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64_le(&mut self) -> Result<u64, VaultError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.read_exact(8)?);
        Ok(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{
        CreateVaultInput, KdfParams, VaultError, create_vault_file, reencrypt_vault_file_with_kek,
        unlock_vault_file, unlock_vault_file_with_kek,
    };

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct SamplePayload {
        schema: u8,
        message: String,
    }

    #[test]
    fn roundtrip_unlock_with_kek_and_reencrypt() {
        let payload = payload_bytes();
        let file = create_vault_file(&CreateVaultInput {
            master_password: "correct horse battery staple",
            payload_plaintext: &payload,
            item_count: 3,
            vault_label: Some("Personal"),
            kdf_params: KdfParams::default(),
        })
        .expect("vault creation should succeed");
        let unlocked = unlock_vault_file_with_kek(&file, "correct horse battery staple")
            .expect("unlock should succeed");

        let new_payload = b"new payload".to_vec();
        let rewritten = reencrypt_vault_file_with_kek(
            unlocked.kek(),
            &new_payload,
            5,
            &unlocked.header,
            &unlocked.envelope,
        )
        .expect("reencrypt should succeed");
        let unlocked_again = unlock_vault_file(&rewritten, "correct horse battery staple")
            .expect("unlock should succeed");
        assert_eq!(unlocked_again.payload_plaintext, new_payload);
        assert_eq!(unlocked_again.header.item_count, 5);
    }

    #[test]
    fn roundtrip_encrypts_and_decrypts_payload() {
        let payload = payload_bytes();
        let file = create_vault_file(&CreateVaultInput {
            master_password: "correct horse battery staple",
            payload_plaintext: &payload,
            item_count: 7,
            vault_label: Some("Personal"),
            kdf_params: KdfParams::default(),
        })
        .expect("vault creation should succeed");
        let unlocked = unlock_vault_file(&file, "correct horse battery staple")
            .expect("unlock should succeed");

        assert_eq!(unlocked.payload_plaintext, payload);
        assert_eq!(unlocked.header.item_count, 7);
        assert_eq!(unlocked.header.vault_label, "Personal");
    }

    #[test]
    fn rejects_out_of_bounds_kdf_memory() {
        let payload = payload_bytes();
        let result = create_vault_file(&CreateVaultInput {
            master_password: "correct horse battery staple",
            payload_plaintext: &payload,
            item_count: 1,
            vault_label: None,
            kdf_params: KdfParams {
                memory_kib: 32 * 1024,
                ..KdfParams::default()
            },
        });

        assert!(matches!(result, Err(VaultError::KdfOutOfBounds { .. })));
    }

    #[test]
    fn tampering_header_byte_fails_authentication() {
        let payload = payload_bytes();
        let mut file = create_vault_file(&CreateVaultInput {
            master_password: "correct horse battery staple",
            payload_plaintext: &payload,
            item_count: 1,
            vault_label: None,
            kdf_params: KdfParams::default(),
        })
        .expect("vault creation should succeed");

        file[6] ^= 0x01;
        let result = unlock_vault_file(&file, "correct horse battery staple");

        assert!(matches!(result, Err(VaultError::AuthFailed)));
    }

    fn payload_bytes() -> Vec<u8> {
        let payload = SamplePayload {
            schema: 1,
            message: "hello".to_owned(),
        };
        let mut output = Vec::new();
        ciborium::ser::into_writer(&payload, &mut output).expect("payload cbor must encode");
        output
    }
}
