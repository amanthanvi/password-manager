use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use url::Url;

use crate::model::{TotpAlgorithm, TotpConfig};

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid base32 TOTP secret")]
    InvalidBase32Secret,
    #[error("invalid otpauth URI: {0}")]
    InvalidOtpAuthUri(String),
    #[error("unsupported otpauth URI type; expected `totp`")]
    UnsupportedOtpAuthType,
    #[error("invalid TOTP config: {0}")]
    InvalidConfig(String),
}

pub fn decode_base32_secret(secret: &str) -> Result<Vec<u8>, TotpError> {
    let normalized: String = secret
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .map(|character| character.to_ascii_uppercase())
        .collect();
    if normalized.is_empty() {
        return Err(TotpError::InvalidBase32Secret);
    }

    let decoded = BASE32
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32_NOPAD.decode(normalized.as_bytes()))
        .map_err(|_| TotpError::InvalidBase32Secret)?;
    if decoded.is_empty() {
        return Err(TotpError::InvalidBase32Secret);
    }

    Ok(decoded)
}

pub fn parse_otpauth_uri(uri: &str) -> Result<TotpConfig, TotpError> {
    let parsed =
        Url::parse(uri).map_err(|error| TotpError::InvalidOtpAuthUri(error.to_string()))?;
    if parsed.scheme() != "otpauth" {
        return Err(TotpError::InvalidOtpAuthUri(
            "scheme must be `otpauth`".to_owned(),
        ));
    }
    if parsed.host_str() != Some("totp") {
        return Err(TotpError::UnsupportedOtpAuthType);
    }

    let mut secret: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut algorithm = TotpAlgorithm::SHA1;
    let mut digits: u8 = 6;
    let mut period: u16 = 30;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.into_owned()),
            "issuer" => issuer = Some(value.into_owned()),
            "algorithm" => {
                algorithm = parse_algorithm(value.as_ref())?;
            }
            "digits" => {
                digits = value.parse::<u8>().map_err(|_| {
                    TotpError::InvalidOtpAuthUri("digits must be an integer".to_owned())
                })?;
            }
            "period" => {
                period = value.parse::<u16>().map_err(|_| {
                    TotpError::InvalidOtpAuthUri("period must be an integer".to_owned())
                })?;
            }
            _ => {}
        }
    }

    let seed = decode_base32_secret(secret.as_deref().ok_or_else(|| {
        TotpError::InvalidOtpAuthUri("missing `secret` query parameter".to_owned())
    })?)?;
    let config = TotpConfig {
        seed,
        issuer: issuer.filter(|value| !value.is_empty()),
        algorithm,
        digits,
        period,
    };
    config
        .validate()
        .map_err(|error| TotpError::InvalidConfig(error.to_string()))?;
    Ok(config)
}

pub fn generate_totp(config: &TotpConfig, unix_seconds: u64) -> Result<String, TotpError> {
    config
        .validate()
        .map_err(|error| TotpError::InvalidConfig(error.to_string()))?;

    let counter = unix_seconds / u64::from(config.period);
    let counter_bytes = counter.to_be_bytes();
    let hmac = match config.algorithm {
        TotpAlgorithm::SHA1 => hmac_sha1(&config.seed, &counter_bytes)?,
        TotpAlgorithm::SHA256 => hmac_sha256(&config.seed, &counter_bytes)?,
        TotpAlgorithm::SHA512 => hmac_sha512(&config.seed, &counter_bytes)?,
    };

    let value = dynamic_truncate(&hmac)?;
    let modulus = 10_u32.pow(u32::from(config.digits));
    let code = value % modulus;
    Ok(format!(
        "{code:0width$}",
        width = usize::from(config.digits)
    ))
}

pub fn generate_totp_now(config: &TotpConfig) -> Result<String, TotpError> {
    generate_totp(config, unix_seconds_now())
}

fn parse_algorithm(value: &str) -> Result<TotpAlgorithm, TotpError> {
    match value.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(TotpAlgorithm::SHA1),
        "SHA256" => Ok(TotpAlgorithm::SHA256),
        "SHA512" => Ok(TotpAlgorithm::SHA512),
        _ => Err(TotpError::InvalidOtpAuthUri(format!(
            "unsupported algorithm `{value}`"
        ))),
    }
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Result<Vec<u8>, TotpError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|_| TotpError::InvalidConfig("invalid seed length".to_owned()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>, TotpError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| TotpError::InvalidConfig("invalid seed length".to_owned()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<Vec<u8>, TotpError> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
        .map_err(|_| TotpError::InvalidConfig("invalid seed length".to_owned()))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn dynamic_truncate(hmac: &[u8]) -> Result<u32, TotpError> {
    let offset = usize::from(
        *hmac
            .last()
            .ok_or_else(|| TotpError::InvalidConfig("empty HMAC output".to_owned()))?
            & 0x0f,
    );
    if hmac.len() < offset + 4 {
        return Err(TotpError::InvalidConfig(
            "HMAC output too short for dynamic truncation".to_owned(),
        ));
    }

    let b0 = u32::from(hmac[offset] & 0x7f);
    let b1 = u32::from(hmac[offset + 1]);
    let b2 = u32::from(hmac[offset + 2]);
    let b3 = u32::from(hmac[offset + 3]);
    Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
}

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{decode_base32_secret, generate_totp, parse_otpauth_uri};
    use crate::model::{TotpAlgorithm, TotpConfig};

    #[test]
    fn matches_rfc6238_vectors() {
        let seed_sha1 = b"12345678901234567890".to_vec();
        let seed_sha256 = b"12345678901234567890123456789012".to_vec();
        let seed_sha512 =
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
        let vectors = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];

        for (timestamp, sha1_code, sha256_code, sha512_code) in vectors {
            let sha1 = TotpConfig {
                seed: seed_sha1.clone(),
                issuer: None,
                algorithm: TotpAlgorithm::SHA1,
                digits: 8,
                period: 30,
            };
            let sha256 = TotpConfig {
                seed: seed_sha256.clone(),
                issuer: None,
                algorithm: TotpAlgorithm::SHA256,
                digits: 8,
                period: 30,
            };
            let sha512 = TotpConfig {
                seed: seed_sha512.clone(),
                issuer: None,
                algorithm: TotpAlgorithm::SHA512,
                digits: 8,
                period: 30,
            };

            assert_eq!(
                generate_totp(&sha1, timestamp).expect("sha1 TOTP should generate"),
                sha1_code
            );
            assert_eq!(
                generate_totp(&sha256, timestamp).expect("sha256 TOTP should generate"),
                sha256_code
            );
            assert_eq!(
                generate_totp(&sha512, timestamp).expect("sha512 TOTP should generate"),
                sha512_code
            );
        }
    }

    #[test]
    fn decodes_base32_secret() {
        let decoded = decode_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .expect("base32 secret should decode");
        assert_eq!(decoded, b"12345678901234567890");
    }

    #[test]
    fn parses_otpauth_uri() {
        let config = parse_otpauth_uri(
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=npw&algorithm=SHA256&digits=8&period=60",
        )
        .expect("otpauth URI should parse");

        assert_eq!(config.issuer.as_deref(), Some("npw"));
        assert_eq!(config.algorithm, TotpAlgorithm::SHA256);
        assert_eq!(config.digits, 8);
        assert_eq!(config.period, 60);
        assert!(!config.seed.is_empty());
    }
}
