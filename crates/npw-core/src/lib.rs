use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod vault;

pub const APP_NAME: &str = "npw";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct VaultId(pub Uuid);

impl VaultId {
    #[must_use]
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }
}

#[must_use]
pub fn bootstrap_banner() -> String {
    format!("{APP_NAME} core ready")
}

pub use vault::{
    CreateVaultInput, EnvelopePlaintext, KdfParams, UnlockedVault, VaultError, VaultHeader,
    create_vault_file, parse_vault_header, unlock_vault_file,
};
