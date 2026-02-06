use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod model;
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

pub use model::{
    AppMetadata, ItemTypeFilter, LoginItem, ModelError, NoteItem, PasskeyRefItem, SearchDoc,
    SearchIndex, Tombstone, TotpAlgorithm, TotpConfig, UrlEntry, UrlMatchType, VaultItem,
    VaultPayload,
};
pub use vault::{
    CreateVaultInput, EnvelopePlaintext, KdfParams, ReencryptVaultInput, UnlockedVault, VaultError,
    VaultHeader, create_vault_file, parse_vault_header, reencrypt_vault_file, unlock_vault_file,
};
