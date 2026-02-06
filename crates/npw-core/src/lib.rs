use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[cfg(test)]
mod tests {
    #[test]
    fn bootstrap_banner_mentions_app_name() {
        assert!(super::bootstrap_banner().contains(super::APP_NAME));
    }

    #[test]
    fn vault_id_random_produces_unique_ids() {
        let a = super::VaultId::random();
        let b = super::VaultId::random();
        assert_ne!(a, b);
    }
}
