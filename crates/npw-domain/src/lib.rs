use npw_core::VaultId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainContext {
    pub vault_id: VaultId,
}

impl DomainContext {
    #[must_use]
    pub fn new(vault_id: VaultId) -> Self {
        Self { vault_id }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn creates_context_with_vault_id() {
        let id = npw_core::VaultId::random();
        let context = super::DomainContext::new(id);
        assert_eq!(context.vault_id, id);
    }
}
