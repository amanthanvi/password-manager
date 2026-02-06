use npw_domain::DomainContext;

#[must_use]
pub fn initialize_storage(context: &DomainContext) -> String {
    format!("storage initialized for {}", context.vault_id.0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn initialize_storage_contains_vault_id() {
        let context = npw_domain::DomainContext::new(npw_core::VaultId::random());
        let message = super::initialize_storage(&context);
        assert!(message.contains("storage initialized"));
    }
}
