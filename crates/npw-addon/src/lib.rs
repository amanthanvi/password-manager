use napi_derive::napi;

#[napi]
pub fn core_banner() -> String {
    npw_core::bootstrap_banner()
}

#[cfg(test)]
mod tests {
    #[test]
    fn exposes_core_banner() {
        assert!(super::core_banner().contains("npw"));
    }
}
