//! Transport building blocks. Catalog activation remains separately gated.
pub mod relay;

pub const BACKEND: &str = "https://enclave.trymaple.ai";
pub const MODEL: &str = "deepseek-v4-1-flash-1017-uncensored";
// Independently reproduced source 55f02f0b; evidence: docs/providers/maple.md.
pub const PCR0: &str = "6eac0f156a3732f05a83de99cef6e429c8b67a43b4cea9af27b419bc3e979b4d6494e9625baff8a22327d60be235851a";

#[cfg(test)]
mod tests {
    use super::PCR0;

    #[test]
    fn front_pin_matches_independent_20261031_reproduction() {
        assert_eq!(PCR0, "6eac0f156a3732f05a83de99cef6e429c8b67a43b4cea9af27b419bc3e979b4d6494e9625baff8a22327d60be235851a");
        assert_eq!(PCR0.len(), 96);
        assert!(PCR0.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(PCR0, "ada74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0");
        assert!(maple_sdk::Pcr0TrustPolicy::from_static_allowlist([PCR0]).is_ok());
    }
}
