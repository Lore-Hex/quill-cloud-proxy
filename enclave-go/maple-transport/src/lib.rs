//! Transport building blocks. Catalog activation remains separately gated.
pub mod relay;

pub const BACKEND: &str = "https://enclave.trymaple.ai";
pub const MODEL: &str = "deepseek-v4-1-flash-1017-uncensored";
// Independently reproduced source 13d75aa7; evidence: docs/providers/maple.md.
pub const PCR0: &str = "3a67fa1c4317d83e77d74123f4e658c4a1a7b15a7a1f6e1e872612390a6499a50118f2dddf05bd034b0318c4bcef53f4";

#[cfg(test)]
mod tests {
    use super::PCR0;

    #[test]
    fn front_pin_matches_independent_20261106_reproduction() {
        assert_eq!(PCR0, "3a67fa1c4317d83e77d74123f4e658c4a1a7b15a7a1f6e1e872612390a6499a50118f2dddf05bd034b0318c4bcef53f4");
        assert_eq!(PCR0.len(), 96);
        assert!(PCR0.bytes().all(|byte| byte.is_ascii_hexdigit()));
        // Superseded measurements are replaced, never kept as extra allowances.
        for retired in [
            "db70ca1d96a458ccea64cc995fb5c5f908b187e32293267e15e8a5677ac12a864c0b90abec6493f777060c95ece729da",
            "9d6ec6dbcdbb282aa80f48e39a497284f5b3d86a06b6a2ac401b14a43eb6632b3255d2fe82417c13109209f3b7b72bdb",
            "6eac0f156a3732f05a83de99cef6e429c8b67a43b4cea9af27b419bc3e979b4d6494e9625baff8a22327d60be235851a",
            "ada74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0",
        ] {
            assert_ne!(PCR0, retired);
        }
        assert!(maple_sdk::Pcr0TrustPolicy::from_static_allowlist([PCR0]).is_ok());
    }
}
