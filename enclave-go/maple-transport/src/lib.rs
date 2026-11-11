//! Transport building blocks. Catalog activation remains separately gated.
pub mod relay;

pub const BACKEND: &str = "https://enclave.trymaple.ai";
pub const MODEL: &str = "deepseek-v4-1-flash-1017-uncensored";
// Independently reproduced release; identity: ../verified-release.json.
pub const PCR0: &str = "0cb6ebb04723d420a6e1c6cde213792a3917f1cadfde1143caf4091f45aa7ed8c3e6915787887ca03ad936f07b70f063";

#[cfg(test)]
mod tests {
    use super::PCR0;

    #[test]
    fn front_pin_matches_independently_verified_release() {
        let release: serde_json::Value =
            serde_json::from_str(include_str!("../verified-release.json")).unwrap();
        assert_eq!(Some(PCR0), release["pcr0"].as_str());
        assert_eq!(Some(super::BACKEND), release["backend"].as_str());
        assert_eq!(Some(super::MODEL), release["model"].as_str());
        assert_eq!(PCR0.len(), 96);
        assert!(PCR0.bytes().all(|byte| byte.is_ascii_hexdigit()));
        // Superseded measurements are replaced, never kept as extra allowances.
        for retired in [
            "769e8dd045dad30df5bb13e4fe8ced547c64f906316fc6e8519a0e858cd8cdb2690bdcf66c9dad3ed5e5d0a37768189a",
            "3a67fa1c4317d83e77d74123f4e658c4a1a7b15a7a1f6e1e872612390a6499a50118f2dddf05bd034b0318c4bcef53f4",
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
