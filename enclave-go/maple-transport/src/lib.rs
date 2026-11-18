//! Transport building blocks. Catalog activation remains separately gated.
pub mod relay;

use maple_sdk::{Pcr0Environment, Pcr0TrustPolicy};

pub const BACKEND: &str = "https://enclave.trymaple.ai";
pub const MODEL: &str = "deepseek-v4-1-flash-1017-uncensored";
// Independently reproduced release; identity: ../verified-release.json.
pub const PCR0: &str = "c0963d7af8aff8b65020ffddd8ed902a881838385073fb24d0d74b8b52eca7843a0288927a9eaa76e1193ac8cf767c95";
/// Maple's canonical signed production PCR history, as the SDK fetches it.
pub const SIGNED_HISTORY_URL: &str = maple_sdk::pcr::OFFICIAL_PRODUCTION_PCR_HISTORY_URL;

/// The serving trust policy: the one Maple's own SDK clients use.
///
/// After the SDK validates the Nitro attestation document, PCR0 must be one of
/// OpenSecret's embedded production measurements or appear in an entry of the
/// signed production history at [`SIGNED_HISTORY_URL`] whose P-384 signature
/// verifies against the key bundled in the SDK. Our independently reproduced
/// [`PCR0`] is added to the static set, so that release needs no history fetch.
///
/// A Maple front-enclave rotation is therefore accepted as soon as Maple signs
/// it, instead of failing closed until we re-pin. A measurement Maple has not
/// signed is still refused, and so is every request when the history cannot be
/// fetched and PCR0 is not in the static set.
pub fn serving_policy() -> maple_sdk::Result<Pcr0TrustPolicy> {
    Pcr0TrustPolicy::official_for(Pcr0Environment::Production).with_additional_pcr0s([PCR0])
}

#[cfg(test)]
mod tests {
    use super::{serving_policy, PCR0, SIGNED_HISTORY_URL};
    use std::collections::BTreeSet;

    const SDK_PCR: &str = include_str!("../.vendor-sdk/src/pcr.rs");

    /// Every 96-hex-digit run in TEXT: the PCR0s it carries.
    fn pcr0s_in(text: &str) -> BTreeSet<String> {
        text.split(|c: char| !c.is_ascii_hexdigit())
            .filter(|run| run.len() == 96)
            .map(str::to_owned)
            .collect()
    }

    /// The PCR0s inside one `const NAME: &[&str] = &[ ... ];` of the vendored SDK.
    fn sdk_list(name: &str) -> BTreeSet<String> {
        let start = SDK_PCR
            .find(&format!("const {name}: &[&str] = &["))
            .unwrap_or_else(|| panic!("vendored SDK has no {name}"));
        let end = start + SDK_PCR[start..].find("];").unwrap();
        pcr0s_in(&SDK_PCR[start..end])
    }

    /// The string literal assigned to `const NAME: &str =` in the vendored SDK.
    fn sdk_str(name: &str) -> &'static str {
        let start = SDK_PCR
            .find(&format!("const {name}: &str ="))
            .unwrap_or_else(|| panic!("vendored SDK has no {name}"));
        let rest = &SDK_PCR[start..];
        let open = rest.find('"').unwrap() + 1;
        let close = open + rest[open..].find('"').unwrap();
        &rest[open..close]
    }

    #[test]
    fn front_pin_matches_independently_verified_release() {
        let release: serde_json::Value =
            serde_json::from_str(include_str!("../verified-release.json")).unwrap();
        assert_eq!(Some(PCR0), release["pcr0"].as_str());
        assert_eq!(Some(super::BACKEND), release["backend"].as_str());
        assert_eq!(Some(super::MODEL), release["model"].as_str());
        assert_eq!(PCR0.len(), 96);
        assert!(PCR0.bytes().all(|byte| byte.is_ascii_hexdigit()));
        // In the static pin, superseded measurements are replaced, never kept as
        // extra allowances. Serving still accepts them while they remain in
        // Maple's signed history (see serving_policy).
        for retired in [
            "4d867ac23d7a42b46a458452fe59f2f2c831b0c553d768287c9ca01f2015b177272b9e807ad585b498ff8a5f3b4141c2",
            "0cb6ebb04723d420a6e1c6cde213792a3917f1cadfde1143caf4091f45aa7ed8c3e6915787887ca03ad936f07b70f063",
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

    #[test]
    fn serving_policy_is_the_official_production_policy_plus_our_pin() {
        let policy = format!("{:?}", serving_policy().unwrap());
        // The static set is exactly OpenSecret's embedded production PCR0s plus
        // our reproduced one: any other static entry would bypass Maple's
        // signature, and no development measurement belongs here.
        let production = sdk_list("OFFICIAL_PRODUCTION_PCR0S");
        let development = sdk_list("OFFICIAL_DEVELOPMENT_PCR0S");
        assert!(!production.is_empty() && !development.is_empty());
        let mut expected = production.clone();
        expected.insert(PCR0.to_owned());
        assert_eq!(pcr0s_in(&policy), expected);
        assert!(pcr0s_in(&policy).is_disjoint(&development));
        // Exactly one history location: the production file, over HTTPS, on
        // GitHub's raw host.
        assert_eq!(
            policy.matches("Url {").count(),
            1,
            "exactly one history location"
        );
        for part in [
            "scheme: \"https\"",
            "host: Some(Domain(\"raw.githubusercontent.com\"))",
            "port: None",
            "path: \"/MaplePrivacyLabs/Maple/master/services/opensecret/pcrProdHistory.json\"",
            "query: None",
        ] {
            assert!(policy.contains(part), "history URL lacks {part}: {policy}");
        }
    }

    #[test]
    fn signed_history_is_makers_canonical_file_verified_with_the_reviewed_key() {
        assert_eq!(
            SIGNED_HISTORY_URL,
            "https://raw.githubusercontent.com/MaplePrivacyLabs/Maple/master/services/opensecret/pcrProdHistory.json"
        );
        assert_eq!(
            sdk_str("OFFICIAL_PRODUCTION_PCR_HISTORY_URL"),
            SIGNED_HISTORY_URL
        );
        // The SDK verifies history entries with its bundled P-384 key. The value
        // of that constant must be the key our release review authenticated the
        // history with, and signature checking must read that constant. The SDK
        // archive is also pinned by SHA-256 in prepare-sdk.sh.
        let release: serde_json::Value =
            serde_json::from_str(include_str!("../verified-release.json")).unwrap();
        let reviewed_key = release["history_public_key_der"].as_str().unwrap();
        assert_eq!(sdk_str("PCR_HISTORY_VERIFICATION_KEY_B64"), reviewed_key);
        let verify = &SDK_PCR[SDK_PCR.find("fn has_valid_signature").unwrap()..];
        let verify = &verify[..verify.find("\n    }\n").unwrap()];
        assert!(verify.contains("BASE64.decode(PCR_HISTORY_VERIFICATION_KEY_B64)"));
        assert!(verify.contains("ECDSA_P384_SHA384_FIXED"));
        assert!(verify.contains(".verify(self.pcr0.as_bytes(), &signature_bytes)"));
        // And history admission requires that check for the matching entry.
        let admit = &SDK_PCR[SDK_PCR.find("async fn verify_pcr0").unwrap()..];
        let admit = &admit[..admit.find("\n    }\n").unwrap()];
        assert!(admit.contains("entry.pcr0 == pcr0_hex && entry.has_valid_signature()"));
    }
}
