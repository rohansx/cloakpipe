//! Industry detection profiles — pre-tuned configurations for common use cases.

use crate::config::{CustomConfig, CustomPattern, DetectionConfig, NerBackend, NerConfig, OverrideConfig};
use serde::{Deserialize, Serialize};

/// Available industry profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndustryProfile {
    General,
    Legal,
    Healthcare,
    Fintech,
}

impl IndustryProfile {
    /// Parse a profile name from a string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "general" => Some(Self::General),
            "legal" | "law" => Some(Self::Legal),
            "healthcare" | "health" | "medical" => Some(Self::Healthcare),
            "fintech" | "finance" | "banking" => Some(Self::Fintech),
            _ => None,
        }
    }

    /// Get the display name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Legal => "legal",
            Self::Healthcare => "healthcare",
            Self::Fintech => "fintech",
        }
    }

    /// Generate a DetectionConfig tuned for this industry.
    pub fn detection_config(&self) -> DetectionConfig {
        match self {
            Self::General => DetectionConfig {
                secrets: true,
                financial: true,
                dates: true,
                emails: true,
                phone_numbers: true,
                ip_addresses: true,
                urls_internal: true,
                ner: NerConfig {
                    enabled: true,
                    backend: NerBackend::GlinerPii,
                    model: None,
                    confidence_threshold: 0.4,
                    entity_types: Vec::new(),
                    sidecar_url: "http://127.0.0.1:9111".into(),
                },
                custom: CustomConfig::default(),
                overrides: OverrideConfig::default(),
                resolver: Default::default(),
            },
            Self::Legal => DetectionConfig {
                secrets: true,
                financial: true,
                dates: true,
                emails: true,
                phone_numbers: true,
                ip_addresses: false,
                urls_internal: false,
                ner: NerConfig {
                    enabled: true,
                    backend: NerBackend::GlinerPii,
                    model: None,
                    confidence_threshold: 0.4,
                    entity_types: Vec::new(),
                    sidecar_url: "http://127.0.0.1:9111".into(),
                },
                custom: CustomConfig {
                    patterns: legal_patterns(),
                },
                overrides: OverrideConfig {
                    preserve: vec![
                        "Supreme Court".into(),
                        "Federal Court".into(),
                        "District Court".into(),
                        "Court of Appeals".into(),
                    ],
                    force: Vec::new(),
                },
                resolver: Default::default(),
            },
            Self::Healthcare => DetectionConfig {
                secrets: true,
                financial: true,
                dates: true,
                emails: true,
                phone_numbers: true,
                ip_addresses: false,
                urls_internal: false,
                ner: NerConfig {
                    enabled: true,
                    backend: NerBackend::GlinerPii,
                    model: None,
                    confidence_threshold: 0.4,
                    entity_types: Vec::new(),
                    sidecar_url: "http://127.0.0.1:9111".into(),
                },
                custom: CustomConfig {
                    patterns: healthcare_patterns(),
                },
                overrides: OverrideConfig {
                    preserve: vec![
                        "FDA".into(),
                        "CDC".into(),
                        "WHO".into(),
                        "NIH".into(),
                    ],
                    force: Vec::new(),
                },
                resolver: Default::default(),
            },
            Self::Fintech => DetectionConfig {
                secrets: true,
                financial: true,
                dates: true,
                emails: true,
                phone_numbers: false,
                ip_addresses: true,
                urls_internal: true,
                ner: NerConfig::default(),
                custom: CustomConfig {
                    patterns: fintech_patterns(),
                },
                overrides: OverrideConfig {
                    preserve: vec![
                        "NYSE".into(),
                        "NASDAQ".into(),
                        "SEC".into(),
                        "FINRA".into(),
                        "RBI".into(),
                        "SEBI".into(),
                    ],
                    force: Vec::new(),
                },
                resolver: Default::default(),
            },
        }
    }

    /// List all available profiles.
    pub fn all() -> &'static [IndustryProfile] {
        &[
            Self::General,
            Self::Legal,
            Self::Healthcare,
            Self::Fintech,
        ]
    }
}

/// Merge a profile's detection config with explicit user overrides.
/// User-specified values always win over profile defaults.
pub fn resolve_detection_config(
    profile: Option<&str>,
    user_config: &DetectionConfig,
    has_explicit_detection: bool,
) -> DetectionConfig {
    let profile = match profile {
        Some(name) => IndustryProfile::from_name(name),
        None => None,
    };

    match profile {
        Some(p) if !has_explicit_detection => p.detection_config(),
        Some(p) => {
            // Merge: start with profile defaults, apply user overrides
            let mut config = p.detection_config();
            // User's explicit category toggles override profile
            config.secrets = user_config.secrets;
            config.financial = user_config.financial;
            config.dates = user_config.dates;
            config.emails = user_config.emails;
            config.phone_numbers = user_config.phone_numbers;
            config.ip_addresses = user_config.ip_addresses;
            config.urls_internal = user_config.urls_internal;
            // Merge custom patterns (profile patterns + user patterns)
            config.custom.patterns.extend(user_config.custom.patterns.clone());
            // User overrides always win
            config.overrides.preserve.extend(user_config.overrides.preserve.clone());
            config.overrides.force.extend(user_config.overrides.force.clone());
            config
        }
        None => user_config.clone(),
    }
}

fn legal_patterns() -> Vec<CustomPattern> {
    vec![
        CustomPattern {
            name: "case_number".into(),
            regex: r"\d{1,2}:\d{2}-[a-z]{2}-\d{4,6}".into(),
            category: "CASE_NUMBER".into(),
        },
        CustomPattern {
            name: "docket_number".into(),
            regex: r"(?i)docket\s*(?:no\.?\s*)?#?\s*\d[\d-]+".into(),
            category: "DOCKET".into(),
        },
        CustomPattern {
            name: "bar_number".into(),
            regex: r"(?i)bar\s*(?:no\.?\s*)?#?\s*\d{4,8}".into(),
            category: "BAR_NUMBER".into(),
        },
        CustomPattern {
            name: "ssn".into(),
            regex: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            category: "SSN".into(),
        },
    ]
}

fn healthcare_patterns() -> Vec<CustomPattern> {
    vec![
        CustomPattern {
            name: "mrn".into(),
            regex: r"(?i)(?:MRN|medical\s*record)\s*(?:no\.?\s*)?#?\s*\d{6,12}".into(),
            category: "MRN".into(),
        },
        CustomPattern {
            name: "npi".into(),
            regex: r"(?i)NPI\s*(?:no\.?\s*)?#?\s*\d{10}".into(),
            category: "NPI".into(),
        },
        CustomPattern {
            name: "dea_number".into(),
            regex: r"(?i)DEA\s*(?:no\.?\s*)?#?\s*[A-Z]{2}\d{7}".into(),
            category: "DEA".into(),
        },
        CustomPattern {
            name: "icd_code".into(),
            regex: r"\b[A-Z]\d{2}\.\d{1,2}\b".into(),
            category: "ICD_CODE".into(),
        },
    ]
}

fn fintech_patterns() -> Vec<CustomPattern> {
    vec![
        CustomPattern {
            name: "swift_bic".into(),
            regex: r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b".into(),
            category: "SWIFT_CODE".into(),
        },
        CustomPattern {
            name: "isin".into(),
            regex: r"\b[A-Z]{2}[A-Z0-9]{9}\d\b".into(),
            category: "ISIN".into(),
        },
        CustomPattern {
            name: "iban".into(),
            regex: r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]){0,16}\b".into(),
            category: "IBAN".into(),
        },
        CustomPattern {
            name: "routing_number".into(),
            regex: r"(?i)(?:routing|ABA)\s*(?:no\.?\s*)?#?\s*\d{9}\b".into(),
            category: "ROUTING_NUMBER".into(),
        },
    ]
}

impl std::fmt::Display for IndustryProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general_profile_defaults() {
        let config = IndustryProfile::General.detection_config();
        assert!(config.secrets);
        assert!(config.financial);
        assert!(config.emails);
        assert!(config.phone_numbers);
        assert!(config.ner.enabled);
        assert!(matches!(config.ner.backend, NerBackend::GlinerPii));
        assert!(config.custom.patterns.is_empty());
    }

    #[test]
    fn test_legal_profile() {
        let config = IndustryProfile::Legal.detection_config();
        assert!(config.financial);
        assert!(config.phone_numbers);
        assert!(config.ner.enabled);
        assert!(matches!(config.ner.backend, NerBackend::GlinerPii));
        assert!(!config.custom.patterns.is_empty());
        assert!(config.custom.patterns.iter().any(|p| p.name == "case_number"));
        assert!(config.overrides.preserve.contains(&"Supreme Court".to_string()));
    }

    #[test]
    fn test_healthcare_profile() {
        let config = IndustryProfile::Healthcare.detection_config();
        assert!(config.financial);
        assert!(config.ner.enabled);
        assert!(matches!(config.ner.backend, NerBackend::GlinerPii));
        assert!(config.custom.patterns.iter().any(|p| p.name == "mrn"));
        assert!(config.custom.patterns.iter().any(|p| p.name == "npi"));
        assert!(config.overrides.preserve.contains(&"FDA".to_string()));
    }

    #[test]
    fn test_fintech_profile() {
        let config = IndustryProfile::Fintech.detection_config();
        assert!(config.financial);
        assert!(config.ip_addresses);
        assert!(config.urls_internal);
        assert!(config.custom.patterns.iter().any(|p| p.name == "swift_bic"));
        assert!(config.overrides.preserve.contains(&"NYSE".to_string()));
    }

    #[test]
    fn test_profile_from_name() {
        assert_eq!(IndustryProfile::from_name("legal"), Some(IndustryProfile::Legal));
        assert_eq!(IndustryProfile::from_name("HEALTHCARE"), Some(IndustryProfile::Healthcare));
        assert_eq!(IndustryProfile::from_name("finance"), Some(IndustryProfile::Fintech));
        assert_eq!(IndustryProfile::from_name("unknown"), None);
    }

    #[test]
    fn test_resolve_no_profile() {
        let user_config = IndustryProfile::General.detection_config();
        let result = resolve_detection_config(None, &user_config, false);
        assert_eq!(result.secrets, user_config.secrets);
        assert_eq!(result.financial, user_config.financial);
    }
}
