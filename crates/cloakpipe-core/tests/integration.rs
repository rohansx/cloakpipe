//! Integration tests for the CloakPipe core pipeline.

use cloakpipe_core::{
    config::{CustomConfig, CustomPattern, DetectionConfig, NerConfig, OverrideConfig},
    detector::Detector,
    replacer::Replacer,
    rehydrator::Rehydrator,
    vault::Vault,
    EntityCategory,
};

fn test_detection_config() -> DetectionConfig {
    DetectionConfig {
        secrets: true,
        financial: true,
        dates: true,
        emails: true,
        phone_numbers: false,
        ip_addresses: true,
        urls_internal: true,
        ner: NerConfig::default(),
        custom: CustomConfig::default(),
        overrides: OverrideConfig::default(),
        resolver: Default::default(),
    }
}

#[test]
fn test_detect_email() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Contact alice@example.com for details").unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].original, "alice@example.com");
    assert_eq!(entities[0].category, EntityCategory::Email);
}

#[test]
fn test_detect_aws_key() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Key: AKIAIOSFODNN7EXAMPLE").unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::Secret));
}

#[test]
fn test_detect_ip_address() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Server at 192.168.1.100 is down").unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::IpAddress));
}

#[test]
fn test_detect_currency_amount() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Revenue was $1.2M this quarter").unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::Amount));
}

#[test]
fn test_detect_percentage() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Growth rate: 15.3% year-over-year").unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::Percentage));
}

#[test]
fn test_detect_fiscal_date() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Results for Q3 2025 are out").unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::Date));
}

#[test]
fn test_detect_internal_url() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let entities = detector.detect("Check https://internal.corp.com/api/status").unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::Url));
}

#[test]
fn test_detect_jwt() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    let entities = detector.detect(&format!("Token: {jwt}")).unwrap();
    assert!(entities.iter().any(|e| e.category == EntityCategory::Secret));
}

#[test]
fn test_custom_pattern() {
    let config = DetectionConfig {
        secrets: false,
        financial: false,
        dates: false,
        emails: false,
        phone_numbers: false,
        ip_addresses: false,
        urls_internal: false,
        ner: NerConfig::default(),
        custom: CustomConfig {
            patterns: vec![CustomPattern {
                name: "project_codename".into(),
                regex: r"Project\s+(Alpha|Beta|Gamma)".into(),
                category: "PROJECT".into(),
            }],
        },
        overrides: OverrideConfig::default(),
        resolver: Default::default(),
    };
    let detector = Detector::from_config(&config).unwrap();
    let entities = detector.detect("Working on Project Alpha").unwrap();
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].original, "Project Alpha");
}

#[test]
fn test_preserve_list() {
    let config = DetectionConfig {
        secrets: false,
        financial: false,
        dates: false,
        emails: true,
        phone_numbers: false,
        ip_addresses: false,
        urls_internal: false,
        ner: NerConfig::default(),
        custom: CustomConfig::default(),
        overrides: OverrideConfig {
            preserve: vec!["public@example.com".into()],
            force: vec![],
        },
        resolver: Default::default(),
    };
    let detector = Detector::from_config(&config).unwrap();
    let entities = detector
        .detect("Contact public@example.com or private@secret.com")
        .unwrap();
    // public@example.com should be preserved (not detected)
    assert!(entities.iter().all(|e| e.original != "public@example.com"));
    assert!(entities.iter().any(|e| e.original == "private@secret.com"));
}

// --- Pseudonymize + Rehydrate roundtrip ---

#[test]
fn test_pseudonymize_roundtrip() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let mut vault = Vault::ephemeral();

    let input = "Contact alice@example.com about the $1.2M deal in Q3 2025";
    let entities = detector.detect(input).unwrap();
    let pseudo = Replacer::pseudonymize(input, &entities, &mut vault).unwrap();

    // Pseudonymized text should not contain originals
    assert!(!pseudo.text.contains("alice@example.com"));
    assert!(!pseudo.text.contains("$1.2M"));

    // Rehydrate should recover original
    let rehydrated = Rehydrator::rehydrate(&pseudo.text, &vault).unwrap();
    assert_eq!(rehydrated.text, input);
}

#[test]
fn test_pseudonymize_consistency() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let mut vault = Vault::ephemeral();

    let input1 = "alice@example.com sent a message";
    let input2 = "Reply to alice@example.com";

    let e1 = detector.detect(input1).unwrap();
    let e2 = detector.detect(input2).unwrap();

    let p1 = Replacer::pseudonymize(input1, &e1, &mut vault).unwrap();
    let p2 = Replacer::pseudonymize(input2, &e2, &mut vault).unwrap();

    // Same entity should get the same token
    assert!(p1.text.contains("EMAIL_1"));
    assert!(p2.text.contains("EMAIL_1"));
}

#[test]
fn test_no_entities_passthrough() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let mut vault = Vault::ephemeral();

    let input = "This is a normal message with no sensitive data.";
    let entities = detector.detect(input).unwrap();
    assert!(entities.is_empty());

    let pseudo = Replacer::pseudonymize(input, &entities, &mut vault).unwrap();
    assert_eq!(pseudo.text, input);
}

#[test]
fn test_multiple_entities_same_category() {
    let detector = Detector::from_config(&test_detection_config()).unwrap();
    let mut vault = Vault::ephemeral();

    let input = "Send to alice@a.com and bob@b.com";
    let entities = detector.detect(input).unwrap();
    let pseudo = Replacer::pseudonymize(input, &entities, &mut vault).unwrap();

    assert!(pseudo.text.contains("EMAIL_1"));
    assert!(pseudo.text.contains("EMAIL_2"));
    assert!(!pseudo.text.contains("alice@a.com"));
    assert!(!pseudo.text.contains("bob@b.com"));
}

// --- Streaming rehydration ---

#[test]
fn test_streaming_rehydration_complete_token() {
    let mut vault = Vault::ephemeral();
    vault.get_or_create("Acme Corp", &EntityCategory::Organization);

    let mut buffer = String::new();
    let (output, matched) = Rehydrator::rehydrate_chunk("The company ORG_1 reported", &mut buffer, &vault).unwrap();
    assert!(matched);
    assert!(output.contains("Acme Corp"));
}
