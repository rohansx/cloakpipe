//! Layer 1: Regex-based pattern detection for secrets, emails, IPs, etc.

use crate::{DetectedEntity, EntityCategory, DetectionSource, config::DetectionConfig};
use anyhow::Result;
use regex::Regex;

pub struct PatternDetector {
    rules: Vec<PatternRule>,
}

struct PatternRule {
    regex: Regex,
    category: EntityCategory,
    _name: String,
}

impl PatternDetector {
    pub fn new(config: &DetectionConfig) -> Result<Self> {
        let mut rules = Vec::new();

        if config.secrets {
            // AWS keys
            rules.push(PatternRule {
                regex: Regex::new(r"(?i)(AKIA[0-9A-Z]{16})")?,
                category: EntityCategory::Secret,
                _name: "aws_access_key".into(),
            });
            // OpenAI / generic API keys (sk-proj-*, sk-live-*, sk-<32+ alphanum>)
            rules.push(PatternRule {
                regex: Regex::new(r"sk-(?:proj|live|test|prod)-[a-zA-Z0-9]{10,}")?,
                category: EntityCategory::Secret,
                _name: "api_key_prefixed".into(),
            });
            rules.push(PatternRule {
                regex: Regex::new(r"sk-[a-zA-Z0-9]{32,}")?,
                category: EntityCategory::Secret,
                _name: "api_key_generic".into(),
            });
            // GitHub tokens
            rules.push(PatternRule {
                regex: Regex::new(r"(?i)(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})")?,
                category: EntityCategory::Secret,
                _name: "github_token".into(),
            });
            // Connection strings
            rules.push(PatternRule {
                regex: Regex::new(r"(?i)(postgres(?:ql)?://[^\s]+|mysql://[^\s]+|mongodb(?:\+srv)?://[^\s]+)")?,
                category: EntityCategory::Secret,
                _name: "connection_string".into(),
            });
            // JWT tokens
            rules.push(PatternRule {
                regex: Regex::new(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")?,
                category: EntityCategory::Secret,
                _name: "jwt_token".into(),
            });
        }

        if config.emails {
            rules.push(PatternRule {
                regex: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")?,
                category: EntityCategory::Email,
                _name: "email".into(),
            });
        }

        // IP addresses MUST come before phone numbers so they win dedup
        if config.ip_addresses {
            rules.push(PatternRule {
                regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")?,
                category: EntityCategory::IpAddress,
                _name: "ipv4".into(),
            });
        }

        // Identity documents MUST come before phone (Aadhaar overlaps phone pattern)
        rules.push(PatternRule {
            regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")?,
            category: EntityCategory::Custom("SSN".into()),
            _name: "ssn".into(),
        });
        rules.push(PatternRule {
            regex: Regex::new(r"\b\d{4}\s\d{4}\s\d{4}\b")?,
            category: EntityCategory::Custom("AADHAAR".into()),
            _name: "aadhaar".into(),
        });
        rules.push(PatternRule {
            regex: Regex::new(r"\b[A-Z]{5}\d{4}[A-Z]\b")?,
            category: EntityCategory::Custom("PAN".into()),
            _name: "pan".into(),
        });

        // Employee / member / policy IDs with common prefixes
        // Matches: EMP-2019-4471, INS-2026-78432, WF-2019-445821, FM-2026-11847, etc.
        rules.push(PatternRule {
            regex: Regex::new(r"\b(?i:EMP|INS|WF|FM|ANT|SH|MRN|TN|CP|HR|POL|CLM|REF|ACCT|MBR|HO)[-–]\d[\w-]{3,}\b")?,
            category: EntityCategory::Custom("ID_NUMBER".into()),
            _name: "prefixed_id".into(),
        });

        // License / certificate numbers with prefix (CRC-1330841, NMLS #1847293, etc.)
        rules.push(PatternRule {
            regex: Regex::new(r"\b(?:CRC|NMLS|NPI|DEA|LPC|BAR|LIC)[-–#\s]*\d{4,}\b")?,
            category: EntityCategory::Custom("LICENSE_NUMBER".into()),
            _name: "license_number".into(),
        });

        // State/professional license with hash prefix (#TX-28491, #GA-12847)
        rules.push(PatternRule {
            regex: Regex::new(r"#[A-Z]{2}-\d{4,}")?,
            category: EntityCategory::Custom("LICENSE_NUMBER".into()),
            _name: "state_license".into(),
        });

        if config.phone_numbers {
            // Tighter phone regex: requires country code or area code pattern,
            // minimum 7 digits total, won't match bare 4-digit numbers or IPs
            rules.push(PatternRule {
                regex: Regex::new(r"(?:\+[1-9]\d{0,2}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4,}")?,
                category: EntityCategory::PhoneNumber,
                _name: "phone".into(),
            });
        }

        // URLs: both internal and general
        if config.urls_internal {
            rules.push(PatternRule {
                regex: Regex::new(r"https?://[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?(?::\d{1,5})?(?:/[^\s)]*)?")?,
                category: EntityCategory::Url,
                _name: "url".into(),
            });
        }

        Ok(Self { rules })
    }

    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        let mut entities = Vec::new();
        for rule in &self.rules {
            for mat in rule.regex.find_iter(text) {
                entities.push(DetectedEntity {
                    original: mat.as_str().to_string(),
                    start: mat.start(),
                    end: mat.end(),
                    category: rule.category.clone(),
                    confidence: 1.0,
                    source: DetectionSource::Pattern,
                });
            }
        }
        Ok(entities)
    }
}
