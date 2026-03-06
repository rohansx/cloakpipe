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
            // Generic API keys / tokens
            rules.push(PatternRule {
                regex: Regex::new(r"(?i)(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})")?,
                category: EntityCategory::Secret,
                _name: "api_token".into(),
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

        if config.phone_numbers {
            rules.push(PatternRule {
                regex: Regex::new(r"\+?[1-9]\d{0,2}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}")?,
                category: EntityCategory::PhoneNumber,
                _name: "phone".into(),
            });
        }

        if config.ip_addresses {
            rules.push(PatternRule {
                regex: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")?,
                category: EntityCategory::IpAddress,
                _name: "ipv4".into(),
            });
        }

        if config.urls_internal {
            rules.push(PatternRule {
                regex: Regex::new(r"https?://(?:internal|staging|dev|admin)\.[a-zA-Z0-9.-]+(?:/[^\s]*)?")?,
                category: EntityCategory::Url,
                _name: "internal_url".into(),
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
