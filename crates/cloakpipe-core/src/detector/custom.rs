//! Layer 4: User-defined TOML pattern rules.

use crate::{DetectedEntity, EntityCategory, DetectionSource, config::DetectionConfig};
use anyhow::Result;
use regex::Regex;

pub struct CustomDetector {
    rules: Vec<CustomRule>,
}

struct CustomRule {
    _name: String,
    regex: Regex,
    category: EntityCategory,
}

impl CustomDetector {
    pub fn new(config: &DetectionConfig) -> Result<Self> {
        let mut rules = Vec::new();
        for pattern in &config.custom.patterns {
            rules.push(CustomRule {
                _name: pattern.name.clone(),
                regex: Regex::new(&pattern.regex)?,
                category: EntityCategory::Custom(pattern.category.clone()),
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
                    source: DetectionSource::Custom,
                });
            }
        }
        Ok(entities)
    }
}
