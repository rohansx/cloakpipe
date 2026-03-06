//! Multi-layer entity detection engine.
//!
//! Layers (applied in order, results merged and deduplicated):
//! 1. Pattern matching (regex) — secrets, emails, IPs, URLs
//! 2. Financial intelligence — amounts, percentages, fiscal dates
//! 3. Named Entity Recognition (ONNX) — persons, organizations, locations
//! 4. Custom rules (TOML config) — project codenames, client tiers, etc.

pub mod patterns;
pub mod financial;
pub mod custom;

#[cfg(feature = "ner")]
pub mod ner;

use crate::{DetectedEntity, config::DetectionConfig};
use anyhow::Result;

/// The combined detection engine that runs all layers.
pub struct Detector {
    pattern_detector: patterns::PatternDetector,
    financial_detector: financial::FinancialDetector,
    custom_detector: custom::CustomDetector,
    #[cfg(feature = "ner")]
    ner_detector: Option<ner::NerDetector>,
    /// Entities to never anonymize (e.g., public companies).
    preserve_list: Vec<String>,
    /// Entities to always anonymize regardless of detection.
    force_list: Vec<String>,
}

impl Detector {
    /// Create a new detector from configuration.
    pub fn from_config(config: &DetectionConfig) -> Result<Self> {
        Ok(Self {
            pattern_detector: patterns::PatternDetector::new(config)?,
            financial_detector: financial::FinancialDetector::new(config)?,
            custom_detector: custom::CustomDetector::new(config)?,
            #[cfg(feature = "ner")]
            ner_detector: if config.ner.enabled {
                Some(ner::NerDetector::new(&config.ner)?)
            } else {
                None
            },
            preserve_list: config.overrides.preserve.clone(),
            force_list: config.overrides.force.clone(),
        })
    }

    /// Run all detection layers on the input text.
    /// Returns a list of detected entities, sorted by position, deduplicated.
    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        let mut entities = Vec::new();

        // Layer 1: Pattern matching
        entities.extend(self.pattern_detector.detect(text)?);

        // Layer 2: Financial intelligence
        entities.extend(self.financial_detector.detect(text)?);

        // Layer 3: NER (optional)
        #[cfg(feature = "ner")]
        if let Some(ref ner) = self.ner_detector {
            entities.extend(ner.detect(text)?);
        }

        // Layer 4: Custom TOML rules
        entities.extend(self.custom_detector.detect(text)?);

        // Filter: remove preserved entities
        entities.retain(|e| !self.preserve_list.contains(&e.original));

        // Add: force-anonymize entities
        for forced in &self.force_list {
            if let Some(start) = text.find(forced.as_str()) {
                entities.push(DetectedEntity {
                    original: forced.clone(),
                    start,
                    end: start + forced.len(),
                    category: crate::EntityCategory::Custom("FORCED".into()),
                    confidence: 1.0,
                    source: crate::DetectionSource::Custom,
                });
            }
        }

        // Sort by position and deduplicate overlapping spans
        entities.sort_by_key(|e| e.start);
        entities = Self::deduplicate_spans(entities);

        Ok(entities)
    }

    /// Remove overlapping entity spans, keeping highest confidence.
    fn deduplicate_spans(entities: Vec<DetectedEntity>) -> Vec<DetectedEntity> {
        let mut result: Vec<DetectedEntity> = Vec::new();
        for entity in entities {
            if let Some(last) = result.last() {
                if entity.start < last.end {
                    // Overlap: keep the one with higher confidence
                    if entity.confidence > last.confidence {
                        result.pop();
                        result.push(entity);
                    }
                    continue;
                }
            }
            result.push(entity);
        }
        result
    }
}
