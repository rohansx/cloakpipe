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
#[cfg(feature = "ner")]
pub mod gliner;
#[cfg(feature = "gliner-pii")]
pub mod gliner_pii;
#[cfg(feature = "ner")]
pub mod distilbert_pii;

#[cfg(feature = "ner")]
use crate::config::NerBackend;
use crate::{DetectedEntity, config::DetectionConfig};
use anyhow::Result;

/// The combined detection engine that runs all layers.
pub struct Detector {
    pattern_detector: patterns::PatternDetector,
    financial_detector: financial::FinancialDetector,
    custom_detector: custom::CustomDetector,
    #[cfg(feature = "ner")]
    ner_detector: Option<ner::NerDetector>,
    #[cfg(feature = "ner")]
    gliner_detector: Option<gliner::GlinerDetector>,
    #[cfg(feature = "gliner-pii")]
    gliner_pii_detector: Option<gliner_pii::GlinerPiiDetector>,
    #[cfg(feature = "ner")]
    distilbert_pii_detector: Option<distilbert_pii::DistilBertPiiDetector>,
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
            ner_detector: if config.ner.enabled && matches!(config.ner.backend, NerBackend::Bert) {
                Some(ner::NerDetector::new(&config.ner)?)
            } else {
                None
            },
            #[cfg(feature = "ner")]
            gliner_detector: if config.ner.enabled && matches!(config.ner.backend, NerBackend::Gliner) {
                Some(gliner::GlinerDetector::new(&config.ner)?)
            } else {
                None
            },
            #[cfg(feature = "ner")]
            distilbert_pii_detector: if config.ner.enabled && matches!(config.ner.backend, NerBackend::DistilBertPii) {
                Some(distilbert_pii::DistilBertPiiDetector::new(&config.ner)?)
            } else {
                None
            },
            #[cfg(feature = "gliner-pii")]
            gliner_pii_detector: if config.ner.enabled && matches!(config.ner.backend, crate::config::NerBackend::GlinerPii) {
                let pii_config = gliner_pii::GlinerPiiConfig {
                    url: config.ner.sidecar_url.clone(),
                    threshold: config.ner.confidence_threshold,
                    timeout_secs: 10,
                };
                let detector = gliner_pii::GlinerPiiDetector::new(pii_config);
                if detector.health_check() {
                    tracing::info!("GLiNER-PII sidecar connected at {}", config.ner.sidecar_url);
                    Some(detector)
                } else {
                    tracing::warn!(
                        "GLiNER-PII sidecar not reachable at {}. NER layer disabled. \
                         Start with: python tools/gliner-pii-server.py",
                        config.ner.sidecar_url
                    );
                    None
                }
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

        // Layer 3: NER (optional — BERT or GLiNER backend)
        #[cfg(feature = "ner")]
        if let Some(ref ner) = self.ner_detector {
            entities.extend(ner.detect(text)?);
        }
        #[cfg(feature = "ner")]
        if let Some(ref gliner) = self.gliner_detector {
            entities.extend(gliner.detect(text)?);
        }

        // Layer 3b: DistilBERT-PII (names, addresses, accounts — runs on any CPU)
        #[cfg(feature = "ner")]
        if let Some(ref distilbert) = self.distilbert_pii_detector {
            entities.extend(distilbert.detect(text)?);
        }

        // Layer 3c: GLiNER-PII sidecar (names, addresses, orgs)
        #[cfg(feature = "gliner-pii")]
        if let Some(ref pii) = self.gliner_pii_detector {
            entities.extend(pii.detect(text)?);
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

    /// Remove overlapping entity spans.
    /// Prefers: higher confidence > longer span > earlier detection layer.
    fn deduplicate_spans(entities: Vec<DetectedEntity>) -> Vec<DetectedEntity> {
        let mut result: Vec<DetectedEntity> = Vec::new();
        for entity in entities {
            if let Some(last) = result.last() {
                if entity.start < last.end {
                    // Overlap: prefer higher confidence, then longer span
                    let replace = entity.confidence > last.confidence
                        || (entity.confidence == last.confidence
                            && (entity.end - entity.start) > (last.end - last.start));
                    if replace {
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
