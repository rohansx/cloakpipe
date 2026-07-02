//! CloakPipe Audit — structured JSONL audit logging.
//!
//! Every pseudonymization/rehydration event is logged for compliance,
//! debugging, and monitoring. Logs contain metadata only — never raw
//! sensitive values.

pub mod sqlite;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use uuid::Uuid;

/// Audit logger that appends JSONL entries to a log file.
pub struct AuditLogger {
    log_dir: String,
    log_entities: bool,
}

/// A single audit log entry.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub event: AuditEvent,
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities_detected: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities_replaced: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_rehydrated: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Pseudonymize,
    Rehydrate,
    VaultSave,
    VaultLoad,
    ProxyRequest,
    Error,
}

impl AuditLogger {
    pub fn new(log_dir: &str, log_entities: bool) -> Result<Self> {
        fs::create_dir_all(log_dir).context("Failed to create audit log directory")?;
        Ok(Self {
            log_dir: log_dir.to_string(),
            log_entities,
        })
    }

    /// Log a pseudonymization event.
    pub fn log_pseudonymize(
        &self,
        request_id: &str,
        entities_detected: usize,
        entities_replaced: usize,
        categories: Vec<String>,
    ) -> Result<()> {
        let entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::Pseudonymize,
            request_id: Some(request_id.to_string()),
            entities_detected: Some(entities_detected),
            entities_replaced: Some(entities_replaced),
            tokens_rehydrated: None,
            categories: if self.log_entities {
                Some(categories)
            } else {
                None
            },
            error: None,
        };
        self.append(entry)
    }

    /// Log a rehydration event.
    pub fn log_rehydrate(
        &self,
        request_id: &str,
        tokens_rehydrated: usize,
    ) -> Result<()> {
        let entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::Rehydrate,
            request_id: Some(request_id.to_string()),
            entities_detected: None,
            entities_replaced: None,
            tokens_rehydrated: Some(tokens_rehydrated),
            categories: None,
            error: None,
        };
        self.append(entry)
    }

    /// Log an error event.
    pub fn log_error(&self, request_id: &str, error: &str) -> Result<()> {
        let entry = AuditEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: AuditEvent::Error,
            request_id: Some(request_id.to_string()),
            entities_detected: None,
            entities_replaced: None,
            tokens_rehydrated: None,
            categories: None,
            error: Some(error.to_string()),
        };
        self.append(entry)
    }

    fn append(&self, entry: AuditEntry) -> Result<()> {
        let date = Utc::now().format("%Y-%m-%d");
        let path = format!("{}/audit-{}.jsonl", self.log_dir, date);
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("Failed to open audit log: {path}"))?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Get the log directory path.
    pub fn log_dir(&self) -> &str {
        &self.log_dir
    }
}
