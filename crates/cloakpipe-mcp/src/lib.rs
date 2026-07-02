//! CloakPipe MCP Server — expose privacy tools to AI agents.
//!
//! Tools: pseudonymize, rehydrate, detect, vault_stats, configure.
//! Transport: stdio (for Claude Code, Cursor, etc.)

use cloakpipe_core::{
    config::{CloakPipeConfig, DetectionConfig},
    detector::Detector,
    profiles::IndustryProfile,
    rehydrator::Rehydrator,
    replacer::Replacer,
    session::SessionManager,
    vault::Vault,
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// MCP server state holding detector, vault, and config.
#[derive(Clone)]
pub struct CloakPipeServer {
    detector: Arc<RwLock<Detector>>,
    vault: Arc<Mutex<Vault>>,
    config: Arc<RwLock<DetectionConfig>>,
    active_profile: Arc<RwLock<Option<String>>>,
    sessions: Arc<SessionManager>,
    // Held for the rmcp tool-dispatch framework; not read directly in this crate.
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

// -- Tool parameter types --

#[derive(Deserialize, schemars::JsonSchema)]
pub struct PseudonymizeParams {
    /// Text containing sensitive data to pseudonymize.
    pub text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct RehydrateParams {
    /// Text with pseudo-tokens (e.g. EMAIL_1, AMOUNT_2) to restore.
    pub text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct DetectParams {
    /// Text to scan for sensitive entities without replacing them.
    pub text: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct ConfigureParams {
    /// Industry profile name: general, legal, healthcare, fintech.
    pub profile: Option<String>,
    /// Detection categories to enable (e.g. ["financial", "phone_numbers"]).
    pub enable: Option<Vec<String>>,
    /// Detection categories to disable.
    pub disable: Option<Vec<String>>,
}

// -- Tool response types --

#[derive(Serialize, Deserialize)]
struct PseudonymizeResult {
    text: String,
    entities_detected: usize,
    categories: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RehydrateResult {
    text: String,
    tokens_rehydrated: usize,
}

#[derive(Serialize, Deserialize)]
struct DetectResult {
    entities: Vec<EntityInfo>,
}

#[derive(Serialize, Deserialize)]
struct EntityInfo {
    original: String,
    category: String,
    confidence: f64,
    source: String,
}

#[derive(Serialize, Deserialize)]
struct VaultStatsResult {
    total_mappings: usize,
    categories: std::collections::HashMap<String, u32>,
}

#[derive(Deserialize, schemars::JsonSchema)]
pub struct SessionContextParams {
    /// Session ID to inspect, or "list" to list all active sessions.
    pub session_id: String,
}

#[derive(Serialize, Deserialize)]
struct ConfigureResult {
    active_profile: Option<String>,
    secrets: bool,
    financial: bool,
    dates: bool,
    emails: bool,
    phone_numbers: bool,
    ip_addresses: bool,
}

#[tool_router]
impl CloakPipeServer {
    /// Pseudonymize text: detect and replace sensitive entities (emails, amounts, secrets, dates, etc.) with consistent tokens. Same entity always maps to same token.
    #[tool(description = "Pseudonymize text: detect and replace sensitive entities with consistent tokens. Same entity always maps to same token. Use this before sending data to external APIs.")]
    async fn pseudonymize(
        &self,
        Parameters(params): Parameters<PseudonymizeParams>,
    ) -> String {
        let detector = self.detector.read().await;
        let entities = match detector.detect(&params.text) {
            Ok(e) => e,
            Err(e) => return format!("Error: Detection failed: {e}"),
        };

        let mut vault = self.vault.lock().await;
        let result = match Replacer::pseudonymize(&params.text, &entities, &mut vault) {
            Ok(r) => r,
            Err(e) => return format!("Error: Pseudonymize failed: {e}"),
        };

        let categories: Vec<String> = entities
            .iter()
            .map(|e| format!("{:?}", e.category))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let response = PseudonymizeResult {
            text: result.text,
            entities_detected: entities.len(),
            categories,
        };

        serde_json::to_string_pretty(&response).unwrap_or_else(|e| format!("Error: {e}"))
    }

    /// Rehydrate text: replace pseudo-tokens back with original values.
    #[tool(description = "Rehydrate text: replace pseudo-tokens (EMAIL_1, AMOUNT_2, etc.) back with original values. Use this to restore real data in LLM responses.")]
    async fn rehydrate(
        &self,
        Parameters(params): Parameters<RehydrateParams>,
    ) -> String {
        let vault = self.vault.lock().await;
        let result = match Rehydrator::rehydrate(&params.text, &vault) {
            Ok(r) => r,
            Err(e) => return format!("Error: Rehydrate failed: {e}"),
        };

        let response = RehydrateResult {
            text: result.text,
            tokens_rehydrated: result.rehydrated_count,
        };

        serde_json::to_string_pretty(&response).unwrap_or_else(|e| format!("Error: {e}"))
    }

    /// Detect sensitive entities in text without replacing them (dry run).
    #[tool(description = "Detect sensitive entities in text without replacing them (dry run). Returns category, confidence, source for each match.")]
    async fn detect(
        &self,
        Parameters(params): Parameters<DetectParams>,
    ) -> String {
        let detector = self.detector.read().await;
        let entities = match detector.detect(&params.text) {
            Ok(e) => e,
            Err(e) => return format!("Error: Detection failed: {e}"),
        };

        let response = DetectResult {
            entities: entities
                .iter()
                .map(|e| EntityInfo {
                    original: e.original.clone(),
                    category: format!("{:?}", e.category),
                    confidence: e.confidence,
                    source: format!("{:?}", e.source),
                })
                .collect(),
        };

        serde_json::to_string_pretty(&response).unwrap_or_else(|e| format!("Error: {e}"))
    }

    /// Show vault statistics: total mappings and per-category counts.
    #[tool(description = "Show vault statistics: total mappings and per-category counts.")]
    async fn vault_stats(&self) -> String {
        let vault = self.vault.lock().await;
        let stats = vault.stats();

        let response = VaultStatsResult {
            total_mappings: stats.total_mappings,
            categories: stats.categories,
        };

        serde_json::to_string_pretty(&response).unwrap_or_else(|e| format!("Error: {e}"))
    }

    /// Configure detection: switch industry profile or toggle categories.
    #[tool(description = "Configure detection at runtime: switch industry profile (general/legal/healthcare/fintech) or enable/disable categories (secrets, financial, dates, emails, phone_numbers, ip_addresses, urls_internal).")]
    async fn configure(
        &self,
        Parameters(params): Parameters<ConfigureParams>,
    ) -> String {
        let mut config = self.config.write().await;

        // Apply profile if specified
        if let Some(ref profile_name) = params.profile {
            if let Some(profile) = IndustryProfile::from_name(profile_name) {
                *config = profile.detection_config();
                let mut ap = self.active_profile.write().await;
                *ap = Some(profile.name().to_string());
            } else {
                return format!(
                    "Error: Unknown profile '{profile_name}'. Use: general, legal, healthcare, fintech"
                );
            }
        }

        // Apply enable/disable toggles
        if let Some(ref enable) = params.enable {
            apply_toggles(&mut config, enable, true);
        }
        if let Some(ref disable) = params.disable {
            apply_toggles(&mut config, disable, false);
        }

        // Rebuild detector with new config
        let new_detector = match Detector::from_config(&config) {
            Ok(d) => d,
            Err(e) => return format!("Error: Failed to rebuild detector: {e}"),
        };
        let mut detector = self.detector.write().await;
        *detector = new_detector;

        let ap = self.active_profile.read().await;
        let response = ConfigureResult {
            active_profile: ap.clone(),
            secrets: config.secrets,
            financial: config.financial,
            dates: config.dates,
            emails: config.emails,
            phone_numbers: config.phone_numbers,
            ip_addresses: config.ip_addresses,
        };

        serde_json::to_string_pretty(&response).unwrap_or_else(|e| format!("Error: {e}"))
    }

    /// Query session context: inspect a session's entities and coreferences, or list all active sessions.
    #[tool(description = "Query session context for context-aware pseudonymization. Pass a session ID to inspect it, or 'list' to see all active sessions. Shows entities tracked, coreferences, sensitivity level, and escalation keywords.")]
    async fn session_context(
        &self,
        Parameters(params): Parameters<SessionContextParams>,
    ) -> String {
        if params.session_id == "list" {
            let sessions = self.sessions.list_sessions();
            if sessions.is_empty() {
                return r#"{"sessions": [], "note": "No active sessions. Sessions are created when requests include x-session-id header."}"#.to_string();
            }
            serde_json::to_string_pretty(&serde_json::json!({
                "sessions": sessions,
                "total": sessions.len(),
            }))
            .unwrap_or_else(|e| format!("Error: {e}"))
        } else {
            match self.sessions.inspect(&params.session_id) {
                Some(stats) => serde_json::to_string_pretty(&stats)
                    .unwrap_or_else(|e| format!("Error: {e}")),
                None => format!(r#"{{"error": "Session '{}' not found"}}"#, params.session_id),
            }
        }
    }
}

fn apply_toggles(config: &mut DetectionConfig, categories: &[String], value: bool) {
    for cat in categories {
        match cat.to_lowercase().as_str() {
            "secrets" => config.secrets = value,
            "financial" => config.financial = value,
            "dates" => config.dates = value,
            "emails" => config.emails = value,
            "phone_numbers" | "phone" => config.phone_numbers = value,
            "ip_addresses" | "ip" => config.ip_addresses = value,
            "urls_internal" | "urls" => config.urls_internal = value,
            _ => {}
        }
    }
}

#[tool_handler]
impl ServerHandler for CloakPipeServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "CloakPipe privacy middleware. Tools: pseudonymize (cloak sensitive data), \
                 rehydrate (restore originals), detect (dry-run scan), vault_stats, configure \
                 (switch industry profiles or toggle detection categories).",
            )
            .with_server_info(
                Implementation::new("cloakpipe", env!("CARGO_PKG_VERSION")),
            )
    }
}

impl CloakPipeServer {
    pub fn new(config: CloakPipeConfig, detector: Detector, vault: Vault) -> Self {
        let detection_config = config.detection.clone();
        let profile = config.profile.clone();
        let sessions = Arc::new(SessionManager::new(config.session.clone()));
        Self {
            detector: Arc::new(RwLock::new(detector)),
            vault: Arc::new(Mutex::new(vault)),
            config: Arc::new(RwLock::new(detection_config)),
            active_profile: Arc::new(RwLock::new(profile)),
            sessions,
            tool_router: Self::tool_router(),
        }
    }
}

/// Start the MCP server on stdio.
pub async fn serve_stdio(
    config: CloakPipeConfig,
    detector: Detector,
    vault: Vault,
) -> anyhow::Result<()> {
    let server = CloakPipeServer::new(config, detector, vault);

    tracing::info!("Starting CloakPipe MCP server (stdio)");

    let transport = rmcp::transport::stdio();
    let service = server
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server failed to start: {e}"))?;
    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakpipe_core::config::DetectionConfig;

    fn test_server() -> CloakPipeServer {
        let config = DetectionConfig {
            secrets: true,
            financial: true,
            dates: true,
            emails: true,
            phone_numbers: false,
            ip_addresses: false,
            urls_internal: false,
            ner: Default::default(),
            custom: Default::default(),
            overrides: Default::default(),
            resolver: Default::default(),
        };
        let detector = Detector::from_config(&config).unwrap();
        let vault = Vault::ephemeral();

        CloakPipeServer {
            detector: Arc::new(RwLock::new(detector)),
            vault: Arc::new(Mutex::new(vault)),
            config: Arc::new(RwLock::new(config)),
            active_profile: Arc::new(RwLock::new(None)),
            sessions: Arc::new(SessionManager::new(Default::default())),
            tool_router: CloakPipeServer::tool_router(),
        }
    }

    #[tokio::test]
    async fn test_pseudonymize_tool() {
        let server = test_server();
        let params = PseudonymizeParams {
            text: "Send $1.2M to alice@acme.com".into(),
        };
        let result = server.pseudonymize(Parameters(params)).await;
        let parsed: PseudonymizeResult = serde_json::from_str(&result).unwrap();
        assert!(parsed.entities_detected > 0);
        assert!(!parsed.text.contains("alice@acme.com"));
        assert!(parsed.text.contains("EMAIL_1"));
    }

    #[tokio::test]
    async fn test_rehydrate_tool() {
        let server = test_server();

        // First pseudonymize
        let params = PseudonymizeParams {
            text: "Contact alice@acme.com".into(),
        };
        let result = server.pseudonymize(Parameters(params)).await;
        let parsed: PseudonymizeResult = serde_json::from_str(&result).unwrap();

        // Then rehydrate
        let params = RehydrateParams { text: parsed.text };
        let result = server.rehydrate(Parameters(params)).await;
        let parsed: RehydrateResult = serde_json::from_str(&result).unwrap();
        assert!(parsed.text.contains("alice@acme.com"));
        assert!(parsed.tokens_rehydrated > 0);
    }

    #[tokio::test]
    async fn test_detect_tool() {
        let server = test_server();
        let params = DetectParams {
            text: "Send $500 to bob@test.com by Q3 2025".into(),
        };
        let result = server.detect(Parameters(params)).await;
        let parsed: DetectResult = serde_json::from_str(&result).unwrap();
        assert!(parsed.entities.len() >= 2);
    }

    #[tokio::test]
    async fn test_vault_stats_tool() {
        let server = test_server();

        // Pseudonymize first to populate vault
        let params = PseudonymizeParams {
            text: "alice@acme.com sent $100".into(),
        };
        server.pseudonymize(Parameters(params)).await;

        let result = server.vault_stats().await;
        let parsed: VaultStatsResult = serde_json::from_str(&result).unwrap();
        assert!(parsed.total_mappings > 0);
    }

    #[tokio::test]
    async fn test_configure_switch_profile() {
        let server = test_server();
        let params = ConfigureParams {
            profile: Some("fintech".into()),
            enable: None,
            disable: None,
        };
        let result = server.configure(Parameters(params)).await;
        let parsed: ConfigureResult = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed.active_profile, Some("fintech".to_string()));
        assert!(parsed.financial);
        assert!(parsed.ip_addresses);
    }

    #[tokio::test]
    async fn test_configure_disable_category() {
        let server = test_server();
        let params = ConfigureParams {
            profile: None,
            enable: None,
            disable: Some(vec!["financial".into()]),
        };
        let result = server.configure(Parameters(params)).await;
        let parsed: ConfigureResult = serde_json::from_str(&result).unwrap();
        assert!(!parsed.financial);
        assert!(parsed.secrets);
    }
}
