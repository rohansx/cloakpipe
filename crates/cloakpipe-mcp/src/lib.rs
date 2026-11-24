//! CloakPipe MCP Server — expose privacy tools to AI agents.
//!
//! Tools: pseudonymize, rehydrate, detect, vault_stats, configure.
//! Transport: stdio (for Claude Code, Cursor, etc.)
//!
//! Also exposes the transparent MCP interceptor ([`proxy`]) — a process that
//! sits between an agent and one or more upstream MCP servers ([`servers`]),
//! gating tool calls, pinning the servers' tool definitions ([`tools_lock`])
//! and, with the opt-in PII transform, masking PII in calls and rehydrating
//! results.

pub mod broker;
pub mod capture;
mod catalog;
pub mod events;
pub mod gate;
pub mod http;
pub mod operations;
pub mod proxy;
pub mod servers;
pub mod tools_lock;
pub use events::{
    DecisionRecord, EventKind, EventSink, GateEvent, JsonlSink, NoopSink, OtelConfig, OtelSink, WebhookConfig, WebhookFormat, WebhookSink,
    EVENT_SCHEMA,
};
pub use gate::{ApprovalRequest, ApprovedCall, Authorization, Denial, GateConfigError, GateMode, OperationKey, ToolGate};
pub use cloakpipe_policy::{Counters, PolicyEngine};
pub use proxy::{
    flush_events, reconcile_operation, run_proxy, run_proxy_io, run_servers, run_servers_io, run_upstream_io, stable_ids, Action, DecisionLog,
    Interceptor, PiiTransform, ProxyContext, Upstream, UpstreamTransport, DEFAULT_SERVER, EVENT_FLUSH, RECONCILE_REQUIRED, TOOL_REFUSED,
    UPSTREAM_UNAVAILABLE,
};
pub use capture::Capture;
pub use http::ListenConfig;
pub use servers::ServerTools;
pub use tools_lock::ToolsLock;

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
    /// M8: optional evidence ledger. When `CLOAKPIPE_LEDGER_DB` is set, each
    /// `pseudonymize` tool call appends a no-PII `McpToolCall` hop record, so
    /// MCP masking produces the same verifiable evidence as the proxy.
    ledger: Option<Arc<Mutex<cloakpipe_ledger::store::LedgerStore>>>,
    tenant_id: uuid::Uuid,
    agent_id: uuid::Uuid,
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
        drop(vault); // release the vault lock before the ledger await below

        let categories: Vec<String> = entities
            .iter()
            .map(|e| format!("{:?}", e.category))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // M8: record a no-PII evidence hop (categories + count only) so MCP
        // masking is as auditable as the proxy.
        if !entities.is_empty() {
            self.record_mcp_hop(categories.join("+"), entities.len() as u32).await;
        }

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
        // M8: open the evidence ledger when CLOAKPIPE_LEDGER_DB points at a path.
        let ledger = std::env::var("CLOAKPIPE_LEDGER_DB")
            .ok()
            .filter(|p| !p.is_empty())
            .and_then(|p| match cloakpipe_ledger::store::LedgerStore::open(&p) {
                Ok(s) => {
                    tracing::info!(db = %p, "MCP evidence ledger enabled");
                    Some(Arc::new(Mutex::new(s)))
                }
                Err(e) => {
                    tracing::warn!("MCP ledger open failed ({e}); evidence disabled");
                    None
                }
            });
        let ns = uuid::Uuid::NAMESPACE_URL;
        Self {
            detector: Arc::new(RwLock::new(detector)),
            vault: Arc::new(Mutex::new(vault)),
            config: Arc::new(RwLock::new(detection_config)),
            active_profile: Arc::new(RwLock::new(profile)),
            sessions,
            ledger,
            tenant_id: uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-tenant"),
            agent_id: uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-agent"),
            tool_router: Self::tool_router(),
        }
    }

    /// M8: append a no-PII `McpToolCall` evidence record for a masking hop.
    /// Only categories + a count + a random token are recorded — never text.
    /// Best-effort: a ledger error is logged, never surfaced to the tool caller.
    async fn record_mcp_hop(&self, entity_type: String, count: u32) {
        let Some(ledger) = &self.ledger else { return };
        let mut store = ledger.lock().await;
        let next_seq = match store.head(&self.tenant_id) {
            Ok((head, _)) => head.map(|s| s + 1).unwrap_or(0),
            Err(e) => {
                tracing::warn!("mcp ledger head failed: {e}");
                return;
            }
        };
        let builder = cloakpipe_ledger::RecordBuilder::new()
            .seq(next_seq)
            .tenant(self.tenant_id)
            .hop(cloakpipe_ledger::Hop::McpToolCall)
            .detection(cloakpipe_ledger::Detection {
                entity_type: entity_type.clone(),
                count,
                detector: cloakpipe_ledger::Detector::Regex,
            })
            .action(cloakpipe_ledger::Action {
                entity_type,
                kind: cloakpipe_ledger::ActionKind::Pseudonymize,
                token_ref: Some(uuid::Uuid::new_v4().to_string()),
            })
            .identities(cloakpipe_ledger::record::Identity {
                agent_id: self.agent_id,
                human_principal: None,
                upstream: "mcp".to_string(),
                region: std::env::var("CLOAKPIPE_REGION").unwrap_or_else(|_| "local".to_string()),
            });
        match builder.build() {
            Ok(mut record) => {
                if let Err(e) = store.append(&self.tenant_id, &mut record) {
                    tracing::warn!("mcp ledger append failed: {e}");
                }
            }
            Err(e) => tracing::warn!("mcp ledger build failed: {e}"),
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

        let ns = uuid::Uuid::NAMESPACE_URL;
        CloakPipeServer {
            detector: Arc::new(RwLock::new(detector)),
            vault: Arc::new(Mutex::new(vault)),
            config: Arc::new(RwLock::new(config)),
            active_profile: Arc::new(RwLock::new(None)),
            sessions: Arc::new(SessionManager::new(Default::default())),
            ledger: None,
            tenant_id: uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-tenant"),
            agent_id: uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-agent"),
            tool_router: CloakPipeServer::tool_router(),
        }
    }

    /// M8: calling the `pseudonymize` tool appends a no-PII evidence record to
    /// the ledger — and the raw value never lands in the ledger DB.
    #[tokio::test]
    async fn mcp_pseudonymize_records_ledger_hop_without_raw_pii() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("mcp-ledger.sqlite");
        let mut server = test_server();
        server.ledger = Some(Arc::new(Mutex::new(
            cloakpipe_ledger::store::LedgerStore::open(db.to_str().unwrap()).unwrap(),
        )));

        // Empty before.
        assert_eq!(
            server.ledger.as_ref().unwrap().lock().await.head(&server.tenant_id).unwrap().0,
            None
        );

        // Call the real tool with PII in the text.
        let secret = "secret@corp.com";
        let out = server
            .pseudonymize(Parameters(PseudonymizeParams {
                text: format!("please email {secret} the report"),
            }))
            .await;
        assert!(out.contains("entities_detected"), "tool returned a result: {out}");

        // A hop was recorded.
        assert_eq!(
            server.ledger.as_ref().unwrap().lock().await.head(&server.tenant_id).unwrap().0,
            Some(0),
            "one MCP hop recorded"
        );

        // NO-PII: the raw value must not appear in ANY ledger DB file.
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap_or_default();
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "raw PII leaked into ledger file {path:?}"
            );
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
