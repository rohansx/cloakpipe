//! CLI command implementations.

use anyhow::{bail, Context, Result};
use cloakpipe_audit::AuditLogger;
use cloakpipe_core::{
    config::CloakPipeConfig,
    detector::Detector,
    replacer::Replacer,
    vault::Vault,
};
use cloakpipe_proxy::{server, state::AppState};

/// Load configuration from TOML file.
fn load_config(path: &str) -> Result<CloakPipeConfig> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read config: {}", path))?;
    toml::from_str(&content).with_context(|| format!("Invalid config in: {}", path))
}

/// Resolve the vault encryption key from environment variable.
fn resolve_vault_key(config: &CloakPipeConfig) -> Result<Vec<u8>> {
    let env_var = config
        .vault
        .key_env
        .as_deref()
        .unwrap_or("CLOAKPIPE_VAULT_KEY");
    match std::env::var(env_var) {
        Ok(hex_key) => {
            let bytes = hex_decode(&hex_key)
                .with_context(|| format!("{} must be a 64-char hex string (32 bytes)", env_var))?;
            if bytes.len() != 32 {
                bail!(
                    "{} must be 32 bytes (got {} bytes). Use a 64-char hex string.",
                    env_var,
                    bytes.len()
                );
            }
            Ok(bytes)
        }
        Err(_) => {
            tracing::warn!(
                "No {} set — generating ephemeral vault key (mappings won't persist across restarts)",
                env_var
            );
            let mut key = vec![0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            Ok(key)
        }
    }
}

/// Simple hex decoder.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        bail!("Hex string must have even length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .with_context(|| format!("Invalid hex at position {}", i))
        })
        .collect()
}

/// Start the proxy server.
pub async fn start(config_path: &str) -> Result<()> {
    let config = if std::path::Path::new(config_path).exists() {
        load_config(config_path)?
    } else {
        tracing::info!("No config found, creating {} with defaults", config_path);
        let config = default_config();
        let toml_str = toml::to_string_pretty(&config)?;
        std::fs::write(config_path, toml_str)?;
        config
    };
    let key = resolve_vault_key(&config)?;
    let detector = Detector::from_config(&config.detection)?;
    let vault = Vault::open(&config.vault.path, key)?;
    let audit = AuditLogger::new(&config.audit.log_path, config.audit.log_entities)?;
    let api_key = std::env::var(config.proxy.api_key_env.as_str())
        .with_context(|| format!("Set {} with your API key", config.proxy.api_key_env))?;

    tracing::info!(
        listen = %config.proxy.listen,
        upstream = %config.proxy.upstream,
        "Starting CloakPipe proxy"
    );

    let state = AppState::new(config, detector, vault, audit, api_key);
    server::start(state).await
}

/// Test detection on sample text.
pub async fn test(config_path: &str, text: Option<String>, file: Option<String>) -> Result<()> {
    let input = match (text, file) {
        (Some(t), _) => t,
        (_, Some(f)) => std::fs::read_to_string(&f)
            .with_context(|| format!("Cannot read file: {}", f))?,
        (None, None) => {
            // Default sample text
            "Tata Motors reported revenue of $1.2M in Q3 2025. Contact: cfo@tatamotors.com. \
             AWS key: AKIAIOSFODNN7EXAMPLE. Server: 192.168.1.100"
                .to_string()
        }
    };

    let config = if std::path::Path::new(config_path).exists() {
        load_config(config_path)?
    } else {
        tracing::info!("No config file found, using defaults");
        default_config()
    };

    let detector = Detector::from_config(&config.detection)?;
    let mut vault = Vault::ephemeral();

    println!("\n--- Input ---");
    println!("{}", input);

    let entities = detector.detect(&input)?;
    println!("\n--- Detected Entities ({}) ---", entities.len());
    for e in &entities {
        println!(
            "  [{:?}] \"{}\" (confidence: {:.0}%, source: {:?})",
            e.category,
            e.original,
            e.confidence * 100.0,
            e.source,
        );
    }

    let result = Replacer::pseudonymize(&input, &entities, &mut vault)?;
    println!("\n--- Pseudonymized ---");
    println!("{}", result.text);

    let rehydrated = cloakpipe_core::rehydrator::Rehydrator::rehydrate(&result.text, &vault)?;
    println!("\n--- Rehydrated ---");
    println!("{}", rehydrated.text);
    println!(
        "\n  Tokens rehydrated: {}",
        rehydrated.rehydrated_count
    );

    let roundtrip_ok = rehydrated.text == input;
    println!("  Roundtrip match: {}", if roundtrip_ok { "YES" } else { "NO" });

    Ok(())
}

/// Show vault statistics.
pub async fn stats(config_path: &str) -> Result<()> {
    let config = load_config(config_path)?;
    let key = resolve_vault_key(&config)?;
    let vault = Vault::open(&config.vault.path, key)?;
    let stats = vault.stats();

    println!("Vault: {}", config.vault.path);
    println!("Total mappings: {}", stats.total_mappings);
    if !stats.categories.is_empty() {
        println!("Categories:");
        for (cat, count) in &stats.categories {
            println!("  {}: {}", cat, count);
        }
    }

    Ok(())
}

/// Initialize a new config file.
pub async fn init() -> Result<()> {
    let path = "cloakpipe.toml";
    if std::path::Path::new(path).exists() {
        bail!("{} already exists", path);
    }

    let config = default_config();
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(path, toml_str)?;
    println!("Created {}", path);
    println!("\nNext steps:");
    println!("  1. Set OPENAI_API_KEY (or your upstream API key)");
    println!("  2. Set CLOAKPIPE_VAULT_KEY (64-char hex string for encryption)");
    println!("  3. Run: cloakpipe start");

    Ok(())
}

fn default_config() -> CloakPipeConfig {
    CloakPipeConfig {
        proxy: cloakpipe_core::config::ProxyConfig {
            listen: "127.0.0.1:8900".into(),
            upstream: "https://api.openai.com".into(),
            api_key_env: "OPENAI_API_KEY".into(),
            timeout_seconds: 120,
            max_concurrent: 256,
            mode: "proxy".into(),
        },
        vault: cloakpipe_core::config::VaultConfig {
            path: "./vault.enc".into(),
            encryption: "aes-256-gcm".into(),
            key_env: Some("CLOAKPIPE_VAULT_KEY".into()),
            key_keyring: false,
        },
        detection: cloakpipe_core::config::DetectionConfig {
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
        },
        tree: Default::default(),
        vectors: Default::default(),
        local: Default::default(),
        audit: Default::default(),
    }
}
