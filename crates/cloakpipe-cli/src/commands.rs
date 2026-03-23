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
    if !hex.len().is_multiple_of(2) {
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

/// Interactive guided setup.
pub async fn setup() -> Result<()> {
    use cloakpipe_core::profiles::IndustryProfile;
    use dialoguer::{Select, Confirm};

    println!("CloakPipe Setup\n");

    // 1. Industry profile
    let profiles = IndustryProfile::all();
    let _profile_names: Vec<&str> = profiles.iter().map(|p| p.name()).collect();
    let profile_descriptions = [
        "General — balanced defaults for most use cases",
        "Legal — NER for names, case numbers, SSNs; preserves numeric reasoning",
        "Healthcare — HIPAA-aware: MRN, NPI, DEA numbers; NER for patient names",
        "Fintech — financial data, SWIFT/ISIN/IBAN; IP and internal URL detection",
    ];

    let profile_idx = Select::new()
        .with_prompt("What industry are you in?")
        .items(&profile_descriptions)
        .default(0)
        .interact()?;
    let profile = profiles[profile_idx];

    // 2. Upstream provider
    let upstreams = [
        "OpenAI (https://api.openai.com)",
        "Azure OpenAI",
        "Anthropic (https://api.anthropic.com)",
        "Ollama / local (http://localhost:11434)",
        "Custom URL",
    ];
    let upstream_idx = Select::new()
        .with_prompt("Which LLM provider?")
        .items(&upstreams)
        .default(0)
        .interact()?;
    let (upstream, api_key_env) = match upstream_idx {
        0 => ("https://api.openai.com".to_string(), "OPENAI_API_KEY"),
        1 => ("https://YOUR_RESOURCE.openai.azure.com".to_string(), "AZURE_OPENAI_API_KEY"),
        2 => ("https://api.anthropic.com".to_string(), "ANTHROPIC_API_KEY"),
        3 => ("http://localhost:11434".to_string(), "OLLAMA_API_KEY"),
        _ => {
            let url: String = dialoguer::Input::new()
                .with_prompt("Enter upstream URL")
                .interact_text()?;
            (url, "API_KEY")
        }
    };

    // 3. Vault backend
    let backends = ["File (vault.enc)", "SQLite (vault.db)"];
    let backend_idx = Select::new()
        .with_prompt("Vault storage backend?")
        .items(&backends)
        .default(0)
        .interact()?;
    let (vault_backend, vault_path) = match backend_idx {
        0 => ("file", "./vault.enc"),
        _ => ("sqlite", "./vault.db"),
    };

    // 4. Audit logging
    let audit_enabled = Confirm::new()
        .with_prompt("Enable audit logging?")
        .default(true)
        .interact()?;

    // Build config
    let detection = profile.detection_config();
    let mut config = default_config();
    config.profile = Some(profile.name().to_string());
    config.proxy.upstream = upstream;
    config.proxy.api_key_env = api_key_env.into();
    config.vault.backend = vault_backend.into();
    config.vault.path = vault_path.into();
    config.detection = detection;
    config.audit = cloakpipe_core::config::AuditConfig {
        enabled: audit_enabled,
        ..Default::default()
    };

    let path = "cloakpipe.toml";
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(path, &toml_str)?;

    println!("\nCreated {} with profile: {}", path, profile);
    println!("\nNext steps:");
    println!("  1. Set {} (your API key)", api_key_env);
    println!("  2. Set CLOAKPIPE_VAULT_KEY=$(openssl rand -hex 32)");
    println!("  3. Run: cloakpipe start");

    Ok(())
}

/// Start as MCP server (stdio transport).
pub async fn mcp(config_path: &str) -> Result<()> {
    let config = if std::path::Path::new(config_path).exists() {
        load_config(config_path)?
    } else {
        tracing::info!("No config file found, using defaults");
        default_config()
    };

    let key = resolve_vault_key(&config)?;
    let vault = cloakpipe_core::vault::Vault::open(&config.vault.path, key)?;
    let detector = cloakpipe_core::detector::Detector::from_config(&config.detection)?;

    cloakpipe_mcp::serve_stdio(config, detector, vault).await
}

/// CloakTree commands — vectorless document retrieval.
pub async fn tree(config_path: &str, action: crate::TreeCommands) -> Result<()> {
    let config = if std::path::Path::new(config_path).exists() {
        load_config(config_path)?
    } else {
        tracing::info!("No config file found, using defaults");
        default_config()
    };

    let tree_config = &config.tree;

    match action {
        crate::TreeCommands::Index { file, no_summaries } => {
            let api_key = std::env::var(&config.proxy.api_key_env).unwrap_or_default();
            let mut tc = tree_config.clone();
            if no_summaries {
                tc.add_node_summaries = false;
            }

            let indexer = cloakpipe_tree::TreeIndexer::new(
                tc,
                api_key,
                config.proxy.upstream.clone(),
            );

            let tree_index = indexer.build_index(&file).await?;
            let path = cloakpipe_tree::storage::TreeStorage::save(
                &tree_index,
                &tree_config.storage_path,
            )?;

            println!("Tree index created:");
            println!("  ID:     {}", tree_index.id);
            println!("  Source: {}", tree_index.source);
            println!("  Nodes:  {}", tree_index.node_count());
            println!("  Depth:  {}", tree_index.max_depth());
            println!("  Pages:  {}", tree_index.total_pages);
            if let Some(desc) = &tree_index.description {
                println!("  Desc:   {}", desc);
            }
            println!("  Saved:  {}", path);
        }

        crate::TreeCommands::Search { index, query } => {
            let api_key = std::env::var(&config.proxy.api_key_env)
                .context("API key required for tree search")?;

            let tree_index = cloakpipe_tree::storage::TreeStorage::load(&index)?;
            let searcher = cloakpipe_tree::TreeSearcher::new(
                api_key,
                config.proxy.upstream.clone(),
                tree_config.search_model.clone(),
            );

            let result = searcher.search(&tree_index, &query).await?;

            println!("Search results for: {}", query);
            println!("  Reasoning: {}", result.reasoning);
            if let Some(conf) = result.confidence {
                println!("  Confidence: {:.0}%", conf * 100.0);
            }
            println!("  Matching nodes:");
            for id in &result.node_ids {
                if let Some(node) = tree_index.find_node(id) {
                    println!("    [{}] {} (pages {}-{})", id, node.title, node.pages.0, node.pages.1);
                    if let Some(summary) = &node.summary {
                        println!("          {}", summary.text);
                    }
                }
            }
        }

        crate::TreeCommands::List => {
            let trees = cloakpipe_tree::storage::TreeStorage::list(&tree_config.storage_path)?;
            if trees.is_empty() {
                println!("No tree indices found in {}", tree_config.storage_path);
                println!("Create one with: cloakpipe tree index <file>");
            } else {
                println!("Tree indices ({}):", trees.len());
                for (id, source) in &trees {
                    println!("  {} -> {}", id, source);
                }
            }
        }

        crate::TreeCommands::Query { file, question } => {
            let api_key = std::env::var(&config.proxy.api_key_env)
                .context("API key required for tree query")?;

            // If file is a .json, load existing index; otherwise build one
            let (tree_index, pages) = if file.ends_with(".json") {
                let tree_index = cloakpipe_tree::storage::TreeStorage::load(&file)?;
                let pages = cloakpipe_tree::parser::parse_document(&tree_index.source)?;
                (tree_index, pages)
            } else {
                let indexer = cloakpipe_tree::TreeIndexer::new(
                    tree_config.clone(),
                    api_key.clone(),
                    config.proxy.upstream.clone(),
                );
                let tree_index = indexer.build_index(&file).await?;
                let pages = cloakpipe_tree::parser::parse_document(&file)?;

                // Save for future use
                let path = cloakpipe_tree::storage::TreeStorage::save(
                    &tree_index,
                    &tree_config.storage_path,
                )?;
                println!("Index saved: {}\n", path);
                (tree_index, pages)
            };

            // Search
            let searcher = cloakpipe_tree::TreeSearcher::new(
                api_key.clone(),
                config.proxy.upstream.clone(),
                tree_config.search_model.clone(),
            );
            let result = searcher.search(&tree_index, &question).await?;

            // Extract content from matching nodes
            let content = cloakpipe_tree::extractor::ContentExtractor::extract(
                &tree_index,
                &result.node_ids,
                &pages,
            )?;

            let context_text: String = content
                .iter()
                .map(|c| format!("[{}] {}\n{}", c.node_id, c.title, c.text))
                .collect::<Vec<_>>()
                .join("\n\n---\n\n");

            // Send to LLM for final answer
            let prompt = format!(
                "Based on the following document excerpts, answer the question.\n\n\
                 EXCERPTS:\n{}\n\n\
                 QUESTION: {}\n\n\
                 Answer concisely based only on the provided excerpts.",
                context_text, question
            );

            let body = serde_json::json!({
                "model": tree_config.search_model,
                "messages": [
                    {"role": "system", "content": "You answer questions based on provided document excerpts. Be precise and cite section titles when relevant."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 1000,
                "temperature": 0.3
            });

            let url = format!("{}/v1/chat/completions", config.proxy.upstream.trim_end_matches('/'));
            let client = reqwest::Client::new();
            let response = client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&body)
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?;

            let answer = response["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("No answer generated");

            println!("Question: {}\n", question);
            println!("Sources ({}):", result.node_ids.len());
            for c in &content {
                println!("  [{}] {} (pages {}-{})", c.node_id, c.title, c.pages.0, c.pages.1);
            }
            println!("\nAnswer:\n{}", answer);
        }

        crate::TreeCommands::Show { index } => {
            let tree_index = cloakpipe_tree::storage::TreeStorage::load(&index)?;

            println!("Tree Index: {}", tree_index.id);
            println!("  Source:  {}", tree_index.source);
            println!("  Model:   {}", tree_index.model);
            println!("  Pages:   {}", tree_index.total_pages);
            println!("  Nodes:   {}", tree_index.node_count());
            println!("  Depth:   {}", tree_index.max_depth());
            println!("  Created: {}", tree_index.created_at);
            if let Some(desc) = &tree_index.description {
                println!("  Desc:    {}", desc);
            }
            println!("\nTree structure:");
            for entry in tree_index.navigation_map() {
                println!("  {}", entry);
            }
        }
    }

    Ok(())
}

/// ADCPE vector encryption commands.
pub async fn vector(action: crate::VectorCommands) -> Result<()> {
    match action {
        crate::VectorCommands::Encrypt { input, output, dim } => {
            let key = resolve_vector_key()?;
            let config = cloakpipe_vector::AdcpeConfig { dimensions: dim, noise_scale: 0.0 };
            let mut enc = cloakpipe_vector::AdcpeEncryptor::new(&key, &config)?;

            let data = std::fs::read_to_string(&input)
                .with_context(|| format!("Cannot read: {}", input))?;
            let vectors: Vec<Vec<f64>> = serde_json::from_str(&data)
                .context("Input must be a JSON array of float arrays")?;

            let encrypted = enc.encrypt_batch(&vectors)?;
            let json = serde_json::to_string_pretty(&encrypted)?;
            std::fs::write(&output, json)?;

            println!("Encrypted {} vectors (dim={}) -> {}", vectors.len(), dim, output);
        }

        crate::VectorCommands::Decrypt { input, output, dim } => {
            let key = resolve_vector_key()?;
            let config = cloakpipe_vector::AdcpeConfig { dimensions: dim, noise_scale: 0.0 };
            let enc = cloakpipe_vector::AdcpeEncryptor::new(&key, &config)?;

            let data = std::fs::read_to_string(&input)
                .with_context(|| format!("Cannot read: {}", input))?;
            let encrypted: Vec<Vec<f64>> = serde_json::from_str(&data)
                .context("Input must be a JSON array of float arrays")?;

            let decrypted = enc.decrypt_batch(&encrypted)?;
            let json = serde_json::to_string_pretty(&decrypted)?;
            std::fs::write(&output, json)?;

            println!("Decrypted {} vectors (dim={}) -> {}", encrypted.len(), dim, output);
        }

        crate::VectorCommands::Test { dim } => {
            let key = resolve_vector_key()?;
            let config = cloakpipe_vector::AdcpeConfig { dimensions: dim, noise_scale: 0.0 };
            let mut enc = cloakpipe_vector::AdcpeEncryptor::new(&key, &config)?;

            // Generate sample vectors
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let a: Vec<f64> = (0..dim).map(|_| rng.gen::<f64>() - 0.5).collect();
            let b: Vec<f64> = (0..dim).map(|_| rng.gen::<f64>() - 0.5).collect();

            let cos_orig = cloakpipe_vector::adcpe::cosine_similarity(&a, &b);

            let ea = enc.encrypt(&a)?;
            let eb = enc.encrypt(&b)?;
            let cos_enc = cloakpipe_vector::adcpe::cosine_similarity(&ea, &eb);

            let da = enc.decrypt(&ea)?;
            let max_err: f64 = a.iter().zip(da.iter())
                .map(|(x, y)| (x - y).abs())
                .fold(0.0, f64::max);

            println!("ADCPE Test (dim={})", dim);
            println!("  Cosine similarity (original):  {:.6}", cos_orig);
            println!("  Cosine similarity (encrypted): {:.6}", cos_enc);
            println!("  Distance preserved: {}", if (cos_orig - cos_enc).abs() < 1e-10 { "YES" } else { "NO" });
            println!("  Roundtrip max error: {:.2e}", max_err);
            println!("  Roundtrip exact: {}", if max_err < 1e-10 { "YES" } else { "NO" });
        }
    }

    Ok(())
}

/// Resolve the ADCPE vector encryption key from env.
fn resolve_vector_key() -> Result<[u8; 32]> {
    let env_var = "CLOAKPIPE_VECTOR_KEY";
    match std::env::var(env_var) {
        Ok(hex_key) => {
            let bytes = hex_decode(&hex_key)
                .with_context(|| format!("{} must be a 64-char hex string", env_var))?;
            if bytes.len() != 32 {
                bail!("{} must be 32 bytes (got {})", env_var, bytes.len());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Err(_) => {
            tracing::warn!("No {} set — generating ephemeral key", env_var);
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            Ok(key)
        }
    }
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
            masking_strategy: cloakpipe_core::MaskingStrategy::Token,
        },
        vault: cloakpipe_core::config::VaultConfig {
            path: "./vault.enc".into(),
            encryption: "aes-256-gcm".into(),
            key_env: Some("CLOAKPIPE_VAULT_KEY".into()),
            key_keyring: false,
            backend: "file".into(),
        },
        profile: None,
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
            resolver: Default::default(),
        },
        tree: Default::default(),
        vectors: Default::default(),
        local: Default::default(),
        audit: Default::default(),
        session: Default::default(),
    }
}

/// RAG pipeline scan — detect and optionally mask PII across files/directories.
pub async fn scan(
    config_path: &str,
    input: String,
    output: Option<String>,
    strategy: String,
    detect_only: bool,
    min_confidence: f64,
) -> Result<()> {
    let config = if std::path::Path::new(config_path).exists() {
        load_config(config_path)?
    } else {
        default_config()
    };

    let detector = Detector::from_config(&config.detection)?;
    let masking_strategy = match strategy.as_str() {
        "format-preserving" | "fp" => cloakpipe_core::MaskingStrategy::FormatPreserving,
        _ => cloakpipe_core::MaskingStrategy::Token,
    };

    let input_path = std::path::Path::new(&input);
    let files = collect_scannable_files(input_path)?;

    if files.is_empty() {
        println!("No scannable files found in: {}", input);
        return Ok(());
    }

    let output_dir = if detect_only {
        None
    } else {
        let dir = output.unwrap_or_else(|| format!("{}-masked", input.trim_end_matches('/')));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Cannot create output dir: {}", dir))?;
        Some(dir)
    };

    let mut vault = Vault::ephemeral();
    let mut total_entities = 0usize;
    let mut total_files = 0usize;
    let mut file_results: Vec<(String, usize)> = Vec::new();

    println!("Scanning {} files for PII...\n", files.len());

    for file_path in &files {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Cannot read: {}", file_path.display()))?;

        let mut entities = detector.detect(&content)?;
        entities.retain(|e| e.confidence >= min_confidence);

        let entity_count = entities.len();
        total_entities += entity_count;

        let rel_path = file_path
            .strip_prefix(input_path)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        if entity_count > 0 {
            total_files += 1;
            file_results.push((rel_path.clone(), entity_count));

            if detect_only {
                println!("  {} — {} entities", rel_path, entity_count);
                for e in &entities {
                    println!(
                        "    [{:?}] \"{}\" (confidence: {:.0}%, source: {:?})",
                        e.category,
                        e.original,
                        e.confidence * 100.0,
                        e.source,
                    );
                }
            }
        }

        if let Some(ref out_dir) = output_dir {
            entities.sort_by_key(|e| e.start);

            let masked_content = if entities.is_empty() {
                content.clone()
            } else {
                Replacer::pseudonymize_with_strategy(
                    &content,
                    &entities,
                    &mut vault,
                    masking_strategy,
                )?
                .text
            };

            let out_path = std::path::Path::new(out_dir).join(&rel_path);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out_path, masked_content)?;
        }
    }

    println!("\n--- Scan Summary ---");
    println!("  Files scanned:  {}", files.len());
    println!("  Files with PII: {}", total_files);
    println!("  Total entities: {}", total_entities);
    println!("  Strategy:       {}", strategy);
    println!("  Min confidence: {:.0}%", min_confidence * 100.0);

    if let Some(ref out_dir) = output_dir {
        // Save vault mappings as JSON for rehydration
        let mappings_path = format!("{}/vault-mappings.json", out_dir);
        let mappings = vault.reverse_mappings();
        let json = serde_json::to_string_pretty(&mappings)?;
        std::fs::write(&mappings_path, json)?;

        println!("  Output dir:     {}", out_dir);
        println!("  Vault mappings: {}", mappings_path);
    }

    if !file_results.is_empty() && !detect_only {
        println!("\n  Files masked:");
        for (path, count) in &file_results {
            println!("    {} ({} entities)", path, count);
        }
    }

    Ok(())
}

/// Collect scannable text files from a path (file or directory).
fn collect_scannable_files(path: &std::path::Path) -> Result<Vec<std::path::PathBuf>> {
    let extensions = ["txt", "md", "json", "csv", "toml", "yaml", "yml", "xml", "html"];

    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if !path.is_dir() {
        bail!("Path does not exist: {}", path.display());
    }

    let mut files = Vec::new();
    collect_files_recursive(path, &extensions, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files_recursive(
    dir: &std::path::Path,
    extensions: &[&str],
    files: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_recursive(&path, extensions, files)?;
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                files.push(path);
            }
        }
    }
    Ok(())
}

/// Session management commands — talks to the running proxy's HTTP API.
pub async fn sessions(config_path: &str, action: crate::SessionCommands) -> Result<()> {
    let config = if std::path::Path::new(config_path).exists() {
        load_config(config_path)?
    } else {
        default_config()
    };

    let base = format!("http://{}", config.proxy.listen);
    let client = reqwest::Client::new();

    match action {
        crate::SessionCommands::List => {
            let resp = client
                .get(format!("{}/sessions", base))
                .send()
                .await
                .context("Cannot reach proxy — is it running?")?
                .json::<serde_json::Value>()
                .await?;

            let sessions = resp.as_array().map(|a| a.len()).unwrap_or(0);
            if sessions == 0 {
                println!("No active sessions.");
                println!("Sessions are created when requests include x-session-id header.");
            } else {
                println!("Active sessions ({}):\n", sessions);
                for sess in resp.as_array().unwrap() {
                    println!(
                        "  {} | {} msgs | {} entities | sensitivity: {} | last: {}",
                        sess["session_id"].as_str().unwrap_or("?"),
                        sess["message_count"],
                        sess["entity_count"],
                        sess["sensitivity"].as_str().unwrap_or("normal"),
                        sess["last_activity"].as_str().unwrap_or("?"),
                    );
                }
            }
        }

        crate::SessionCommands::Inspect { session_id } => {
            let resp = client
                .get(format!("{}/sessions/{}", base, session_id))
                .send()
                .await
                .context("Cannot reach proxy — is it running?")?;

            if resp.status() == 404 {
                bail!("Session {} not found", session_id);
            }

            let stats: serde_json::Value = resp.json().await?;
            println!("Session: {}", session_id);
            println!("  Messages:      {}", stats["message_count"]);
            println!("  Entities:      {}", stats["entity_count"]);
            println!("  Coreferences:  {}", stats["coreference_count"]);
            println!("  Sensitivity:   {}", stats["sensitivity"].as_str().unwrap_or("normal"));
            if let Some(keywords) = stats["escalation_keywords"].as_array() {
                if !keywords.is_empty() {
                    let kw: Vec<&str> = keywords.iter().filter_map(|k| k.as_str()).collect();
                    println!("  Keywords:      {}", kw.join(", "));
                }
            }
            if let Some(cats) = stats["categories"].as_object() {
                println!("  Categories:");
                for (cat, count) in cats {
                    println!("    {}: {}", cat, count);
                }
            }
            println!("  Created:       {}", stats["created_at"].as_str().unwrap_or("?"));
            println!("  Last activity: {}", stats["last_activity"].as_str().unwrap_or("?"));
        }

        crate::SessionCommands::Flush { session_id } => {
            let resp = client
                .delete(format!("{}/sessions/{}", base, session_id))
                .send()
                .await
                .context("Cannot reach proxy — is it running?")?
                .json::<serde_json::Value>()
                .await?;

            if resp["flushed"].as_bool() == Some(true) {
                println!("Session {} flushed.", session_id);
            } else {
                println!("Session {} not found.", session_id);
            }
        }

        crate::SessionCommands::FlushAll => {
            let resp = client
                .delete(format!("{}/sessions", base))
                .send()
                .await
                .context("Cannot reach proxy — is it running?")?
                .json::<serde_json::Value>()
                .await?;

            println!("Flushed {} sessions.", resp["flushed"]);
        }
    }

    Ok(())
}
