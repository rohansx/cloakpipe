//! CloakPipe CLI: the self-hosted policy-enforcement gate for AI agent tool
//! calls (`mcp-proxy`), its evidence tooling and the regex PII proxy.
//!
//! Optional cargo features, all off by default (`full` turns them all on):
//! `ner` (neural NER detectors), `rag` (`tree`, `vector` and the proxy's RAG
//! routes) and `certification` (legacy `eval`, `release certify`,
//! `verify-cert` and `audit-pack`).

mod action;
mod anchor;
mod approvals;
#[cfg(feature = "certification")]
mod audit_pack;
#[cfg(feature = "certification")]
mod cert;
mod commands;
mod events;
mod evidence;
mod gate;
mod infer;
mod keys;
mod manifest;
mod operations;
mod prove;
mod release;
mod tools;
mod verify;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cloakpipe")]
#[command(about = "Self-hosted policy-enforcement gate for AI agent tool calls")]
#[command(version)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "cloakpipe.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the CloakPipe proxy server
    Start,
    /// Test detection on sample text
    Test {
        /// Text to test detection on
        #[arg(short, long)]
        text: Option<String>,
        /// File to read test text from
        #[arg(short, long)]
        file: Option<String>,
    },
    /// Show vault statistics
    Stats,
    /// Initialize a new cloakpipe.toml config file
    Init,
    /// Interactive guided setup (industry profiles, detection tuning)
    Setup,
    /// Start as an MCP server (for agent integrations)
    Mcp,
    /// Transparently proxy an upstream MCP server: gate tool calls with
    /// --manifest; mask PII in arguments only with --transform pii.
    McpProxy(Box<gate::McpProxyArgs>),
    /// CloakTree: vectorless document retrieval
    #[cfg(feature = "rag")]
    Tree {
        #[command(subcommand)]
        action: TreeCommands,
    },
    /// ADCPE: encrypt/decrypt embedding vectors
    #[cfg(feature = "rag")]
    Vector {
        #[command(subcommand)]
        action: VectorCommands,
    },
    /// Manage active sessions (context-aware pseudonymization)
    Sessions {
        #[command(subcommand)]
        action: SessionCommands,
    },
    /// The tool gate's manifest (cloakpipe.manifest.yaml): validate, hash
    Manifest {
        #[command(subcommand)]
        action: manifest::ManifestCommands,
    },
    /// Agent Release manifests: validate, hash, diff, inspect, keygen
    Release {
        #[command(subcommand)]
        action: release::ReleaseCommands,
    },
    /// Seal an exported evidence bundle under a signed batch head and anchor it
    /// externally (RFC 3161 TSA and/or Sigstore Rekor); see docs/ANCHORING.md
    Anchor(anchor::AnchorArgs),
    /// Tool calls at the action boundary: print a call's fingerprint
    Action {
        #[command(subcommand)]
        action: action::ActionCommands,
    },
    /// Sign an approval receipt for one exact tool call (for mcp-proxy --approvals)
    Approve(action::ApproveArgs),
    /// Approvals through a broker: fetch its approver keys as --approver-key files
    Approvals {
        #[command(subcommand)]
        action: approvals::ApprovalsCommands,
    },
    /// Upstream MCP tool definitions: pin them in cloakpipe.tools.lock, diff against it
    Tools {
        #[command(subcommand)]
        action: tools::ToolsCommands,
    },
    /// Side-effecting tool calls tracked by mcp-proxy --operations-db: list, reconcile
    Operations {
        #[command(subcommand)]
        action: operations::OperationsCommands,
    },
    /// The gate's signed decision ledger: print its entries or the gate public
    /// key, or export a signed audit pack
    Ledger {
        #[command(subcommand)]
        action: evidence::LedgerCommands,
    },
    /// Verify a gate audit pack (`ledger export`) offline: entries, chain,
    /// signatures, anchored epochs (RFC 3161, Rekor) and gaps
    Verify(verify::VerifyArgs),
    /// Gate event delivery: send a test webhook, verify a webhook signature
    Events {
        #[command(subcommand)]
        action: events::EventsCommands,
    },
    /// Evaluation runs: import external results as certification evidence
    #[cfg(feature = "certification")]
    Eval {
        #[command(subcommand)]
        action: cert::EvalCommands,
    },
    /// Draft a contract from tool calls captured in shadow mode
    /// (`mcp-proxy --capture`), or diff captured traffic against one (--diff)
    Infer(Box<infer::InferArgs>),
    /// Run a live agent through an attack pack with the gate off (shadow) and
    /// on (enforce), and report which attacks reached the tools
    Prove(Box<prove::ProveArgs>),
    /// The stub tool server `prove` runs behind the gate (internal)
    #[command(hide = true)]
    ProveStub(prove::stub::StubArgs),
    /// Scan files/directories for PII (RAG pre-indexing pipeline)
    Scan {
        /// Input file or directory (recursively scans .txt, .md, .json, .csv)
        input: String,
        /// Output directory for masked files (default: <input>-masked)
        #[arg(short, long)]
        output: Option<String>,
        /// Masking strategy: token or format-preserving
        #[arg(long, default_value = "token")]
        strategy: String,
        /// Only detect, don't mask (prints report)
        #[arg(long)]
        detect_only: bool,
        /// Minimum confidence threshold (0.0–1.0)
        #[arg(long, default_value = "0.5")]
        min_confidence: f64,
    },
}

#[cfg(feature = "rag")]
#[derive(Subcommand)]
pub enum TreeCommands {
    /// Build a tree index from a document
    Index {
        /// Path to the document (PDF, TXT, MD)
        file: String,
        /// Skip LLM-generated summaries (offline mode)
        #[arg(long)]
        no_summaries: bool,
    },
    /// Search a tree index with a natural language query
    Search {
        /// Path to the tree index JSON file
        index: String,
        /// The search query
        query: String,
    },
    /// List all tree indices
    List,
    /// Query a document end-to-end (index + search + extract + answer)
    Query {
        /// Path to the document (or existing tree index JSON)
        file: String,
        /// The question to answer
        question: String,
    },
    /// Show tree index details
    Show {
        /// Path to the tree index JSON file
        index: String,
    },
}

#[derive(Subcommand)]
pub enum SessionCommands {
    /// List all active sessions
    List,
    /// Inspect a session's entity map and coreferences
    Inspect {
        /// Session ID to inspect
        session_id: String,
    },
    /// Flush (delete) a specific session
    Flush {
        /// Session ID to flush
        session_id: String,
    },
    /// Flush all sessions
    FlushAll,
}

#[cfg(feature = "rag")]
#[derive(Subcommand)]
pub enum VectorCommands {
    /// Encrypt embedding vectors from a JSON file
    Encrypt {
        /// Input JSON file (array of float arrays)
        input: String,
        /// Output file for encrypted vectors
        output: String,
        /// Vector dimensions
        #[arg(long, default_value = "1536")]
        dim: usize,
    },
    /// Decrypt embedding vectors
    Decrypt {
        /// Input JSON file (encrypted vectors)
        input: String,
        /// Output file for decrypted vectors
        output: String,
        /// Vector dimensions
        #[arg(long, default_value = "1536")]
        dim: usize,
    },
    /// Test ADCPE: encrypt sample vectors and verify distance preservation
    Test {
        /// Vector dimensions to test
        #[arg(long, default_value = "8")]
        dim: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Release and eval tooling is synchronous (including blocking HTTP for `register`),
    // prints machine-readable output and uses distinct exit codes, so it runs
    // before logging setup and outside the async runtime.
    let command = match cli.command {
        Commands::Manifest { action } => std::process::exit(manifest::run(action)),
        Commands::Release { action } => std::process::exit(release::run(action)),
        #[cfg(feature = "certification")]
        Commands::Eval { action } => std::process::exit(cert::eval(action)),
        Commands::Anchor(args) => std::process::exit(anchor::run(args)),
        Commands::Action { action } => std::process::exit(action::run(action)),
        Commands::Approve(args) => std::process::exit(action::approve(args)),
        Commands::Approvals { action } => std::process::exit(approvals::run(action)),
        Commands::Operations { action } => std::process::exit(operations::run(action)),
        Commands::Tools { action } => std::process::exit(tools::run(action)),
        Commands::Ledger { action } => std::process::exit(evidence::run(action)),
        Commands::Verify(args) => std::process::exit(verify::run(args)),
        Commands::Events { action } => std::process::exit(events::run(action)),
        Commands::Infer(args) => std::process::exit(infer::run(*args)),
        Commands::Prove(args) => std::process::exit(prove::run(*args)),
        Commands::ProveStub(args) => std::process::exit(prove::stub::run(args)),
        other => other,
    };

    tokio::runtime::Runtime::new()?.block_on(run(command, cli.config))
}

async fn run(command: Commands, config: String) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        // Diagnostics go to stderr — stdout is reserved for program output and,
        // for the `mcp`/`mcp-proxy` stdio servers, the JSON-RPC stream itself.
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloakpipe=info,tower_http=info".into()),
        )
        .init();

    match command {
        Commands::Start => commands::start(&config).await,
        Commands::Test { text, file } => commands::test(&config, text, file).await,
        Commands::Stats => commands::stats(&config).await,
        Commands::Init => commands::init().await,
        Commands::Setup => commands::setup().await,
        Commands::Mcp => commands::mcp(&config).await,
        Commands::McpProxy(args) => commands::mcp_proxy(&config, *args).await,
        #[cfg(feature = "rag")]
        Commands::Tree { action } => commands::tree(&config, action).await,
        #[cfg(feature = "rag")]
        Commands::Vector { action } => commands::vector(action).await,
        Commands::Sessions { action } => commands::sessions(&config, action).await,
        #[cfg(feature = "certification")]
        Commands::Eval { .. } => unreachable!("handled above"),
        Commands::Manifest { .. }
        | Commands::Release { .. }
        | Commands::Anchor(_)
        | Commands::Action { .. }
        | Commands::Approve(_)
        | Commands::Approvals { .. }
        | Commands::Operations { .. }
        | Commands::Tools { .. }
        | Commands::Ledger { .. }
        | Commands::Verify(_)
        | Commands::Events { .. }
        | Commands::Infer(_)
        | Commands::Prove(_)
        | Commands::ProveStub(_) => unreachable!("handled above"),
        Commands::Scan { input, output, strategy, detect_only, min_confidence } => {
            commands::scan(&config, input, output, strategy, detect_only, min_confidence).await
        }
    }
}
