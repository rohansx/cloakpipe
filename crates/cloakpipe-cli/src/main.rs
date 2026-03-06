//! CloakPipe CLI — entrypoint for the privacy proxy.

mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cloakpipe")]
#[command(about = "Privacy middleware for LLM & RAG pipelines")]
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
    /// CloakTree: vectorless document retrieval
    Tree {
        #[command(subcommand)]
        action: TreeCommands,
    },
    /// ADCPE: encrypt/decrypt embedding vectors
    Vector {
        #[command(subcommand)]
        action: VectorCommands,
    },
}

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloakpipe=info,tower_http=info".into()),
        )
        .init();

    match cli.command {
        Commands::Start => commands::start(&cli.config).await,
        Commands::Test { text, file } => commands::test(&cli.config, text, file).await,
        Commands::Stats => commands::stats(&cli.config).await,
        Commands::Init => commands::init().await,
        Commands::Tree { action } => commands::tree(&cli.config, action).await,
        Commands::Vector { action } => commands::vector(action).await,
    }
}
