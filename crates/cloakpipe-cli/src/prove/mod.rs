//! `cloakpipe prove`: run a live agent through an attack pack with the gate
//! in shadow mode and in enforce mode, and report which attacks reached the
//! tools, which were refused (and why), and whether normal work still
//! completes.
//!
//! ```text
//! cloakpipe prove --agent agent.yaml --contract cloakpipe.manifest.yaml \
//!     --pack support-basics --runs 5 --sandbox local|docker|e2b [--parallel N]
//! ```
//!
//! Each scenario runs `--runs` times per mode, every run in a fresh
//! directory (and, with docker or e2b, a fresh sandbox) holding the gate,
//! stub tool servers and the run's records. Agents are not deterministic, so
//! results are rates. The agent is any program (`agent.yaml`, see
//! [`Agent`]); it finds its MCP server in `$CLOAKPIPE_PROVE_MCP_CONFIG` (or
//! the command in `$CLOAKPIPE_PROVE_GATE`) and its task in
//! `$CLOAKPIPE_PROVE_PROMPT` / `$CLOAKPIPE_PROVE_TASK`.
//!
//! Exit codes: 0 every attack held and the control passed, 1 the report
//! failed (an attack reached a tool in enforce mode, false refusals above
//! `--max-false-refusal-rate`, or the agent never ran), 2 usage or I/O error.

mod pack;
mod report;
mod run;
mod sandbox;
pub mod stub;

use crate::keys::{invalid, usage, Res};
use crate::release::{EXIT_INVALID, EXIT_OK};
use clap::Args;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use run::Mode;

#[derive(Debug, Args)]
pub struct ProveArgs {
    /// The agent to prove (agent.yaml: command, env, pass_env, timeout, setup, image, template)
    #[arg(long)]
    pub agent: PathBuf,
    /// The contract the gate runs (a cloakpipe.manifest.yaml)
    #[arg(long)]
    pub contract: PathBuf,
    /// A built-in attack pack (support-basics, support-injection) or a pack file
    #[arg(long, default_value = "support-basics")]
    pub pack: String,
    /// Runs per scenario and mode
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u64).range(1..=1000))]
    pub runs: u64,
    /// Where runs execute: local (child processes), docker or e2b
    #[arg(long, default_value = "local", value_parser = ["local", "docker", "e2b"])]
    pub sandbox: String,
    /// Runs at once
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=500))]
    pub parallel: u64,
    /// Only these scenarios (repeatable)
    #[arg(long = "scenario", value_name = "ID")]
    pub scenarios: Vec<String>,
    /// Report directory: report.json, report.html and every run's records
    #[arg(long, default_value = "prove-report")]
    pub out: PathBuf,
    /// Fail when more than this share of control runs had a refusal
    #[arg(long, default_value_t = 0.0)]
    pub max_false_refusal_rate: f64,
    /// The cloakpipe binary the sandbox runs (default: this one). For docker
    /// or e2b it must run on the image's Linux.
    #[arg(long = "cloakpipe-bin")]
    pub cloakpipe_bin: Option<PathBuf>,
    /// Print the report as JSON instead of the summary table
    #[arg(long)]
    pub json: bool,
}

/// The agent under test (`agent.yaml`).
#[derive(Debug, Clone)]
pub struct Agent {
    pub name: String,
    /// The agent.yaml's directory: the working directory of every run.
    pub dir: PathBuf,
    pub command: Vec<String>,
    /// Literal environment.
    pub env: BTreeMap<String, String>,
    /// Variables passed through from this environment (model API keys).
    pub pass_env: Vec<String>,
    pub timeout: Duration,
    /// e2b: run once in the snapshot (e.g. `pip install -r requirements.txt`).
    pub setup: Option<String>,
    pub image: Option<String>,
    pub template: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    name: Option<String>,
    command: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    pass_env: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout: u64,
    setup: Option<String>,
    image: Option<String>,
    template: Option<String>,
}

fn default_timeout() -> u64 {
    180
}

fn load_agent(path: &Path) -> Res<Agent> {
    let src = std::fs::read_to_string(path).map_err(|e| usage(format_args!("--agent {}: {e}", path.display())))?;
    let raw: RawAgent = serde_yaml::from_str(&src).map_err(|e| invalid(format_args!("--agent {}: {e}", path.display())))?;
    if raw.command.is_empty() {
        return Err(invalid(format_args!("--agent {}: command is empty", path.display())));
    }
    let dir = std::fs::canonicalize(path).map_err(|e| usage(format_args!("--agent {}: {e}", path.display())))?;
    let dir = dir.parent().unwrap_or(Path::new("/")).to_path_buf();
    Ok(Agent {
        name: raw.name.unwrap_or_else(|| dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
        dir,
        command: raw.command,
        env: raw.env,
        pass_env: raw.pass_env,
        timeout: Duration::from_secs(raw.timeout.max(1)),
        setup: raw.setup,
        image: raw.image,
        template: raw.template,
    })
}

pub fn run(a: ProveArgs) -> i32 {
    crate::keys::finish(run_inner(&a))
}

fn run_inner(a: &ProveArgs) -> Res<i32> {
    let agent = load_agent(&a.agent)?;
    let mut pack = pack::load(&a.pack).map_err(usage)?;
    if !a.scenarios.is_empty() {
        if let Some(id) = a.scenarios.iter().find(|id| !pack.scenarios.iter().any(|s| &s.id == *id)) {
            return Err(usage(format_args!("--scenario {id}: not in pack {}", pack.name)));
        }
        pack.scenarios.retain(|s| a.scenarios.contains(&s.id));
    }
    let contract = std::fs::canonicalize(&a.contract).map_err(|e| usage(format_args!("--contract {}: {e}", a.contract.display())))?;
    let manifest = cloakpipe_release::v1::Manifest::parse_path(&contract).map_err(|e| invalid(format_args!("--contract: {e}")))?;
    let policy = manifest.policy.as_ref().map(|p| p.declared.clone());
    if policy.as_deref().is_some_and(|p| Path::new(p).is_absolute() || p.split(['/', '\\']).any(|c| c == "..")) {
        return Err(usage("--contract: prove copies the contract with its policy, which must be a relative path inside the contract's directory"));
    }
    let exe = match &a.cloakpipe_bin {
        Some(p) => std::fs::canonicalize(p).map_err(|e| usage(format_args!("--cloakpipe-bin {}: {e}", p.display())))?,
        None => std::env::current_exe().map_err(|e| usage(format_args!("cannot find this binary: {e}")))?,
    };
    std::fs::create_dir_all(&a.out).map_err(|e| usage(format_args!("--out {}: {e}", a.out.display())))?;
    let out = std::fs::canonicalize(&a.out).map_err(|e| usage(format_args!("--out: {e}")))?;
    let runs_dir = out.join("runs");
    // Only ever delete a runs directory an earlier prove wrote.
    if runs_dir.exists() {
        if !runs_dir.join(MARKER).exists() {
            return Err(usage(format_args!("{} exists and was not written by cloakpipe prove: choose another --out", runs_dir.display())));
        }
        std::fs::remove_dir_all(&runs_dir).map_err(|e| usage(format_args!("{}: {e}", runs_dir.display())))?;
    }
    sandbox::write(&runs_dir.join(MARKER), "written by cloakpipe prove; deleted and rewritten on the next run\n").map_err(usage)?;
    let private = out.join(".private");
    create_private_dir(&private).map_err(|e| usage(format_args!("{}: {e}", private.display())))?;

    let mut sandbox = sandbox::backend(&a.sandbox, &exe, agent.image.as_deref(), agent.template.as_deref(), &out).map_err(usage)?;
    sandbox.prepare(&agent.dir, agent.setup.as_deref()).map_err(invalid)?;
    let setup = run::Setup { exe: &exe, contract: &contract, policy: policy.as_deref(), agent: &agent, pack: &pack, private: &private };

    let mut jobs = Vec::new();
    for s in &pack.scenarios {
        for mode in [Mode::Shadow, Mode::Enforce] {
            for n in 1..=a.runs as usize {
                jobs.push((s, mode, n));
            }
        }
    }
    let total = jobs.len();
    eprintln!("prove: {} scenario(s) × 2 modes × {} run(s) = {total} runs on {} ({} at once)", pack.scenarios.len(), a.runs, sandbox.name(), a.parallel);
    let started = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let clock = Instant::now();
    let queue = Mutex::new(jobs.into_iter().enumerate().collect::<Vec<_>>());
    let results = Mutex::new(Vec::with_capacity(total));
    let sb: &dyn sandbox::Sandbox = sandbox.as_ref();
    std::thread::scope(|scope| {
        for _ in 0..(a.parallel as usize).min(total.max(1)) {
            // Not `while let`: its guard would live for the whole body and
            // serialize the workers.
            #[allow(clippy::while_let_loop)]
            scope.spawn(|| loop {
                let Some((i, (scenario, mode, n))) = queue.lock().ok().and_then(|mut q| q.pop()) else { break };
                let dir = runs_dir.join(&scenario.id).join(format!("{}-{n}", mode.as_str()));
                let finished = run::prepare(&setup, scenario, mode, &dir).and_then(|job| sb.run(&job));
                let outcome = run::measure(scenario, mode, n, &dir, finished, &exe);
                eprintln!(
                    "prove: [{}/{total}] {} {} #{n}: {}",
                    total - i,
                    scenario.id,
                    mode.as_str(),
                    summary(&outcome)
                );
                if let Ok(mut r) = results.lock() {
                    r.push(outcome);
                }
            });
        }
    });
    sandbox.finish();
    let mut outcomes = results.into_inner().unwrap_or_default();
    outcomes.sort_by(|x, y| (&x.scenario, x.mode as u8, x.run).cmp(&(&y.scenario, y.mode as u8, y.run)));

    let meta = report::Meta {
        agent: &agent.name,
        contract: &a.contract.display().to_string(),
        contract_digest: manifest.digest().to_string(),
        sandbox: sandbox.name(),
        runs: a.runs as usize,
        started,
        seconds: clock.elapsed().as_secs_f64(),
    };
    let r = report::build(&pack, &outcomes, &meta, &report::Thresholds { max_false_refusal_rate: a.max_false_refusal_rate });
    let json_path = out.join("report.json");
    sandbox::write(&json_path, &serde_json::to_string_pretty(&r).unwrap_or_default()).map_err(usage)?;
    sandbox::write(&out.join("report.html"), &report::html(&r)).map_err(usage)?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    } else {
        print!("{}", report::text(&r));
    }
    let _ = std::fs::remove_dir_all(&private);
    eprintln!("prove: report in {} (report.html, report.json)", out.display());
    Ok(if r["ok"] == true { EXIT_OK } else { EXIT_INVALID })
}

/// Marks a runs directory as prove's own.
const MARKER: &str = ".cloakpipe-prove";

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

fn summary(o: &run::Outcome) -> String {
    let mut s = if o.ok { String::from("agent ok") } else { format!("agent failed ({})", o.error.clone().unwrap_or_else(|| format!("{:?}", o.finished))) };
    if o.attempted {
        s.push_str(", attempted");
    }
    if o.reached {
        s.push_str(", REACHED the tool");
    }
    if o.completed {
        s.push_str(", completed");
    }
    if !o.refusals.is_empty() {
        s.push_str(&format!(", refused: {}", o.refusals.keys().cloned().collect::<Vec<_>>().join(",")));
    }
    s
}
