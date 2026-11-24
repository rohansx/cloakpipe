//! Where a `prove` run executes: a sandbox backend.
//!
//! The interface is small on purpose (start, copy files, run, collect,
//! destroy), folded into [`Sandbox::prepare`] and [`Sandbox::run`]. Every
//! backend sees the same absolute paths as the host: the run directory, the
//! agent directory and the `cloakpipe` binary are mounted or uploaded at
//! their host paths, so the gate command `prove` writes works unchanged.
//!
//! - `local`: a child process on this machine (no isolation; the default).
//! - `docker`: `docker run` per run, the directories bind-mounted.
//! - `e2b`: an E2B sandbox per run, started from a snapshot prepared once
//!   (binary, agent and its `setup` installed), driven by the `e2b` Python
//!   SDK (`pip install e2b`, `E2B_API_KEY`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// One run for a backend to execute.
pub struct Job {
    pub run_dir: PathBuf,
    pub agent_dir: PathBuf,
    pub command: Vec<String>,
    /// The only environment the agent gets besides the backend's basics.
    pub env: Vec<(String, String)>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Finished {
    pub exit: Option<i32>,
    pub timed_out: bool,
}

pub trait Sandbox: Sync {
    fn name(&self) -> &'static str;
    /// Once, before any run: build what every run starts from.
    fn prepare(&mut self, _agent_dir: &Path, _setup: Option<&str>) -> Result<(), String> {
        Ok(())
    }
    /// Run `job`; the agent's stdout and stderr go to `agent.out` / `agent.err`
    /// in the run directory, and the run directory comes back filled.
    fn run(&self, job: &Job) -> Result<Finished, String>;
    /// Once, after every run.
    fn finish(&mut self) {}
}

pub fn backend(name: &str, exe: &Path, image: Option<&str>, template: Option<&str>, scratch: &Path) -> Result<Box<dyn Sandbox>, String> {
    match name {
        "local" => Ok(Box::new(Local)),
        "docker" => Ok(Box::new(Docker { exe: exe.to_path_buf(), image: image.unwrap_or(DEFAULT_IMAGE).to_string() })),
        "e2b" => {
            if std::env::var_os("E2B_API_KEY").is_none() {
                return Err("--sandbox e2b needs E2B_API_KEY in the environment".into());
            }
            let runner = scratch.join("e2b_runner.py");
            std::fs::write(&runner, E2B_RUNNER).map_err(|e| format!("{}: {e}", runner.display()))?;
            Ok(Box::new(E2b { exe: exe.to_path_buf(), template: template.unwrap_or("base").to_string(), runner, snapshot: None }))
        }
        other => Err(format!("--sandbox {other}: expected local, docker or e2b")),
    }
}

/// glibc 2.41: runs a `cloakpipe` built on a current distribution.
pub const DEFAULT_IMAGE: &str = "python:3.12-slim-trixie";

struct Local;

impl Sandbox for Local {
    fn name(&self) -> &'static str {
        "local"
    }

    fn run(&self, job: &Job) -> Result<Finished, String> {
        let mut cmd = Command::new(&job.command[0]);
        cmd.args(&job.command[1..]).current_dir(&job.agent_dir).stdin(Stdio::null());
        // The user's own machine: their environment, minus any CloakPipe
        // settings that would point the gate elsewhere.
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("CLOAKPIPE_") {
                cmd.env_remove(k);
            }
        }
        cmd.envs(job.env.iter().map(|(k, v)| (k, v)));
        wait(spawn(cmd, &job.run_dir)?, job.timeout, || {})
    }
}

struct Docker {
    exe: PathBuf,
    image: String,
}

impl Sandbox for Docker {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn run(&self, job: &Job) -> Result<Finished, String> {
        for p in [&job.run_dir, &job.agent_dir, &self.exe] {
            if p.to_string_lossy().contains(':') {
                return Err(format!("--sandbox docker: {} contains ':', which a bind mount cannot carry", p.display()));
            }
        }
        let name = format!("cloakpipe-prove-{:016x}", rand::random::<u64>());
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "--init", "--name", &name]).stdin(Stdio::null());
        let mount = |p: &Path, ro: bool| format!("{}:{}{}", p.display(), p.display(), if ro { ":ro" } else { "" });
        cmd.arg("-v").arg(mount(&job.run_dir, false));
        cmd.arg("-v").arg(mount(&job.agent_dir, true));
        cmd.arg("-v").arg(mount(&self.exe, true));
        cmd.arg("-w").arg(&job.agent_dir);
        #[cfg(unix)]
        {
            // Files the run writes stay the user's.
            let (uid, gid) = ids(&job.run_dir);
            cmd.arg("--user").arg(format!("{uid}:{gid}"));
        }
        cmd.arg("-e").arg(format!("HOME={}", job.run_dir.join("home").display()));
        // By name only: values (API keys) never appear on a command line.
        for (k, v) in &job.env {
            cmd.arg("-e").arg(k).env(k, v);
        }
        cmd.arg(&self.image).args(&job.command);
        wait(spawn(cmd, &job.run_dir)?, job.timeout, || {
            let _ = Command::new("docker").args(["kill", &name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        })
    }
}

/// The owner of `dir`, which this process created: its uid and gid.
#[cfg(unix)]
fn ids(dir: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).map(|m| (m.uid(), m.gid())).unwrap_or((1000, 1000))
}

struct E2b {
    exe: PathBuf,
    template: String,
    runner: PathBuf,
    snapshot: Option<String>,
}

impl E2b {
    fn python(&self, mode: &str, spec: &serde_json::Value, log: &Path, timeout: Duration) -> Result<serde_json::Value, String> {
        let spec_path = log.with_extension("spec.json");
        std::fs::write(&spec_path, spec.to_string()).map_err(|e| e.to_string())?;
        let mut cmd = Command::new("python3");
        // -E, not -I: an e2b SDK installed with `pip install --user` stays importable.
        cmd.arg("-E").arg(&self.runner).arg(mode).arg(&spec_path).stdin(Stdio::null());
        let out_path = log.with_extension("result.json");
        cmd.env("CLOAKPIPE_E2B_RESULT", &out_path);
        let finished = wait(spawn_logged(cmd, log)?, timeout, || {})?;
        if finished.timed_out {
            return Err(format!("e2b {mode} timed out (see {})", log.display()));
        }
        let result = std::fs::read_to_string(&out_path).map_err(|_| format!("e2b {mode} failed (see {})", log.display()))?;
        serde_json::from_str(&result).map_err(|e| e.to_string())
    }
}

impl Sandbox for E2b {
    fn name(&self) -> &'static str {
        "e2b"
    }

    fn prepare(&mut self, agent_dir: &Path, setup: Option<&str>) -> Result<(), String> {
        let spec = serde_json::json!({
            "template": self.template,
            "exe": self.exe,
            "upload": [agent_dir],
            "setup": setup,
        });
        let log = self.runner.with_file_name("e2b-prepare.log");
        eprintln!("prove: preparing an E2B snapshot from template {} (binary, agent, setup)…", self.template);
        let r = self.python("prepare", &spec, &log, Duration::from_secs(1800)).map_err(|e| {
            // The usual cause: a binary linked against a newer glibc than the template's.
            let glibc = std::fs::read_to_string(&log).is_ok_and(|l| l.contains("GLIBC_"));
            if glibc { format!("{e}: {GLIBC_HINT}") } else { e }
        })?;
        let id = r.get("snapshot").and_then(|s| s.as_str()).ok_or_else(|| format!("e2b prepare: no snapshot id (see {})", log.display()))?;
        eprintln!("prove: E2B snapshot {id} ready");
        self.snapshot = Some(id.to_string());
        Ok(())
    }

    fn run(&self, job: &Job) -> Result<Finished, String> {
        let snapshot = self.snapshot.as_deref().ok_or("e2b: not prepared")?;
        let spec = serde_json::json!({
            "snapshot": snapshot,
            "run_dir": job.run_dir,
            "cwd": job.agent_dir,
            "command": job.command,
            "env": job.env.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
            "timeout": job.timeout.as_secs(),
        });
        let log = job.run_dir.join("e2b.log");
        let r = self.python("run", &spec, &log, job.timeout + Duration::from_secs(300))?;
        Ok(Finished {
            exit: r.get("exit").and_then(serde_json::Value::as_i64).map(|c| c as i32),
            timed_out: r.get("timed_out").and_then(serde_json::Value::as_bool).unwrap_or(false),
        })
    }

    fn finish(&mut self) {
        if let Some(id) = self.snapshot.take() {
            let log = self.runner.with_file_name("e2b-cleanup.log");
            if let Err(e) = self.python("cleanup", &serde_json::json!({ "snapshot": id }), &log, Duration::from_secs(120)) {
                eprintln!("prove: could not delete E2B snapshot {id}: {e}");
            }
        }
    }
}

/// What to do when the sandbox's Linux cannot run this binary.
const GLIBC_HINT: &str = "the sandbox cannot run this cloakpipe binary (it needs a newer glibc). Build a static one and pass it: \
rustup target add x86_64-unknown-linux-musl && cargo build --release -p cloakpipe-cli --target x86_64-unknown-linux-musl, \
then --cloakpipe-bin target/x86_64-unknown-linux-musl/release/cloakpipe";

const E2B_RUNNER: &str = include_str!("e2b_runner.py");

fn spawn(mut cmd: Command, run_dir: &Path) -> Result<Child, String> {
    let out = std::fs::File::create(run_dir.join("agent.out")).map_err(|e| e.to_string())?;
    let err = std::fs::File::create(run_dir.join("agent.err")).map_err(|e| e.to_string())?;
    cmd.stdout(out).stderr(err);
    group(&mut cmd);
    cmd.spawn().map_err(|e| format!("cannot start {:?}: {e}", cmd.get_program()))
}

fn spawn_logged(mut cmd: Command, log: &Path) -> Result<Child, String> {
    let f = std::fs::File::create(log).map_err(|e| e.to_string())?;
    let g = f.try_clone().map_err(|e| e.to_string())?;
    cmd.stdout(f).stderr(g);
    group(&mut cmd);
    cmd.spawn().map_err(|e| format!("cannot start {:?}: {e}", cmd.get_program()))
}

/// Its own process group, so a timeout takes down everything it started.
fn group(cmd: &mut Command) {
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(cmd, 0);
    #[cfg(not(unix))]
    let _ = cmd;
}

/// Wait for `child`; whatever happens, take down its whole process group
/// afterwards, so nothing it started (the gate chain, stubs) outlives the run.
fn wait(mut child: Child, timeout: Duration, on_timeout: impl Fn()) -> Result<Finished, String> {
    let start = Instant::now();
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(Finished { exit: status.code(), timed_out: false }),
            Err(e) => break Err(e.to_string()),
            Ok(None) if start.elapsed() > timeout => {
                on_timeout();
                break Ok(Finished { exit: None, timed_out: true });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    kill_group(&mut child);
    result
}

fn kill_group(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill").args(["-KILL", "--", &format!("-{}", child.id())]).stderr(Stdio::null()).status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Write `text` to `path`, creating parents.
pub fn write(path: &Path, text: &str) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    std::fs::File::create(path).and_then(|mut f| f.write_all(text.as_bytes())).map_err(|e| format!("{}: {e}", path.display()))
}
