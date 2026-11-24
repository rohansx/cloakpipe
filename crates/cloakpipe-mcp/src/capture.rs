//! Opt-in local capture of tool calls, the input to `cloakpipe infer`.
//!
//! The decision ledger never stores argument values, so it cannot be used
//! to draft a contract. A capture can: with `mcp-proxy --capture <dir>` the
//! interceptor appends every `tools/call` (raw arguments, before any PII
//! transform), every `tools/list` reply and the trusted task context to a
//! JSONL file in `<dir>`. It is:
//!
//! - **opt-in and shadow-only**: the CLI accepts it only in shadow mode or
//!   without a gate;
//! - **local**: written owner-only (`0700` directory, `0600` files), never
//!   sent anywhere and never part of an audit pack;
//! - **short-lived**: [`prune`] deletes files older than N days
//!   (`--capture-max-age`), and `infer --delete-after` deletes what it read;
//! - **reducible**: with [`Capture::open`]'s `shapes`, every string (in
//!   arguments and in the task context) is replaced by its shape: length,
//!   a pattern class and a salted hash. Equal strings still hash equal, so a
//!   value can be matched to the task context without being stored.
//!
//! Capture is best effort: a write failure is logged and never changes a
//! decision or delays a call beyond the write itself.
//!
//! One file per proxy run (one task context). Records, one per line:
//!
//! ```text
//! {"v":1,"kind":"session","ts":…,"shapes":false,"task":{…}|null}
//! {"v":1,"kind":"tools","ts":…,"tools":[{"name":…,"inputSchema":…},…]}
//! {"v":1,"kind":"call","ts":…,"tool":…,"args":{…}|null}
//! ```

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// The capture record format version.
pub const CAPTURE_VERSION: u64 = 1;
/// The member that marks a string replaced by its shape.
pub const SHAPE_KEY: &str = "$shape";
const SALT_FILE: &str = ".capture-salt";
const PREFIX: &str = "capture-";

/// An open capture file.
pub struct Capture {
    out: Mutex<BufWriter<File>>,
    path: PathBuf,
    /// The salt strings are hashed with; `None`: raw values are kept.
    salt: Option<[u8; 32]>,
}

impl Capture {
    /// Create a new capture file in `dir` (created owner-only if needed) and
    /// record the session: its trusted task context and whether strings are
    /// reduced to shapes.
    pub fn open(dir: &Path, task: Option<&Value>, shapes: bool) -> std::io::Result<Self> {
        create_private_dir(dir)?;
        let salt = if shapes { Some(load_salt(dir)?) } else { None };
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
        // Two proxies started in the same millisecond still get two files.
        let path = dir.join(format!("{PREFIX}{stamp}-{}-{:08x}.jsonl", std::process::id(), rand::random::<u32>()));
        let file = private_file(&path)?;
        let capture = Self { out: Mutex::new(BufWriter::new(file)), path, salt };
        let task = task.map(|t| capture.reduce(t));
        capture.write(json!({ "kind": "session", "shapes": shapes, "task": task }))?;
        Ok(capture)
    }

    /// The file being written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one `tools/call` with its raw arguments.
    pub fn call(&self, tool: &str, args: Option<&Value>) {
        let args = args.map(|a| self.reduce(a));
        self.record(json!({ "kind": "call", "tool": tool, "args": args }));
    }

    /// Record a `tools/list` reply: each tool's name and input schema.
    pub fn tools(&self, tools: &[Value]) {
        let listed: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let name = t.get("name")?.as_str()?;
                Some(json!({ "name": name, "inputSchema": t.get("inputSchema").cloned().unwrap_or(Value::Null) }))
            })
            .collect();
        self.record(json!({ "kind": "tools", "tools": listed }));
    }

    fn record(&self, v: Value) {
        if let Err(e) = self.write(v) {
            tracing::warn!(path = %self.path.display(), "capture: could not write a record: {e}");
        }
    }

    fn write(&self, mut v: Value) -> std::io::Result<()> {
        v["v"] = json!(CAPTURE_VERSION);
        v["ts"] = json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        let mut out = self.out.lock().map_err(|_| std::io::Error::other("capture lock poisoned"))?;
        serde_json::to_writer(&mut *out, &v)?;
        out.write_all(b"\n")?;
        out.flush()
    }

    /// `v` as it is stored: unchanged, or with every string reduced to its shape.
    fn reduce(&self, v: &Value) -> Value {
        match &self.salt {
            None => v.clone(),
            Some(salt) => shape_value(v, salt),
        }
    }
}

/// Every string in `v` replaced by its shape.
fn shape_value(v: &Value, salt: &[u8; 32]) -> Value {
    match v {
        Value::String(s) => shape(s, salt),
        Value::Array(a) => Value::Array(a.iter().map(|x| shape_value(x, salt)).collect()),
        // A `$shape` member the agent sent is renamed, so it can never pass
        // for a shape this capture wrote.
        Value::Object(o) => Value::Object(
            o.iter().map(|(k, x)| (if k == SHAPE_KEY { format!("{SHAPE_KEY}_") } else { k.clone() }, shape_value(x, salt))).collect::<Map<_, _>>(),
        ),
        other => other.clone(),
    }
}

/// A string's shape: `{"$shape": {"len", "class", "h", "prefix"?}}`.
pub fn shape(s: &str, salt: &[u8; 32]) -> Value {
    let class = classify(s);
    let mut shape = json!({ "len": s.chars().count(), "class": class, "h": hash(s, salt) });
    if class == "id" {
        shape["prefix"] = json!(id_prefix(s));
    }
    json!({ SHAPE_KEY: shape })
}

/// The pattern class of a string: `email`, `url`, `uuid`, `digits`, `id`
/// (letters then digits, such as `T-1042`), `text` (has whitespace) or
/// `token`.
pub fn classify(s: &str) -> &'static str {
    let ascii_word = |c: char| c.is_ascii_alphanumeric() || "._%+-".contains(c);
    if let Some((local, domain)) = s.split_once('@') {
        if !local.is_empty() && local.chars().all(ascii_word) && domain.contains('.') && domain.chars().all(ascii_word) {
            return "email";
        }
    }
    if (s.starts_with("https://") || s.starts_with("http://")) && !s.contains(char::is_whitespace) {
        return "url";
    }
    let b = s.as_bytes();
    if b.len() == 36 && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-') && s.chars().filter(|c| *c != '-').all(|c| c.is_ascii_hexdigit()) {
        return "uuid";
    }
    if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) {
        return "digits";
    }
    if !id_prefix(s).is_empty() && s.len() <= 40 {
        return "id";
    }
    if s.contains(char::is_whitespace) {
        return "text";
    }
    "token"
}

/// `T-` of `T-1042`: one to eight ASCII letters, an optional `-` or `_`,
/// then only digits (at least one). Empty for anything else.
pub fn id_prefix(s: &str) -> &str {
    let letters = s.bytes().take_while(u8::is_ascii_alphabetic).count();
    if letters == 0 || letters > 8 {
        return "";
    }
    let sep = usize::from(matches!(s.as_bytes().get(letters), Some(b'-' | b'_')));
    let rest = &s[letters + sep..];
    if rest.is_empty() || !rest.bytes().all(|c| c.is_ascii_digit()) {
        return "";
    }
    &s[..letters + sep]
}

fn hash(s: &str, salt: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(s.as_bytes());
    let d = h.finalize();
    d[..12].iter().map(|b| format!("{b:02x}")).collect()
}

/// The capture directory's salt, created on first use (owner-only).
fn load_salt(dir: &Path) -> std::io::Result<[u8; 32]> {
    let path = dir.join(SALT_FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let mut salt = [0u8; 32];
            let bytes = s.trim().as_bytes();
            if bytes.len() != 64 {
                return Err(std::io::Error::other(format!("{}: not a 32-byte hex salt", path.display())));
            }
            for (i, out) in salt.iter_mut().enumerate() {
                let pair = std::str::from_utf8(&bytes[2 * i..2 * i + 2]).map_err(std::io::Error::other)?;
                *out = u8::from_str_radix(pair, 16).map_err(std::io::Error::other)?;
            }
            Ok(salt)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Written whole under a temporary name, then linked into place:
            // a proxy starting at the same moment either wins or reads ours.
            let salt: [u8; 32] = rand::random();
            let tmp = dir.join(format!("{SALT_FILE}.{:016x}", rand::random::<u64>()));
            private_file(&tmp)?.write_all(salt.iter().map(|b| format!("{b:02x}")).collect::<String>().as_bytes())?;
            let linked = std::fs::hard_link(&tmp, &path);
            std::fs::remove_file(&tmp)?;
            match linked {
                Ok(()) => Ok(salt),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => load_salt(dir),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// The capture files in `dir`, oldest first.
pub fn files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(PREFIX) && n.ends_with(".jsonl")))
        .collect();
    out.sort();
    Ok(out)
}

/// Delete the capture files in `dir` last written more than `max_age` ago.
/// Returns how many were deleted.
pub fn prune(dir: &Path, max_age: Duration) -> std::io::Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let cutoff = SystemTime::now().checked_sub(max_age).unwrap_or(SystemTime::UNIX_EPOCH);
    let mut n = 0;
    for path in files(dir)? {
        if std::fs::metadata(&path)?.modified()? < cutoff {
            std::fs::remove_file(&path)?;
            n += 1;
        }
    }
    Ok(n)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

fn private_file(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        assert_eq!(classify("dana@customer.example"), "email");
        assert_eq!(classify("https://x.example/a"), "url");
        assert_eq!(classify("123e4567-e89b-12d3-a456-426614174000"), "uuid");
        assert_eq!(classify("4211"), "digits");
        assert_eq!(classify("T-1042"), "id");
        assert_eq!(id_prefix("T-1042"), "T-");
        assert_eq!(id_prefix("op_77"), "op_");
        assert_eq!(id_prefix("T-10a"), "");
        assert_eq!(classify("Your refund is on its way."), "text");
        assert_eq!(classify("abc"), "token");
    }

    #[test]
    fn shapes_hide_values_but_keep_equality() {
        let dir = tempfile::tempdir().unwrap();
        let task = json!({ "ticket": { "customer_email": "dana@customer.example" } });
        let c = Capture::open(dir.path(), Some(&task), true).unwrap();
        c.call("send_email", Some(&json!({ "to": "dana@customer.example", "n": 3 })));
        drop(c);
        let file = files(dir.path()).unwrap().remove(0);
        let text = std::fs::read_to_string(file).unwrap();
        assert!(!text.contains("dana"), "{text}");
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let in_task = &lines[0]["task"]["ticket"]["customer_email"][SHAPE_KEY]["h"];
        let in_call = &lines[1]["args"]["to"][SHAPE_KEY]["h"];
        assert_eq!(in_task, in_call);
        assert_eq!(lines[1]["args"]["n"], json!(3));
        // The same salt on the next run: the same hashes.
        let again = Capture::open(dir.path(), Some(&task), true).unwrap();
        let text = std::fs::read_to_string(again.path()).unwrap();
        assert!(text.contains(in_task.as_str().unwrap()));
    }

    #[test]
    fn prune_deletes_old_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let c = Capture::open(dir.path(), None, false).unwrap();
        assert_eq!(prune(dir.path(), Duration::from_secs(3600)).unwrap(), 0);
        assert!(c.path().exists());
        assert_eq!(prune(dir.path(), Duration::ZERO).unwrap(), 1);
        assert!(files(dir.path()).unwrap().is_empty());
    }
}
