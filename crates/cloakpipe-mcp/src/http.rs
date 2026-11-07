//! MCP over HTTP: the Streamable HTTP transport (MCP spec rev 2025-06-18),
//! on both sides of the gate. The decisions are the [`Interceptor`]'s, the
//! same as over stdio: this module only moves messages.
//!
//! **Agent side** ([`serve`], `mcp-proxy --listen ADDR`):
//!
//! - `POST /mcp` takes one JSON-RPC message. A request is answered with one
//!   `application/json` response (no SSE response streams); a notification
//!   or a response is accepted with `202`.
//! - `initialize` issues an `Mcp-Session-Id`; every other message must carry
//!   a live one (`400` without, `404` for an unknown or ended session).
//!   `DELETE /mcp` ends a session. `GET /mcp` is `405`: there is no
//!   server-to-client stream, so upstream notifications and requests that
//!   answer no agent request (progress, logging, `list_changed`) are dropped.
//! - `GET /health` reports the release name and digest (no token needed).
//! - An `Origin` header must be a loopback origin or the listener's own
//!   (against DNS rebinding). With a listen token, every `/mcp` request
//!   needs `Authorization: Bearer <token>`.
//! - Each agent request is forwarded under an id unique to this gate, so
//!   sessions sharing the upstream never collide, and its reply finds its
//!   way back; the agent sees its own id.
//!
//! **Upstream side** ([`UpstreamTransport::Http`], `mcp-proxy --upstream-url`):
//! the gate is a Streamable HTTP client. Each message is POSTed with the
//! configured headers, `Accept: application/json, text/event-stream`, and,
//! after `initialize`, the server's `Mcp-Session-Id` and the negotiated
//! `MCP-Protocol-Version`. The reply comes back as JSON or as an SSE stream
//! (each event relayed, until the reply). Requests run concurrently, except
//! `initialize`, which completes before anything after it is sent.
//!
//! **Fail closed:** a request whose transport fails (connection refused, an
//! HTTP error status, a stream that ends without the reply) is answered by
//! [`Interceptor::on_upstream_error`]: `upstream_unavailable`, or for a
//! side-effecting call, `unknown` until reconciled, recorded in the ledger.

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::proxy::{flush_events, write_line, Action, Interceptor, ProxyContext, Upstream, UpstreamTransport, DEFAULT_SERVER, EVENT_FLUSH, UPSTREAM_UNAVAILABLE};
use crate::servers::{StdioServer, DISCOVERY_TIMEOUT};
use crate::tools_lock::ToolsLock;

/// The session header (both sides).
const SESSION: &str = "mcp-session-id";
/// The negotiated protocol version, sent after `initialize` (client side).
const PROTOCOL_VERSION: &str = "mcp-protocol-version";
/// How long one upstream exchange may take, SSE stream included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// What an upstream connection hands back.
pub(crate) enum Incoming {
    /// One JSON-RPC message from the upstream (one line).
    Message(String),
    /// A message this gate sent was not delivered or got no reply.
    Failed { message: String, error: String },
}

type Deliver = Arc<dyn Fn(Incoming) + Send + Sync>;

// ── upstream side: the Streamable HTTP client ───────────────────────────

/// The gate as the HTTP client of an upstream MCP server. Owns a small
/// runtime, so it works from plain threads and from inside the CLI's.
pub(crate) struct HttpClient {
    queue: tokio::sync::mpsc::UnboundedSender<String>,
    shared: Arc<ClientShared>,
    runtime: Option<tokio::runtime::Runtime>,
}

struct ClientShared {
    client: reqwest::Client,
    url: String,
    headers: reqwest::header::HeaderMap,
    session: Mutex<Option<String>>,
    protocol: Mutex<Option<String>>,
    /// Messages handed to [`HttpClient::send`] and not yet settled.
    busy: AtomicUsize,
    deliver: Deliver,
}

impl HttpClient {
    pub(crate) fn start(url: &str, headers: &[(String, String)], deliver: Deliver) -> Result<Self> {
        let mut map = reqwest::header::HeaderMap::new();
        for (name, value) in headers {
            let name = reqwest::header::HeaderName::from_bytes(name.as_bytes()).with_context(|| format!("upstream header name {name:?}"))?;
            // The value is a credential, often: never in an error message.
            let mut value = reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| anyhow::anyhow!("upstream header {name}: the value is not a valid header value"))?;
            value.set_sensitive(true);
            map.append(name, value);
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building the upstream HTTP client")?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("cloakpipe-upstream-http")
            .enable_all()
            .build()
            .context("starting the upstream HTTP runtime")?;
        let shared = Arc::new(ClientShared {
            client,
            url: url.to_string(),
            headers: map,
            session: Mutex::new(None),
            protocol: Mutex::new(None),
            busy: AtomicUsize::new(0),
            deliver,
        });
        let (queue, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        {
            let shared = shared.clone();
            runtime.spawn(async move {
                while let Some(message) = rx.recv().await {
                    let parsed: Option<Value> = serde_json::from_str(&message).ok();
                    let method = parsed.as_ref().and_then(|v| v.get("method")).and_then(Value::as_str);
                    let request = parsed.as_ref().and_then(|v| v.get("id")).is_some_and(|id| !id.is_null()) && method.is_some();
                    if request && method != Some("initialize") {
                        // A slow tool must not hold up the next call.
                        let shared = shared.clone();
                        tokio::spawn(async move { shared.exchange(message).await });
                    } else {
                        // `initialize` sets the session everything after it
                        // carries; notifications keep their order.
                        shared.exchange(message).await;
                    }
                }
            });
        }
        Ok(Self { queue, shared, runtime: Some(runtime) })
    }

    /// Send one message; its reply (or failure) comes back through `deliver`.
    pub(crate) fn send(&self, message: String) {
        self.shared.busy.fetch_add(1, Ordering::SeqCst);
        if let Err(e) = self.queue.send(message) {
            self.shared.busy.fetch_sub(1, Ordering::SeqCst);
            (self.shared.deliver)(Incoming::Failed { message: e.0, error: "the upstream client has stopped".into() });
        }
    }

    /// Wait for every message sent to settle, end the upstream session
    /// (best effort) and stop.
    pub(crate) fn close(mut self) {
        while self.shared.busy.load(Ordering::SeqCst) > 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Some(runtime) = self.runtime.take() {
            let session = self.shared.session.lock().ok().and_then(|s| s.clone());
            if let Some(session) = session {
                let shared = self.shared.clone();
                let ended = runtime.block_on(async move {
                    let req = shared.client.delete(&shared.url).headers(shared.headers.clone()).header(SESSION, session);
                    tokio::time::timeout(Duration::from_secs(5), req.send()).await
                });
                if !matches!(ended, Ok(Ok(_))) {
                    tracing::debug!("upstream session not ended (DELETE failed); it will expire");
                }
            }
            runtime.shutdown_background();
        }
    }
}

impl ClientShared {
    /// POST one message and relay what comes back.
    async fn exchange(&self, message: String) {
        if let Err(error) = self.post(&message).await {
            (self.deliver)(Incoming::Failed { message, error });
        }
        self.busy.fetch_sub(1, Ordering::SeqCst);
    }

    async fn post(&self, message: &str) -> Result<(), String> {
        let parsed: Option<Value> = serde_json::from_str(message).ok();
        let method = parsed.as_ref().and_then(|v| v.get("method")).and_then(Value::as_str);
        let initialize = method == Some("initialize");
        // The reply this message waits for, if it is a request.
        let expected = parsed.as_ref().and_then(|v| v.get("id")).filter(|id| !id.is_null() && method.is_some()).cloned();

        let mut req = self
            .client
            .post(&self.url)
            .headers(self.headers.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
            .body(message.to_string());
        if !initialize {
            if let Some(session) = self.session.lock().ok().and_then(|s| s.clone()) {
                req = req.header(SESSION, session);
            }
            if let Some(version) = self.protocol.lock().ok().and_then(|s| s.clone()) {
                req = req.header(PROTOCOL_VERSION, version);
            }
        }
        let resp = req.send().await.map_err(|e| format!("POST failed: {}", without_url(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        if initialize {
            if let Some(session) = resp.headers().get(SESSION).and_then(|v| v.to_str().ok()) {
                if let Ok(mut s) = self.session.lock() {
                    *s = Some(session.to_string());
                }
            }
        }
        let sse = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.trim_start().to_ascii_lowercase().starts_with("text/event-stream"));
        let mut answered = false;
        if sse {
            let mut resp = resp;
            let mut events = SseParser::default();
            'stream: while let Some(chunk) = resp.chunk().await.map_err(|e| format!("reading the event stream: {}", without_url(&e)))? {
                for data in events.feed(&chunk) {
                    answered |= self.relay(&data, expected.as_ref(), initialize);
                    if answered {
                        // The reply is in: the rest of the stream is not waited for.
                        break 'stream;
                    }
                }
            }
        } else if status != reqwest::StatusCode::ACCEPTED {
            let body = resp.bytes().await.map_err(|e| format!("reading the response: {}", without_url(&e)))?;
            if !body.iter().all(u8::is_ascii_whitespace) {
                let text = String::from_utf8_lossy(&body);
                match serde_json::from_str::<Value>(&text) {
                    Ok(Value::Array(batch)) => {
                        for msg in batch {
                            answered |= self.relay(&msg.to_string(), expected.as_ref(), initialize);
                        }
                    }
                    Ok(msg) => answered |= self.relay(&msg.to_string(), expected.as_ref(), initialize),
                    Err(_) => return Err("the response is not JSON".into()),
                }
            }
        }
        if expected.is_some() && !answered {
            return Err(format!("HTTP {status} without a response to the request"));
        }
        Ok(())
    }

    /// Hand one upstream message on; whether it is the reply to `expected`.
    fn relay(&self, data: &str, expected: Option<&Value>, initialize: bool) -> bool {
        let Ok(msg) = serde_json::from_str::<Value>(data) else {
            tracing::warn!("upstream sent an event that is not JSON; dropped");
            return false;
        };
        let reply = msg.get("method").is_none() && (msg.get("result").is_some() || msg.get("error").is_some());
        let answers = reply && expected.is_some_and(|id| msg.get("id") == Some(id));
        if answers && initialize {
            if let Some(version) = msg.pointer("/result/protocolVersion").and_then(Value::as_str) {
                if let Ok(mut p) = self.protocol.lock() {
                    *p = Some(version.to_string());
                }
            }
        }
        (self.deliver)(Incoming::Message(msg.to_string()));
        answers
    }
}

/// What went wrong, by kind: never the URL (it may carry credentials).
fn without_url(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else if e.is_body() || e.is_decode() {
        "the body could not be read"
    } else {
        "request error"
    }
}

/// Server-sent events, fed in chunks: each complete event's `data`.
#[derive(Default)]
struct SseParser {
    buf: Vec<u8>,
    data: Vec<String>,
}

impl SseParser {
    fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line);
            if line.is_empty() {
                // End of an event.
                if !self.data.is_empty() {
                    out.push(self.data.join("\n"));
                    self.data.clear();
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
            }
            // `event:`, `id:`, `retry:` and `:` comments carry nothing to relay.
        }
        out
    }
}

/// The stdio agent in front of an HTTP upstream (`mcp-proxy --upstream-url`
/// without `--listen`): returns when the agent closes its input and every
/// forwarded message has settled.
pub(crate) fn run_stdio_agent<R, W>(upstream: &Upstream, ctx: ProxyContext, agent_in: R, agent_out: W) -> Result<()>
where
    R: std::io::Read + Send + 'static,
    W: Write + Send + 'static,
{
    let UpstreamTransport::Http { url, headers } = &upstream.transport else {
        anyhow::bail!("not an HTTP upstream");
    };
    let sinks = ctx.events.clone();
    let interceptor = Arc::new(Interceptor::new(ctx)?);
    let agent_out = Arc::new(Mutex::new(agent_out));
    let deliver: Deliver = {
        let interceptor = interceptor.clone();
        let agent_out = agent_out.clone();
        let server = upstream.name.clone();
        Arc::new(move |incoming| {
            let actions = match incoming {
                Incoming::Message(line) => interceptor.on_upstream_line(&server, &line),
                Incoming::Failed { message, error } => interceptor.on_upstream_error(&server, &message, &error),
            };
            for action in actions {
                if let Action::ToAgent(out) = action {
                    let _ = write_line(&agent_out, &out);
                }
            }
        })
    };
    let client = HttpClient::start(url, headers, deliver)?;
    for line in BufReader::new(agent_in).lines() {
        let Ok(line) = line else { break };
        let sent = interceptor.on_agent_line(&line).into_iter().all(|action| match action {
            Action::ToAgent(reply) => write_line(&agent_out, &reply).is_ok(),
            Action::ToUpstream { message, .. } => {
                client.send(message);
                true
            }
        });
        if !sent {
            break;
        }
    }
    client.close();
    for action in interceptor.finish() {
        if let Action::ToAgent(notice) = action {
            let _ = write_line(&agent_out, &notice);
        }
    }
    flush_events(&sinks, EVENT_FLUSH);
    Ok(())
}

// ── upstream side: a stdio child behind the HTTP listener ───────────────

/// A stdio upstream shared by every HTTP session.
struct StdioLink {
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Child>,
    reader: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Its output and what runs when it ends, until [`Self::begin`].
    output: Mutex<Option<(Lines, Closed)>>,
    deliver: Deliver,
}

type Lines = Box<dyn Iterator<Item = String> + Send>;
type Closed = Box<dyn FnOnce() + Send>;

impl StdioLink {
    /// Spawn `command`; once begun, its lines go to `deliver`, and `closed`
    /// runs once its output ends (it exited).
    fn start(command: &[String], deliver: Deliver, closed: Closed) -> Result<Self> {
        anyhow::ensure!(!command.is_empty(), "upstream MCP command is empty");
        let mut child = Command::new(&command[0])
            .args(&command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn upstream MCP server: {command:?}"))?;
        let stdin = child.stdin.take().context("upstream has no stdin")?;
        let stdout = child.stdout.take().context("upstream has no stdout")?;
        let lines: Lines = Box::new(BufReader::new(stdout).lines().map_while(std::io::Result::ok));
        Ok(Self::attach(child, stdin, lines, deliver, closed))
    }

    /// A server already running (spawned and initialized by the gate).
    fn attach(child: Child, stdin: ChildStdin, lines: Lines, deliver: Deliver, closed: Closed) -> Self {
        Self {
            stdin: Mutex::new(Some(stdin)),
            child: Mutex::new(child),
            reader: Mutex::new(None),
            output: Mutex::new(Some((lines, closed))),
            deliver,
        }
    }

    /// Start relaying its output (once every link exists, so what it sends
    /// can be routed).
    fn begin(&self) {
        let Some((lines, closed)) = self.output.lock().ok().and_then(|mut o| o.take()) else { return };
        let deliver = self.deliver.clone();
        let reader = std::thread::spawn(move || {
            for line in lines {
                deliver(Incoming::Message(line));
            }
            closed();
        });
        if let Ok(mut r) = self.reader.lock() {
            *r = Some(reader);
        }
    }

    fn send(&self, message: String) {
        let written = match self.stdin.lock().as_deref_mut() {
            Ok(Some(stdin)) => stdin.write_all(message.as_bytes()).and_then(|_| stdin.write_all(b"\n")).and_then(|_| stdin.flush()),
            _ => Err(std::io::Error::other("the upstream's input is closed")),
        };
        if let Err(e) = written {
            (self.deliver)(Incoming::Failed { message, error: format!("writing to the upstream: {e}") });
        }
    }

    /// Close the upstream's input, give it a moment to exit (then kill it)
    /// and relay its last output.
    fn close(&self) {
        if let Ok(mut stdin) = self.stdin.lock() {
            stdin.take();
        }
        if let Ok(mut child) = self.child.lock() {
            let mut waited = Duration::ZERO;
            while matches!(child.try_wait(), Ok(None)) && waited < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(20));
                waited += Duration::from_millis(20);
            }
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.lock().ok().and_then(|mut r| r.take()) {
            let _ = reader.join();
        }
    }
}

// ── upstream side: the agent framework's own tools (`--decide`) ─────────

/// The upstream behind `POST /decide`: there is no MCP server. A
/// `tools/call` the gate forwards is held until `POST /outcome` reports
/// what the framework's tool returned, which becomes the upstream's reply
/// (so the ledger records the outcome, and a side-effecting call left
/// without one is `unknown` at shutdown). Everything else the gate would
/// send a server (`initialize`, `tools/list`, `ping`) is answered here.
pub(crate) struct DeferredLink {
    /// Forwarded calls awaiting their outcome, by the id they went out
    /// under: the message as sent.
    pending: Mutex<HashMap<u64, String>>,
    deliver: Deliver,
}

impl DeferredLink {
    fn new(deliver: Deliver) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            deliver,
        }
    }

    fn send(&self, message: String) {
        let Ok(msg) = serde_json::from_str::<Value>(&message) else {
            return;
        };
        let id = msg.get("id").cloned().filter(|id| !id.is_null());
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            return;
        };
        let Some(id) = id else { return }; // a notification takes no answer
        match method {
            "tools/call" => {
                if let (Some(n), Ok(mut p)) = (id.as_u64(), self.pending.lock()) {
                    p.insert(n, message);
                }
            }
            "initialize" => self.answer(
                id,
                serde_json::json!({
                    "protocolVersion": crate::servers::PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "cloakpipe-decide", "version": env!("CARGO_PKG_VERSION") },
                }),
            ),
            "tools/list" => self.answer(id, serde_json::json!({ "tools": [] })),
            "ping" => self.answer(id, serde_json::json!({})),
            _ => {
                let reply = serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "Method not found" } });
                (self.deliver)(Incoming::Message(reply.to_string()));
            }
        }
    }

    fn answer(&self, id: Value, result: Value) {
        let reply = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
        (self.deliver)(Incoming::Message(reply.to_string()));
    }

    /// Whether call `n` was forwarded and awaits its outcome.
    fn holds(&self, n: u64) -> bool {
        self.pending
            .lock()
            .map(|p| p.contains_key(&n))
            .unwrap_or(false)
    }

    /// The outcome of call `n`: `Ok(result)` is the tool's MCP result
    /// (`content`, `isError`), `Err(error)` means the tool never answered
    /// (a timeout, a crash): the call fails closed, `unknown` if it has
    /// side effects. `false` when `n` is not awaiting an outcome.
    fn settle(&self, n: u64, outcome: Result<Value, String>) -> bool {
        let Some(message) = self.pending.lock().ok().and_then(|mut p| p.remove(&n)) else {
            return false;
        };
        let incoming = match outcome {
            Ok(result) => Incoming::Message(
                serde_json::json!({ "jsonrpc": "2.0", "id": n, "result": result }).to_string(),
            ),
            Err(error) => Incoming::Failed { message, error },
        };
        (self.deliver)(incoming);
        true
    }
}

enum Link {
    Stdio(StdioLink),
    Http(Mutex<Option<HttpClient>>),
    Deferred(Arc<DeferredLink>),
}

impl Link {
    fn begin(&self) {
        if let Link::Stdio(link) = self {
            link.begin();
        }
    }

    fn send(&self, message: String) {
        match self {
            Link::Stdio(link) => link.send(message),
            Link::Http(client) => match client.lock().ok().as_deref() {
                Some(Some(client)) => client.send(message),
                _ => tracing::warn!("upstream client stopped; message dropped"),
            },
            Link::Deferred(link) => link.send(message),
        }
    }

    fn close(&self) {
        match self {
            Link::Stdio(link) => link.close(),
            Link::Http(client) => {
                if let Some(client) = client.lock().ok().and_then(|mut c| c.take()) {
                    client.close();
                }
            }
            // Calls still awaiting an outcome are left in flight: `finish`
            // records them `unknown`.
            Link::Deferred(_) => {}
        }
    }
}

// ── agent side: the listener ────────────────────────────────────────────

/// How `mcp-proxy --listen` serves.
#[derive(Debug, Clone)]
pub struct ListenConfig {
    pub addr: SocketAddr,
    /// When set, every `/mcp` request needs `Authorization: Bearer <token>`.
    pub token: Option<String>,
}

/// An agent request waiting for its reply.
struct Waiter {
    /// The session that sent it.
    session: String,
    /// The id the agent gave it.
    original: Value,
    reply: tokio::sync::oneshot::Sender<String>,
}

/// Routes upstream messages back to the POSTs waiting for them, and the
/// interceptor's messages to the upstreams.
struct Dispatch {
    interceptor: Interceptor,
    waiters: Mutex<HashMap<u64, Waiter>>,
    /// Each upstream by name, set once at start-up.
    links: std::sync::OnceLock<HashMap<String, Link>>,
}

impl Dispatch {
    fn deliver(&self, server: &str, incoming: Incoming) {
        let actions = match incoming {
            Incoming::Message(line) => self.interceptor.on_upstream_line(server, &line),
            Incoming::Failed { message, error } => self.interceptor.on_upstream_error(server, &message, &error),
        };
        self.route(actions);
    }

    /// Send `message` to upstream `server`.
    fn send(&self, server: &str, message: String) {
        match self.links.get().and_then(|links| links.get(server)) {
            Some(link) => link.send(message),
            None => tracing::warn!(server, "no such upstream; message dropped"),
        }
    }

    /// Hand each message for the agent to the request it answers; send
    /// each message for an upstream (several servers: listing pages, refused
    /// server requests).
    fn route(&self, actions: Vec<Action>) {
        for action in actions {
            let line = match action {
                Action::ToAgent(line) => line,
                Action::ToUpstream { server, message } => {
                    self.send(&server, message);
                    continue;
                }
            };
            let Ok(mut msg) = serde_json::from_str::<Value>(&line) else { continue };
            let reply = msg.get("method").is_none() && (msg.get("result").is_some() || msg.get("error").is_some());
            let waiter = msg
                .get("id")
                .and_then(Value::as_u64)
                .filter(|_| reply)
                .and_then(|n| self.waiters.lock().ok().and_then(|mut w| w.remove(&n)));
            match waiter {
                Some(w) => {
                    msg["id"] = w.original;
                    let _ = w.reply.send(msg.to_string());
                }
                // No server-to-client stream over HTTP (GET is 405).
                None => tracing::debug!("upstream message answers no waiting request; dropped"),
            }
        }
    }

    /// The id a session's request in flight was forwarded under.
    fn forwarded_as(&self, session: &str, original: &Value) -> Option<u64> {
        let waiters = self.waiters.lock().ok()?;
        waiters.iter().find(|(_, w)| w.session == session && &w.original == original).map(|(n, _)| *n)
    }

    /// No reply will come any more: every waiting request fails closed.
    fn drop_waiters(&self) {
        if let Ok(mut w) = self.waiters.lock() {
            w.clear();
        }
    }
}

struct Hub {
    dispatch: Arc<Dispatch>,
    next_id: AtomicU64,
    sessions: Mutex<HashSet<String>>,
    token: Option<String>,
    health: Value,
    /// `--decide`: the framework's own tools, behind `/decide` and `/outcome`.
    deferred: Option<Arc<DeferredLink>>,
}

/// Serve MCP over HTTP at `config.addr` in front of `upstream` until
/// `shutdown` resolves or the (stdio) upstream exits. The bound address is
/// announced on stderr: `cloakpipe: MCP over HTTP listening on http://ADDR/mcp`.
pub async fn serve<F>(config: ListenConfig, upstream: Upstream, ctx: ProxyContext, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with(config, Upstreams::One(upstream), ctx, shutdown).await
}

/// [`serve`] in front of several stdio servers, or one with a tools lock
/// (`mcp-proxy --listen … --server … --tools-lock …`): the gate starts,
/// initializes and lists each server first, then an
/// [`Interceptor::with_servers`] routes each `tools/call` to the server that
/// serves the tool, hiding and refusing drifted tools. A server that exits
/// leaves the others serving; when the last one has, the listener stops
/// with an error.
pub async fn serve_servers<F>(config: ListenConfig, upstreams: Vec<Upstream>, ctx: ProxyContext, lock: Option<ToolsLock>, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with(config, Upstreams::Routed(upstreams, lock), ctx, shutdown).await
}

/// [`serve`] with no MCP server behind the gate (`mcp-proxy --listen …
/// --decide`): the agent framework asks the gate about its own tools.
///
/// - `POST /decide` takes `{"tool": …, "arguments": {…}}` and answers
///   `{"decision": "allow", "call": N}` (run it, then report), `{"decision":
///   "deny", "reason": …, "message": …, "data": {…}}` (the gate's refusal, as
///   the agent would see it), `{"decision": "approve", …}` (a refusal whose
///   reason is `approval_required`: hold the call for a human) or
///   `{"decision": "replay", "result": …}` (a side-effecting call already
///   done, answered from the operations store).
/// - `POST /outcome` takes `{"call": N, "result": …}` (`result` is the
///   tool's output: a string, or an MCP result with `content`; `is_error`
///   marks a failure) or `{"call": N, "error": "…"}` (the tool never
///   answered) and records it.
///
/// Both need the listen token, when there is one. Every decision goes to
/// the ledger exactly as over MCP.
pub async fn serve_decide<F>(config: ListenConfig, ctx: ProxyContext, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_with(config, Upstreams::Deferred, ctx, shutdown).await
}

enum Upstreams {
    One(Upstream),
    Routed(Vec<Upstream>, Option<ToolsLock>),
    Deferred,
}

async fn serve_with<F>(config: ListenConfig, upstreams: Upstreams, ctx: ProxyContext, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let mode = ctx.gate.as_ref().map(|g| match g.mode {
        crate::GateMode::Enforce => "enforce",
        crate::GateMode::Shadow => "shadow",
    });
    let health = match &ctx.gate {
        Some(gate) => serde_json::json!({ "status": "ok", "release": gate.release_name(), "release_digest": gate.release(), "mode": mode, "tools": gate.declared_tools() }),
        None => serde_json::json!({ "status": "ok", "release": Value::Null, "release_digest": Value::Null, "mode": mode }),
    };
    let mut deferred = None;
    let listener = tokio::net::TcpListener::bind(config.addr).await.with_context(|| format!("--listen {}: cannot bind", config.addr))?;
    let local = listener.local_addr()?;
    let upstream_gone = Arc::new(tokio::sync::Notify::new());
    let dispatch = match upstreams {
        Upstreams::One(upstream) => {
            let dispatch = Arc::new(Dispatch { interceptor: Interceptor::new(ctx)?, waiters: Mutex::new(HashMap::new()), links: Default::default() });
            let server = upstream.name.clone();
            let deliver: Deliver = {
                let dispatch = dispatch.clone();
                let server = server.clone();
                Arc::new(move |incoming| dispatch.deliver(&server, incoming))
            };
            let link = match &upstream.transport {
                UpstreamTransport::Stdio { command } => {
                    let dispatch = dispatch.clone();
                    let gone = upstream_gone.clone();
                    let closed = Box::new(move || {
                        // Calls still in flight never get their reply.
                        dispatch.route(dispatch.interceptor.finish());
                        dispatch.drop_waiters();
                        gone.notify_one();
                    });
                    Link::Stdio(StdioLink::start(command, deliver, closed)?)
                }
                UpstreamTransport::Http { url, headers } => Link::Http(Mutex::new(Some(HttpClient::start(url, headers, deliver)?))),
            };
            let _ = dispatch.links.set(HashMap::from([(server, link)]));
            dispatch
        }
        Upstreams::Routed(upstreams, lock) => {
            // Start, initialize and list every server (blocking I/O).
            let (interceptor, parts) = tokio::task::spawn_blocking(move || -> Result<_> {
                anyhow::ensure!(!upstreams.is_empty(), "no upstream MCP server");
                let mut servers = upstreams.iter().map(StdioServer::spawn).collect::<Result<Vec<_>>>()?;
                let mut listing = Vec::new();
                for server in &mut servers {
                    listing.push(server.discover(DISCOVERY_TIMEOUT)?);
                }
                let interceptor = Interceptor::with_servers(ctx, listing, lock)?;
                let parts: Vec<_> = servers.into_iter().map(|s| (s.name.clone(), s.into_parts())).collect();
                Ok((interceptor, parts))
            })
            .await
            .context("starting the upstream servers")??;
            let dispatch = Arc::new(Dispatch { interceptor, waiters: Mutex::new(HashMap::new()), links: Default::default() });
            let live = Arc::new(AtomicUsize::new(parts.len()));
            let mut links = HashMap::new();
            for (name, (child, stdin, lines)) in parts {
                let deliver: Deliver = {
                    let dispatch = dispatch.clone();
                    let name = name.clone();
                    Arc::new(move |incoming| dispatch.deliver(&name, incoming))
                };
                let closed: Closed = {
                    let (dispatch, gone, live, name) = (dispatch.clone(), upstream_gone.clone(), live.clone(), name.clone());
                    Box::new(move || {
                        // Its requests fail closed; the other servers serve on.
                        dispatch.route(dispatch.interceptor.server_gone(&name));
                        if live.fetch_sub(1, Ordering::SeqCst) == 1 {
                            dispatch.route(dispatch.interceptor.finish());
                            dispatch.drop_waiters();
                            gone.notify_one();
                        }
                    })
                };
                links.insert(name, Link::Stdio(StdioLink::attach(child, stdin, Box::new(lines.into_iter()), deliver, closed)));
            }
            let _ = dispatch.links.set(links);
            dispatch
        }
        Upstreams::Deferred => {
            let dispatch = Arc::new(Dispatch { interceptor: Interceptor::new(ctx)?, waiters: Mutex::new(HashMap::new()), links: Default::default() });
            let deliver: Deliver = {
                let dispatch = dispatch.clone();
                Arc::new(move |incoming| dispatch.deliver(DEFAULT_SERVER, incoming))
            };
            let link = Arc::new(DeferredLink::new(deliver));
            deferred = Some(link.clone());
            let _ = dispatch.links.set(HashMap::from([(DEFAULT_SERVER.to_string(), Link::Deferred(link))]));
            dispatch
        }
    };
    for link in dispatch.links.get().into_iter().flat_map(HashMap::values) {
        link.begin();
    }
    let hub = Arc::new(Hub {
        dispatch: dispatch.clone(),
        next_id: AtomicU64::new(1),
        sessions: Mutex::new(HashSet::new()),
        token: config.token,
        health,
        deferred,
    });

    if !local.ip().is_loopback() {
        let token = if hub.token.is_some() { "" } else { " and no --listen-token-file is set: anyone who can reach it can use the gate's tools" };
        eprintln!("warning: --listen {local} is not a loopback address{token}");
    }
    let app = Router::new().route("/mcp", get(get_mcp).post(post_mcp).delete(delete_mcp)).route("/health", get(get_health));
    let app = if hub.deferred.is_some() {
        eprintln!("cloakpipe: decisions served on http://{local}/decide (outcomes on /outcome)");
        app.route("/decide", post(post_decide)).route("/outcome", post(post_outcome))
    } else {
        eprintln!("cloakpipe: MCP over HTTP listening on http://{local}/mcp");
        app
    };
    let app = app.with_state(hub.clone());
    let gone = upstream_gone.clone();
    let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = {
        let exited = exited.clone();
        async move {
            tokio::select! {
                _ = shutdown => {}
                _ = gone.notified() => exited.store(true, Ordering::SeqCst),
            }
        }
    };
    axum::serve(listener, app).with_graceful_shutdown(stop).await.context("serving MCP over HTTP")?;

    // No agent request is in flight any more: stop the upstream, then sweep.
    let hub2 = hub.clone();
    tokio::task::spawn_blocking(move || {
        for link in hub2.dispatch.links.get().into_iter().flat_map(HashMap::values) {
            link.close();
        }
        hub2.dispatch.route(hub2.dispatch.interceptor.finish());
        hub2.dispatch.drop_waiters();
    })
    .await
    .context("stopping the upstream")?;
    if exited.load(Ordering::SeqCst) {
        anyhow::bail!("the upstream MCP server exited");
    }
    Ok(())
}

/// A JSON-RPC error response with no id (transport-level problems).
fn rpc_error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": Value::Null, "error": { "code": -32000, "message": message } });
    (status, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response()
}

fn json_response(body: String, session: Option<&str>) -> Response {
    let mut resp = (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    if let Some(session) = session.and_then(|s| HeaderValue::from_str(s).ok()) {
        resp.headers_mut().insert(HeaderName::from_static(SESSION), session);
    }
    resp
}

impl Hub {
    /// The token and the origin, checked on every `/mcp` request.
    fn admit(&self, headers: &HeaderMap) -> Result<(), Box<Response>> {
        if let Some(token) = &self.token {
            let given = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split_once(' '))
                // The scheme is case-insensitive (RFC 9110 11.1).
                .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
                .map(|(_, token)| token.trim());
            if !given.is_some_and(|g| constant_time_eq(g.as_bytes(), token.as_bytes())) {
                let mut resp = rpc_error(StatusCode::UNAUTHORIZED, "Unauthorized: a bearer token is required");
                resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                return Err(Box::new(resp));
            }
        }
        if !origin_allowed(headers) {
            return Err(Box::new(rpc_error(StatusCode::FORBIDDEN, "Forbidden: origin not allowed")));
        }
        Ok(())
    }

    /// A live session from the request's header: `Err` is the response.
    fn session(&self, headers: &HeaderMap) -> Result<String, Box<Response>> {
        let Some(session) = headers.get(SESSION).and_then(|v| v.to_str().ok()) else {
            return Err(Box::new(rpc_error(StatusCode::BAD_REQUEST, "Bad Request: the Mcp-Session-Id header is required")));
        };
        if !self.sessions.lock().map(|s| s.contains(session)).unwrap_or(false) {
            return Err(Box::new(rpc_error(StatusCode::NOT_FOUND, "Session not found")));
        }
        Ok(session.to_string())
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// No `Origin` (not a browser), a loopback origin, or the listener's own.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else { return true };
    let Some(authority) = origin.to_str().ok().and_then(|o| o.split_once("://")).map(|(_, rest)| rest.trim_end_matches('/')) else {
        return false;
    };
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return true;
    }
    headers.get(header::HOST).and_then(|h| h.to_str().ok()).is_some_and(|h| h.eq_ignore_ascii_case(authority))
}

async fn get_health(State(hub): State<Arc<Hub>>) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], hub.health.to_string()).into_response()
}

async fn get_mcp(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if let Err(resp) = hub.admit(&headers) {
        return *resp;
    }
    let mut resp = rpc_error(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed: no server-to-client stream; POST messages");
    resp.headers_mut().insert(header::ALLOW, HeaderValue::from_static("POST, DELETE"));
    resp
}

async fn delete_mcp(State(hub): State<Arc<Hub>>, headers: HeaderMap) -> Response {
    if let Err(resp) = hub.admit(&headers) {
        return *resp;
    }
    match hub.session(&headers) {
        Ok(session) => {
            if let Ok(mut s) = hub.sessions.lock() {
                s.remove(&session);
            }
            StatusCode::OK.into_response()
        }
        Err(resp) => *resp,
    }
}

async fn post_mcp(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(resp) = hub.admit(&headers) {
        return *resp;
    }
    let mut text = String::from_utf8_lossy(&body).into_owned();
    let mut parsed: Option<Value> = serde_json::from_str(&text).ok();
    let method = parsed.as_ref().and_then(|v| v.get("method")).and_then(Value::as_str).map(str::to_string);
    let initialize = method.as_deref() == Some("initialize");
    let session = if initialize {
        None
    } else {
        match hub.session(&headers) {
            Ok(session) => Some(session),
            Err(resp) => return *resp,
        }
    };
    // A cancellation names the agent's id for its request: the upstream
    // knows it by the gate's. One naming no request of this session in
    // flight goes nowhere, so a session can never cancel another's.
    if method.as_deref() == Some("notifications/cancelled") {
        let Some(msg) = parsed.as_mut() else { return StatusCode::ACCEPTED.into_response() };
        let forwarded = match (session.as_deref(), msg.pointer("/params/requestId")) {
            (Some(session), Some(original)) => hub.dispatch.forwarded_as(session, original),
            _ => None,
        };
        let Some(n) = forwarded else {
            tracing::debug!("a cancellation names no request of this session in flight; dropped");
            return StatusCode::ACCEPTED.into_response();
        };
        msg["params"]["requestId"] = Value::from(n);
        text = msg.to_string();
    }
    // A request is forwarded under an id unique to this gate, so its reply
    // finds this POST whichever session sent it. Only a message that parsed
    // is rewritten; anything else reaches the gate as sent.
    let original = parsed.as_ref().filter(|_| method.is_some()).and_then(|v| v.get("id")).filter(|id| !id.is_null()).cloned();
    let (line, waiting) = match (original, parsed) {
        (Some(original), Some(mut msg)) => {
            let n = hub.next_id.fetch_add(1, Ordering::SeqCst);
            msg["id"] = Value::from(n);
            let (tx, rx) = tokio::sync::oneshot::channel();
            if let Ok(mut w) = hub.dispatch.waiters.lock() {
                w.insert(n, Waiter { session: session.clone().unwrap_or_default(), original: original.clone(), reply: tx });
            }
            (msg.to_string(), Some((n, original, rx)))
        }
        _ => (text, None),
    };
    let decided = {
        let hub = hub.clone();
        tokio::task::spawn_blocking(move || hub.dispatch.interceptor.on_agent_line(&line)).await
    };
    let actions = match decided {
        Ok(actions) => actions,
        Err(_) => return rpc_error(StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
    };
    // A direct answer (a refusal, a replayed result) is this POST's reply.
    let mut direct = None;
    for action in actions {
        match action {
            Action::ToAgent(reply) if direct.is_none() => direct = Some(reply),
            Action::ToAgent(_) => tracing::debug!("a second direct answer; dropped"),
            Action::ToUpstream { server, message } => hub.dispatch.send(&server, message),
        }
    }
    let reply = match (direct, waiting) {
        (Some(reply), None) => reply,
        (Some(reply), Some((n, original, _))) => {
            if let Ok(mut w) = hub.dispatch.waiters.lock() {
                w.remove(&n);
            }
            match serde_json::from_str::<Value>(&reply) {
                Ok(mut msg) if msg.get("id").and_then(Value::as_u64) == Some(n) => {
                    msg["id"] = original;
                    msg.to_string()
                }
                _ => reply,
            }
        }
        (None, None) => return StatusCode::ACCEPTED.into_response(),
        (None, Some((_, original, rx))) => match rx.await {
            Ok(reply) => reply,
            // The upstream is gone and the request was not answered.
            Err(_) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": original,
                "error": {
                    "code": UPSTREAM_UNAVAILABLE,
                    "message": "the upstream MCP server did not answer this request (transport error); it failed closed",
                    "data": { "reason": "upstream_unavailable" },
                },
            })
            .to_string(),
        },
    };
    let issued = if initialize && serde_json::from_str::<Value>(&reply).is_ok_and(|r| r.get("result").is_some()) {
        let session = uuid::Uuid::new_v4().simple().to_string();
        if let Ok(mut s) = hub.sessions.lock() {
            s.insert(session.clone());
        }
        Some(session)
    } else {
        None
    };
    json_response(reply, issued.as_deref())
}

// ── agent side: `/decide` and `/outcome` (`--decide`) ───────────────────

fn plain_json(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    plain_json(
        StatusCode::BAD_REQUEST,
        serde_json::json!({ "error": message }),
    )
}

/// `POST /decide`: one tool call the framework is about to run, decided by
/// the gate as a `tools/call` would be (see [`serve_decide`]).
async fn post_decide(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(resp) = hub.admit(&headers) {
        return *resp;
    }
    let Some(deferred) = hub.deferred.clone() else {
        return plain_json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "not serving decisions (start with --decide)" }),
        );
    };
    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("the body must be a JSON object");
    };
    let Some(tool) = req
        .get("tool")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    else {
        return bad_request("\"tool\" (the tool's name) is required");
    };
    let arguments = match req.get("arguments") {
        None | Some(Value::Null) => Value::Object(Default::default()),
        Some(args) if args.is_object() => args.clone(),
        Some(_) => return bad_request("\"arguments\" must be a JSON object"),
    };
    let n = hub.next_id.fetch_add(1, Ordering::SeqCst);
    let call = serde_json::json!({ "jsonrpc": "2.0", "id": n, "method": "tools/call", "params": { "name": tool, "arguments": arguments } });
    let line = call.to_string();
    // A waiter, so a reply the gate gives later (a replay settled by the
    // operations store) is not mistaken for an upstream message to drop.
    let (tx, rx) = tokio::sync::oneshot::channel();
    if let Ok(mut w) = hub.dispatch.waiters.lock() {
        w.insert(
            n,
            Waiter {
                session: "decide".into(),
                original: Value::from(n),
                reply: tx,
            },
        );
    }
    let decided = {
        let hub = hub.clone();
        tokio::task::spawn_blocking(move || hub.dispatch.interceptor.on_agent_line(&line)).await
    };
    let Ok(actions) = decided else {
        return plain_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "decision": "deny", "reason": "fail_closed", "message": "Internal error" }),
        );
    };
    let mut direct = None;
    for action in actions {
        match action {
            Action::ToAgent(reply) if direct.is_none() => direct = Some(reply),
            Action::ToAgent(_) => tracing::debug!("a second direct answer; dropped"),
            Action::ToUpstream { server, message } => hub.dispatch.send(&server, message),
        }
    }
    if let Ok(mut w) = hub.dispatch.waiters.lock() {
        w.remove(&n);
    }
    drop(rx);
    if deferred.holds(n) {
        return plain_json(
            StatusCode::OK,
            serde_json::json!({ "decision": "allow", "call": n, "mode": hub.health.get("mode") }),
        );
    }
    let Some(reply) = direct.and_then(|r| serde_json::from_str::<Value>(&r).ok()) else {
        return plain_json(
            StatusCode::OK,
            serde_json::json!({ "decision": "deny", "reason": "fail_closed", "message": "the gate gave no answer" }),
        );
    };
    if let Some(result) = reply.get("result") {
        return plain_json(
            StatusCode::OK,
            serde_json::json!({ "decision": "replay", "result": result, "mode": hub.health.get("mode") }),
        );
    }
    let error = reply.get("error").cloned().unwrap_or_default();
    let reason = error
        .pointer("/data/reason")
        .and_then(Value::as_str)
        .unwrap_or("fail_closed")
        .to_string();
    let decision = if reason == "approval_required" {
        "approve"
    } else {
        "deny"
    };
    plain_json(
        StatusCode::OK,
        serde_json::json!({
            "decision": decision,
            "reason": reason,
            "message": error.get("message"),
            "code": error.get("code"),
            "data": error.get("data"),
            "mode": hub.health.get("mode"),
        }),
    )
}

/// `POST /outcome`: what a call allowed by `/decide` returned.
async fn post_outcome(State(hub): State<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(resp) = hub.admit(&headers) {
        return *resp;
    }
    let Some(deferred) = hub.deferred.clone() else {
        return plain_json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "not serving decisions (start with --decide)" }),
        );
    };
    let Ok(req) = serde_json::from_slice::<Value>(&body) else {
        return bad_request("the body must be a JSON object");
    };
    let Some(n) = req.get("call").and_then(Value::as_u64) else {
        return bad_request("\"call\" (the id /decide answered with) is required");
    };
    let outcome = match (req.get("error"), req.get("result")) {
        (Some(Value::String(error)), _) => Err(error.clone()),
        (Some(_), _) => return bad_request("\"error\" must be a string"),
        (None, result) => {
            let is_error = req
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let result = match result {
                // An MCP result already.
                Some(r) if r.get("content").is_some() => r.clone(),
                Some(Value::String(text)) => {
                    serde_json::json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
                }
                Some(Value::Null) | None => {
                    serde_json::json!({ "content": [], "isError": is_error })
                }
                Some(other) => {
                    serde_json::json!({ "content": [{ "type": "text", "text": other.to_string() }], "isError": is_error })
                }
            };
            Ok(result)
        }
    };
    let settled = {
        let deferred = deferred.clone();
        tokio::task::spawn_blocking(move || deferred.settle(n, outcome))
            .await
            .unwrap_or(false)
    };
    if settled {
        plain_json(
            StatusCode::OK,
            serde_json::json!({ "recorded": true, "call": n }),
        )
    } else {
        plain_json(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "recorded": false, "call": n, "error": "no such call awaits an outcome" }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_events_are_split_across_chunks() {
        let mut p = SseParser::default();
        assert!(p.feed(b"event: message\r\ndata: {\"a\"").is_empty());
        assert_eq!(p.feed(b":1}\r\n\r\n: comment\n\ndata: x\ndata: y\n\n"), ["{\"a\":1}", "x\ny"]);
    }

    #[test]
    fn origins() {
        let with = |origin: &str, host: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
            origin_allowed(&h)
        };
        assert!(origin_allowed(&HeaderMap::new()));
        assert!(with("http://localhost:3000", "10.0.0.5:8900"));
        assert!(with("http://127.0.0.1", "10.0.0.5:8900"));
        assert!(with("http://[::1]:8080", "10.0.0.5:8900"));
        assert!(with("https://gate.internal:8900", "gate.internal:8900"));
        assert!(!with("https://evil.example", "127.0.0.1:8900"));
        assert!(!with("null", "127.0.0.1:8900"));
        assert!(!with("http://localhost.evil.example", "127.0.0.1:8900"));
    }
}
