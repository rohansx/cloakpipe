# Review instructions

CloakPipe is a Rust-native privacy proxy that detects, masks, and unmasks PII
in LLM traffic, plus a cryptographic ledger and verifier (chain, signatures,
anchors, Merkle proofs). Correctness and privacy guarantees outrank style.

Open the review summary with a one-line tally (e.g. `3 important, 2 nits`), and
lead with "No blocking issues" when nothing is Important.

## What Important (🔴) means here

Reserve 🔴 for findings that would break a privacy guarantee, corrupt the
verifiable ledger, or crash on untrusted input. Specifically:

- **PII leakage**: any path where raw/unmasked PII can be logged, persisted,
  cached, sent to an upstream model, or surfaced in an error, panic message,
  span, or metric label. Broken mask/unmask round-trips and placeholder
  collisions count here.
- **Weakened crypto verification**: ledger hashing/chaining, signature checks,
  anchors, or proof validation that is skipped, made to **fail open**, uses a
  non-constant-time comparison for secrets/MACs, or accepts a malformed bundle
  that should be rejected.
- **Panic on untrusted input**: `unwrap`/`expect`/`panic!`/`unreachable!`,
  slice/index or integer-overflow panics, on a path reachable from request
  data or an untrusted bundle.
- **Concurrency hazards**: data races, deadlocks, or holding a lock across an
  `.await`.
- **Regressions to the zero-leak gates** (cloakleak) or the verifier e2e checks.

Style, naming, formatting, and refactor suggestions are 🟡 Nit at most.

## Cap the nits

Report at most **five** 🟡 Nits per review. If you found more, add
"plus N similar items" to the summary instead of posting them inline.

## Do not report

- Anything CI already enforces: `cargo fmt`, `cargo clippy -- -D warnings`,
  and compiler warnings (see `.github/workflows/ci.yml`).
- `Cargo.lock` and any generated or vendored files.
- The intentionally-insecure **baseline** implementations in cloakleak that are
  designed to leak 100% (they exist as a reference — do not flag them as leaks).
- Test fixtures and corpora that contain fake/sample PII on purpose.

## Always check

- New PII entity detectors / maskers ship with tests, and any change is
  reflected in the cloakleak tracks (prose + tool_json) so the zero-leak gate
  still passes.
- Log lines, error messages, panics, and telemetry never include raw PII,
  secrets, or full request/response bodies.
- Verifier checks (`chain`, `sigs`, `anchors`, `proofs`) fail **closed** — a
  missing, malformed, or tampered field must be an error, never a silent pass.
- New dependencies are justified; watch for anything pulling PII or ledger data
  off-box.

## Verification bar

Behavior claims need a `file:line` citation in the source, not an inference
from a name. If you cannot point to the code that causes the issue, downgrade
to a question in the summary rather than a 🔴 inline comment.

## Re-review convergence

After the first review of a PR, suppress new nits and post 🔴 Important
findings only. Don't re-raise items already fixed.
