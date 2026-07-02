# CloakLeak — Public PII-Leak Benchmark

**Status:** v0 (Phase 1 of v2 pivot).
**License:** Apache-2.0 (harness) / CC-BY-4.0 (sample corpus).
**Companion doc:** [`docs/v2/09-CLOAKLEAK.md`](../../docs/v2/09-CLOAKLEAK.md).

---

## What this is

An open, reproducible benchmark that measures **PII-leak rate** for any
LLM-privacy middleware. Runs any function `&str -> String` (the system
under test, SUT) over a sample corpus, scans the redacted output for
surviving identifiers, and emits a per-entity, per-track scoreboard.

**The point is not "CloakPipe scores 100%."** The point is that
*anyone* can plug in a SUT and get a comparable number.

---

## Status: honest disclosure

**Phase 1 v0 is shipped.** The harness works, the regex detectors work,
the corpora load, the CI gate works. Two SUTs ship today:

| SUT | What it does | Expected behavior |
|---|---|---|
| `passthrough` | Returns input unchanged | ~100% leak (baseline) |
| `perfect` | Returns `***` | 0% leak (upper bound) |
| `cloakpipe-regex` | Regex-detect + class-shaped token redaction | depends on input |

**What this is NOT:**

- **Not** a "CloakPipe scored 100%" claim. The sample corpus is
  **10 samples per track**, hand-written and public. It's enough to
  prove the harness produces real numbers from real inputs, not enough
  to back a marketing claim. Published scores come from the
  held-out validation set (see [`STATUS.md`](STATUS.md)), which we are
  not shipping in this repo.
- **Not** a benchmark for ML-based detectors. Regex only. The
  neural NER tier is benchmarked separately.
- **Not** a benchmark for adversarial / obfuscation cases. Phase 2+
  work.

---

## Tracks (Phase 1)

| Track | Source | Samples |
|---|---|---|
| `prose` | `corpus/prose/sample.jsonl` | 10 |
| `tool_json` | `corpus/tool_json/sample.jsonl` | 10 |

Each sample declares which entity classes should appear. The leak
score for a class is `leaked_samples / samples_with_class`. A sample
counts as "leaked" if *any* of its expected entities survived
redaction.

---

## Running

```
cargo run -p cloakleak-cli -- baselines --track prose
cargo run -p cloakleak-cli -- run --sut cloakpipe-regex --track prose
cargo run -p cloakleak-cli -- run --sut passthrough --track tool_json
```

Exit codes: `0` zero leaks (CI gate passes), `1` one or more leaks
(CI gate fails), `2` usage error.

---

## Layout

```
crates/cloakleak/
  src/
    detect.rs        entity taxonomy + regex detection
    sut.rs           System-Under-Test trait + reference SUTs
    score.rs         scoring + report serialization
    corpus.rs        JSONL corpus loader
    cloakpipe_sut.rs CloakPipe regex SUT (the "real" one)
    lib.rs
  corpus/
    prose/sample.jsonl
    tool_json/sample.jsonl
  tests/
    m6_gate.rs       M6 exit gate — must pass before any release

crates/cloakleak-cli/
  src/main.rs        CLI
```

---

## Test results

```
$ cargo test -p cloakleak
test result: ok. 18 passed; 0 failed
$ cargo test -p cloakleak --test m6_gate
test result: ok. 8 passed; 0 failed

$ cargo run -p cloakleak-cli -- baselines --track prose
passthrough      overall_leak_rate=0.9000  (9 leaked / 10 samples)
perfect          overall_leak_rate=0.0000  (0 leaked / 10 samples)
cloakpipe-regex  overall_leak_rate=0.0000  (0 leaked / 10 samples)
```

The 0.90 for passthrough (not 1.00) is correct: one sample in each
corpus is intentionally clean ("write a haiku", "weather api") and
declares no expected entities, so it can't leak in the
expected-entity sense.

---

## Roadmap

- **Phase 1 (now):** regex, prose + tool_json, harness works. ✓
- **Phase 2 (M10 launch):** RAG track; held-out validation set
  published; first scoreboard vs Presidio / LLM Guard / CloakLLM.
- **Phase 3:** OCR track; vendor invitations; design-partner
  case study.