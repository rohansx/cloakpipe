//! CloakLeak — the open PII-leak benchmark.
//!
//! Phase 1 (M6) supports two tracks:
//! - **prose** — free-text messages that should be masked before
//!   reaching the LLM.
//! - **tool_json** — MCP `CallToolResult` / arguments JSON where PII
//!   may appear inside string fields.
//!
//! ## Metric
//!
//! Per entity type, per track: `leak_rate = leaked / total`. "Leaked"
//! means the system under test (SUT) failed to mask at least one
//! instance of the entity in the input.
//!
//! ## Held-out validation
//!
//! The public corpus here is a *sample*. The full validation set lives
//! in a private repo — `cloakleak-private/` — and is the basis of
//! published scores. (See `docs/v2/09-CLOAKLEAK.md` §3.)
//!
//! ## What we test (not what we claim)
//!
//! This crate is the *harness*. It runs any function
//! `Fn(&str) -> String` (the redaction function under test) over the
//! corpus, measures leaks, and reports a scoreboard. We do **not**
//! bake in any particular SUT — that's the whole point of an open
//! benchmark.

pub mod cloakpipe_sut;
pub mod corpus;
pub mod detect;
pub mod score;
pub mod sut;

pub use cloakpipe_sut::CloakPipeRegexSut;
pub use corpus::{Corpus, Track};
pub use detect::{EntityClass, Leak};
pub use score::{ScoreReport, ScoreRow};
pub use sut::{Sut, SutError};