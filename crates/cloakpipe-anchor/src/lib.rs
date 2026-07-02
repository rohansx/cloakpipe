//! CloakPipe Anchor — external anchoring for evidence bundles.
//!
//! Per docs/v2/05-SYSTEM_DESIGN.md §2:
//!
//! "Publish signed batch heads to a transparency log and/or trusted
//! timestamp authority *outside operator control* so history cannot
//! be rewritten undetectably."
//!
//! ## Components
//!
//! - [`merkle`] — pure-SHA-256 Merkle tree over record hashes, with
//!   inclusion-proof generation and verification.
//! - [`batch`] — batch head construction (signed Merkle root +
//!   metadata).
//! - [`anchor`] — pluggable anchor backend. Phase 1 ships:
//!   - [`anchor::TsaBackend`] — RFC-3161 timestamp authority (with a
//!     fully-tested in-process TSA implementation).
//!   - [`anchor::LogBackend`] — generic transparency-log backend
//!     (Rekor v2 / Trillian-Tessera shaped; in-process test harness).
//! - [`receipt`] — typed [`AnchorReceipt`] with `verify()` for
//!   offline checking.
//!
//! ## Why standalone
//!
//! Like `cloakpipe-verify`, this crate defines its own types for the
//! wire format. The producer (M2's bundle exporter) consumes these
//! types; the verifier reads them. No dependency on `cloakpipe-ledger`
//! or `cloakpipe-verify`.

pub mod anchor;
pub mod batch;
pub mod merkle;
pub mod receipt;