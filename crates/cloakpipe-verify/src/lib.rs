//! Library API of `cloakpipe-verify`.
//!
//! The CLI binary (`src/main.rs`) is the user-facing entry point;
//! this module exposes the same primitives for embedding in tests,
//! other tools, or future language bindings.
//!
//! Both the binary and this lib are part of the same crate and share
//! the bundle format and verifier implementation. A hostile third
//! party can build *only* this crate and verify a bundle — see
//! `tests/m2_gate.rs` for the end-to-end gate.

pub mod anchor;
pub mod bundle;
pub mod verify;