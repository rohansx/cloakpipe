//! System-under-test (SUT) abstraction.
//!
//! A CloakLeak SUT is anything that takes an input string and returns
//! a redacted string. Plugging in CloakPipe is one option; plugging in
//! Presidio, LLM Guard, or a no-op baseline are equally valid.
//!
//! The SUT must be **pure** (deterministic, no I/O) for two reasons:
//! - Reproducibility — anyone running the same SUT over the public
//!   corpus must get the same score.
//! - Held-out isolation — we don't want SUTs to phone home with the
//!   validation set during benchmarking.

use thiserror::Error;

/// A redaction function under test.
pub trait Sut: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn redact(&self, input: &str) -> Result<String, SutError>;
}

#[derive(Debug, Error)]
pub enum SutError {
    #[error("sut returned invalid utf-8")]
    InvalidUtf8,
    #[error("sut panicked")]
    Panicked,
}

/// A passthrough SUT — does no redaction. The reference baseline that
/// the scoreboard expects to score 100% leak (or near it). Useful for
/// regression-testing the *harness*: if passthrough scores < 100%,
/// something is broken in leak detection.
pub struct Passthrough;

impl Sut for Passthrough {
    fn name(&self) -> &str {
        "passthrough"
    }
    fn version(&self) -> &str {
        "0"
    }
    fn redact(&self, input: &str) -> Result<String, SutError> {
        Ok(input.to_string())
    }
}

/// A perfect SUT — replaces the whole input with `***`. The reference
/// upper bound: 0% leaks. If this scores > 0%, the harness is broken.
pub struct PerfectEraser;

impl Sut for PerfectEraser {
    fn name(&self) -> &str {
        "perfect_eraser"
    }
    fn version(&self) -> &str {
        "0"
    }
    fn redact(&self, _input: &str) -> Result<String, SutError> {
        Ok("***".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_preserves_input() {
        let p = Passthrough;
        assert_eq!(p.redact("PAN ABCDE1234F").unwrap(), "PAN ABCDE1234F");
    }

    #[test]
    fn perfect_eraser_returns_stars() {
        let p = PerfectEraser;
        assert_eq!(p.redact("anything").unwrap(), "***");
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(Passthrough.name(), "passthrough");
        assert_eq!(PerfectEraser.name(), "perfect_eraser");
    }
}