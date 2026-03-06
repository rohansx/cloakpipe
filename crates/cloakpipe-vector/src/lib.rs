//! CloakPipe Vector — ADCPE distance-preserving vector encryption.
//!
//! Encrypts embedding vectors using a secret orthogonal transformation
//! so that approximate nearest-neighbor relationships are preserved.
//! This means encrypted vectors can still be used for similarity search
//! in vector databases, but cannot be inverted back to the original
//! embeddings (which could leak the source text).
//!
//! ## How it works
//!
//! 1. A secret orthogonal matrix Q is derived from a key using
//!    Gram-Schmidt orthogonalization of a seeded random matrix.
//! 2. Each vector v is transformed: v' = Q * v (+ optional noise)
//! 3. Cosine similarity is preserved: cos(Q*a, Q*b) = cos(a, b)
//! 4. Optional Gaussian noise can be added for differential privacy,
//!    at the cost of slight distance distortion.

pub mod adcpe;

pub use adcpe::{AdcpeEncryptor, AdcpeConfig};
