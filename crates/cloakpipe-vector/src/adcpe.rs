//! ADCPE: Approximately Distance-Preserving Cryptographic Encryption
//!
//! Applies a secret orthogonal transformation to embedding vectors.
//! Orthogonal transformations preserve inner products (and thus cosine
//! similarity), making encrypted vectors usable for similarity search.

use anyhow::{bail, Result};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Configuration for ADCPE encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdcpeConfig {
    /// Dimensionality of the embedding vectors.
    pub dimensions: usize,
    /// Optional noise scale (0.0 = exact distance preservation, >0 adds noise).
    #[serde(default)]
    pub noise_scale: f64,
}

/// ADCPE vector encryptor.
///
/// Holds a secret orthogonal matrix derived from the encryption key.
/// The matrix is generated via Gram-Schmidt orthogonalization of a
/// seeded pseudo-random matrix.
pub struct AdcpeEncryptor {
    /// The orthogonal transformation matrix (row-major, dim x dim).
    matrix: Vec<f64>,
    /// The inverse (transpose for orthogonal) matrix for decryption.
    matrix_inv: Vec<f64>,
    /// Dimensionality.
    dim: usize,
    /// Noise scale for differential privacy.
    noise_scale: f64,
    /// RNG for noise generation.
    rng: StdRng,
}

impl Drop for AdcpeEncryptor {
    fn drop(&mut self) {
        self.matrix.zeroize();
        self.matrix_inv.zeroize();
    }
}

impl AdcpeEncryptor {
    /// Create a new ADCPE encryptor from a 32-byte key.
    ///
    /// The key is used to seed a PRNG that generates the random matrix,
    /// which is then orthogonalized via Gram-Schmidt.
    pub fn new(key: &[u8; 32], config: &AdcpeConfig) -> Result<Self> {
        let dim = config.dimensions;
        if dim == 0 {
            bail!("Vector dimensions must be > 0");
        }

        // Seed RNG from key
        let mut seed = [0u8; 32];
        seed.copy_from_slice(key);
        let mut rng = StdRng::from_seed(seed);

        // Generate random matrix
        let mut matrix = vec![0.0f64; dim * dim];
        for v in matrix.iter_mut() {
            *v = rng.gen::<f64>() * 2.0 - 1.0;
        }

        // Gram-Schmidt orthogonalization
        gram_schmidt(&mut matrix, dim)?;

        // Transpose = inverse for orthogonal matrices
        let matrix_inv = transpose(&matrix, dim);

        // Fresh RNG for noise (different seed)
        let mut noise_seed = [0u8; 32];
        for (i, b) in key.iter().enumerate() {
            noise_seed[i] = b.wrapping_add(0x5A);
        }
        let noise_rng = StdRng::from_seed(noise_seed);

        Ok(Self {
            matrix,
            matrix_inv,
            dim,
            noise_scale: config.noise_scale,
            rng: noise_rng,
        })
    }

    /// Encrypt a single embedding vector.
    ///
    /// Returns the transformed vector with the same dimensionality.
    pub fn encrypt(&mut self, vector: &[f64]) -> Result<Vec<f64>> {
        if vector.len() != self.dim {
            bail!(
                "Vector dimension mismatch: expected {}, got {}",
                self.dim,
                vector.len()
            );
        }

        let mut result = mat_vec_mul(&self.matrix, vector, self.dim);

        // Add optional noise
        if self.noise_scale > 0.0 {
            for v in result.iter_mut() {
                *v += self.rng.gen::<f64>() * self.noise_scale;
            }
        }

        Ok(result)
    }

    /// Decrypt a single embedding vector (inverse transformation).
    ///
    /// Note: if noise was added during encryption, decryption will not
    /// recover the exact original vector.
    pub fn decrypt(&self, encrypted: &[f64]) -> Result<Vec<f64>> {
        if encrypted.len() != self.dim {
            bail!(
                "Vector dimension mismatch: expected {}, got {}",
                self.dim,
                encrypted.len()
            );
        }

        Ok(mat_vec_mul(&self.matrix_inv, encrypted, self.dim))
    }

    /// Encrypt a batch of vectors.
    pub fn encrypt_batch(&mut self, vectors: &[Vec<f64>]) -> Result<Vec<Vec<f64>>> {
        vectors.iter().map(|v| self.encrypt(v)).collect()
    }

    /// Decrypt a batch of vectors.
    pub fn decrypt_batch(&self, encrypted: &[Vec<f64>]) -> Result<Vec<Vec<f64>>> {
        encrypted.iter().map(|v| self.decrypt(v)).collect()
    }

    /// Get the dimensionality.
    pub fn dimensions(&self) -> usize {
        self.dim
    }
}

/// Encrypt f32 vectors (common for embedding APIs).
pub fn encrypt_f32(encryptor: &mut AdcpeEncryptor, vector: &[f32]) -> Result<Vec<f32>> {
    let f64_vec: Vec<f64> = vector.iter().map(|&v| v as f64).collect();
    let encrypted = encryptor.encrypt(&f64_vec)?;
    Ok(encrypted.iter().map(|&v| v as f32).collect())
}

/// Decrypt f32 vectors.
pub fn decrypt_f32(encryptor: &AdcpeEncryptor, encrypted: &[f32]) -> Result<Vec<f32>> {
    let f64_vec: Vec<f64> = encrypted.iter().map(|&v| v as f64).collect();
    let decrypted = encryptor.decrypt(&f64_vec)?;
    Ok(decrypted.iter().map(|&v| v as f32).collect())
}

/// Matrix-vector multiplication (row-major matrix).
fn mat_vec_mul(matrix: &[f64], vector: &[f64], dim: usize) -> Vec<f64> {
    (0..dim)
        .map(|i| {
            let row_start = i * dim;
            (0..dim).map(|j| matrix[row_start + j] * vector[j]).sum()
        })
        .collect()
}

/// Transpose a square matrix (row-major).
fn transpose(matrix: &[f64], dim: usize) -> Vec<f64> {
    let mut result = vec![0.0; dim * dim];
    for i in 0..dim {
        for j in 0..dim {
            result[j * dim + i] = matrix[i * dim + j];
        }
    }
    result
}

/// Gram-Schmidt orthogonalization (in-place, row-major).
fn gram_schmidt(matrix: &mut [f64], dim: usize) -> Result<()> {
    for i in 0..dim {
        // Subtract projections onto previous rows
        for j in 0..i {
            let dot = dot_rows(matrix, i, j, dim);
            let norm_sq = dot_rows(matrix, j, j, dim);
            if norm_sq < 1e-10 {
                bail!("Gram-Schmidt failed: degenerate matrix (row {} near-zero)", j);
            }
            let scale = dot / norm_sq;
            for k in 0..dim {
                let val = matrix[j * dim + k];
                matrix[i * dim + k] -= scale * val;
            }
        }

        // Normalize
        let norm = dot_rows(matrix, i, i, dim).sqrt();
        if norm < 1e-10 {
            bail!("Gram-Schmidt failed: zero norm at row {}", i);
        }
        for k in 0..dim {
            matrix[i * dim + k] /= norm;
        }
    }
    Ok(())
}

/// Dot product of two rows in a row-major matrix.
fn dot_rows(matrix: &[f64], row_a: usize, row_b: usize, dim: usize) -> f64 {
    let a_start = row_a * dim;
    let b_start = row_b * dim;
    let mut sum = 0.0;
    for k in 0..dim {
        sum += matrix[a_start + k] * matrix[b_start + k];
    }
    sum
}

/// Compute cosine similarity between two vectors.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm_a < 1e-10 || norm_b < 1e-10 {
        return 0.0;
    }
    dot / (norm_a * norm_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    fn test_config(dim: usize) -> AdcpeConfig {
        AdcpeConfig {
            dimensions: dim,
            noise_scale: 0.0,
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(4)).unwrap();
        let original = vec![1.0, 2.0, 3.0, 4.0];

        let encrypted = enc.encrypt(&original).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        for (a, b) in original.iter().zip(decrypted.iter()) {
            assert!((a - b).abs() < 1e-10, "Roundtrip failed: {} vs {}", a, b);
        }
    }

    #[test]
    fn test_cosine_similarity_preserved() {
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(8)).unwrap();

        let a = vec![1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0];
        let b = vec![0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0];
        let c = vec![1.0, 0.1, 1.0, 0.1, 1.0, 0.1, 1.0, 0.1];

        let cos_ab_orig = cosine_similarity(&a, &b);
        let cos_ac_orig = cosine_similarity(&a, &c);

        let ea = enc.encrypt(&a).unwrap();
        let eb = enc.encrypt(&b).unwrap();
        let ec = enc.encrypt(&c).unwrap();

        let cos_ab_enc = cosine_similarity(&ea, &eb);
        let cos_ac_enc = cosine_similarity(&ea, &ec);

        assert!(
            (cos_ab_orig - cos_ab_enc).abs() < 1e-10,
            "Cosine AB not preserved: {} vs {}",
            cos_ab_orig, cos_ab_enc
        );
        assert!(
            (cos_ac_orig - cos_ac_enc).abs() < 1e-10,
            "Cosine AC not preserved: {} vs {}",
            cos_ac_orig, cos_ac_enc
        );
    }

    #[test]
    fn test_encrypted_vectors_differ() {
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(4)).unwrap();
        let v = vec![1.0, 2.0, 3.0, 4.0];
        let encrypted = enc.encrypt(&v).unwrap();

        // Encrypted should NOT equal original
        assert_ne!(v, encrypted);
    }

    #[test]
    fn test_different_keys_produce_different_output() {
        let config = test_config(4);
        let v = vec![1.0, 2.0, 3.0, 4.0];

        let mut enc1 = AdcpeEncryptor::new(&[0xAB; 32], &config).unwrap();
        let mut enc2 = AdcpeEncryptor::new(&[0xCD; 32], &config).unwrap();

        let e1 = enc1.encrypt(&v).unwrap();
        let e2 = enc2.encrypt(&v).unwrap();

        assert_ne!(e1, e2);
    }

    #[test]
    fn test_dimension_mismatch_error() {
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(4)).unwrap();
        let wrong_dim = vec![1.0, 2.0, 3.0]; // 3 instead of 4

        assert!(enc.encrypt(&wrong_dim).is_err());
    }

    #[test]
    fn test_batch_encrypt_decrypt() {
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(4)).unwrap();
        let vectors = vec![
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 0.0, 1.0, 0.0],
        ];

        let encrypted = enc.encrypt_batch(&vectors).unwrap();
        assert_eq!(encrypted.len(), 3);

        let decrypted = enc.decrypt_batch(&encrypted).unwrap();
        for (orig, dec) in vectors.iter().zip(decrypted.iter()) {
            for (a, b) in orig.iter().zip(dec.iter()) {
                assert!((a - b).abs() < 1e-10);
            }
        }
    }

    #[test]
    fn test_f32_roundtrip() {
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(4)).unwrap();
        let original: Vec<f32> = vec![0.1, 0.2, 0.3, 0.4];

        let encrypted = encrypt_f32(&mut enc, &original).unwrap();
        let decrypted = decrypt_f32(&enc, &encrypted).unwrap();

        for (a, b) in original.iter().zip(decrypted.iter()) {
            assert!((a - b).abs() < 1e-5, "f32 roundtrip: {} vs {}", a, b);
        }
    }

    #[test]
    fn test_noise_adds_distortion() {
        let config = AdcpeConfig {
            dimensions: 4,
            noise_scale: 0.01,
        };
        let mut enc = AdcpeEncryptor::new(&test_key(), &config).unwrap();
        let v = vec![1.0, 2.0, 3.0, 4.0];

        let encrypted = enc.encrypt(&v).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();

        // With noise, roundtrip won't be exact
        let max_err: f64 = v.iter().zip(decrypted.iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0, f64::max);

        assert!(max_err > 1e-12, "Expected some distortion from noise");
        assert!(max_err < 1.0, "Distortion too large: {}", max_err);
    }

    #[test]
    fn test_orthogonality() {
        // Verify the matrix is orthogonal: Q * Q^T = I
        let enc = AdcpeEncryptor::new(&test_key(), &test_config(4)).unwrap();
        let dim = enc.dim;

        for i in 0..dim {
            for j in 0..dim {
                let dot = dot_rows(&enc.matrix, i, j, dim);
                let expected = if i == j { 1.0 } else { 0.0 };
                assert!(
                    (dot - expected).abs() < 1e-10,
                    "Not orthogonal at ({}, {}): {} vs {}",
                    i, j, dot, expected
                );
            }
        }
    }

    #[test]
    fn test_realistic_embedding_dimensions() {
        // Test with realistic dimensions (128, simulating a small model)
        let mut enc = AdcpeEncryptor::new(&test_key(), &test_config(128)).unwrap();

        let mut rng = StdRng::seed_from_u64(42);
        let a: Vec<f64> = (0..128).map(|_| rng.gen::<f64>() - 0.5).collect();
        let b: Vec<f64> = (0..128).map(|_| rng.gen::<f64>() - 0.5).collect();

        let cos_orig = cosine_similarity(&a, &b);

        let ea = enc.encrypt(&a).unwrap();
        let eb = enc.encrypt(&b).unwrap();

        let cos_enc = cosine_similarity(&ea, &eb);

        assert!(
            (cos_orig - cos_enc).abs() < 1e-10,
            "Cosine not preserved at dim=128: {} vs {}",
            cos_orig, cos_enc
        );
    }
}
