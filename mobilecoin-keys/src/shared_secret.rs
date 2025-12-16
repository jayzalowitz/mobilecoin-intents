//! Shared secret computation for key derivation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha3::{Digest, Sha3_256};

use crate::{RistrettoPrivate, RistrettoPublic};

/// Domain separator for shared secret derivation.
const SHARED_SECRET_DOMAIN: &[u8] = b"mc_shared_secret";

/// Compute the shared secret for key derivation.
///
/// This implements the Diffie-Hellman shared secret with hashing:
/// ```text
/// s = Hs(r*A, index) = Hs(a*R, index)
/// ```
///
/// # Arguments
/// * `public_key` - The other party's public key (A or R)
/// * `private_key` - Our private key (r or a)
/// * `output_index` - The output index for domain separation
///
/// # Returns
/// A scalar that can be used for key derivation.
pub fn compute_shared_secret(
    public_key: &RistrettoPublic,
    private_key: &RistrettoPrivate,
    output_index: u64,
) -> Scalar {
    // Decompress the public key.
    //
    // Security: do not panic on invalid points, since these APIs may be used
    // with untrusted inputs (e.g., parsing transaction data or external
    // addresses). An invalid point results in a deterministic "non-secret"
    // shared secret, which will not match any valid output ownership checks.
    let Some(point) = public_key.decompress() else {
        return hash_to_scalar_with_index(&RistrettoPoint::identity(), output_index);
    };

    // Compute DH: private_key * public_key
    let dh_point = private_key.as_scalar() * point;

    // Hash to scalar with output index
    hash_to_scalar_with_index(&dh_point, output_index)
}

/// Compute shared secret from a point and scalar directly.
///
/// This is used when we already have the raw cryptographic values.
#[cfg(test)]
pub(crate) fn compute_shared_secret_raw(
    point: &RistrettoPoint,
    scalar: &Scalar,
    output_index: u64,
) -> Scalar {
    let dh_point = scalar * point;
    hash_to_scalar_with_index(&dh_point, output_index)
}

/// Hash a Ristretto point to a scalar.
///
/// Uses SHA3-256 with domain separation.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(SHARED_SECRET_DOMAIN);
    hasher.update(data);
    let hash = hasher.finalize();

    // Interpret as scalar (mod order)
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order(bytes)
}

/// Hash a point and index to a scalar.
fn hash_to_scalar_with_index(point: &RistrettoPoint, index: u64) -> Scalar {
    let mut hasher = Sha3_256::new();
    hasher.update(SHARED_SECRET_DOMAIN);
    hasher.update(point.compress().as_bytes());
    hasher.update(index.to_le_bytes());
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order(bytes)
}

/// Hash a point to a point (for key images).
///
/// Uses hash-to-curve via hashing to scalar and multiplying by base point.
pub fn hash_to_point(point: &RistrettoPublic) -> RistrettoPoint {
    let scalar = hash_to_scalar(point.as_bytes());
    RISTRETTO_BASEPOINT_TABLE.basepoint() * scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret_symmetry() {
        // Alice and Bob generate key pairs
        let alice_private = RistrettoPrivate::generate();
        let alice_public = alice_private.public_key();

        let bob_private = RistrettoPrivate::generate();
        let bob_public = bob_private.public_key();

        // Both compute the same shared secret
        let alice_secret = compute_shared_secret(&bob_public, &alice_private, 0);
        let bob_secret = compute_shared_secret(&alice_public, &bob_private, 0);

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_different_indices_different_secrets() {
        let alice_private = RistrettoPrivate::generate();
        let bob_private = RistrettoPrivate::generate();
        let bob_public = bob_private.public_key();

        let secret0 = compute_shared_secret(&bob_public, &alice_private, 0);
        let secret1 = compute_shared_secret(&bob_public, &alice_private, 1);

        assert_ne!(secret0, secret1);
    }

    #[test]
    fn test_hash_to_scalar_deterministic() {
        let data = b"test data";
        let scalar1 = hash_to_scalar(data);
        let scalar2 = hash_to_scalar(data);

        assert_eq!(scalar1, scalar2);
    }

    #[test]
    fn test_hash_to_scalar_different_data() {
        let scalar1 = hash_to_scalar(b"data1");
        let scalar2 = hash_to_scalar(b"data2");

        assert_ne!(scalar1, scalar2);
    }
}
