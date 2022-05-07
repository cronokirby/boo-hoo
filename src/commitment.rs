use crate::constants::HASH_SIZE_BYTES;
use bincode::{config, encode_into_std_write, Decode, Encode};
use blake3::KEY_LEN;
use rand_core::{CryptoRng, RngCore};

/// The blinding factor for a commitment
///
/// We reveal this in order to demonstrate that a given value was inside some
/// commitment.
#[derive(Clone, Default, Encode, Decode)]
pub struct Decommitment([u8; KEY_LEN]);

impl Decommitment {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut out = [0u8; KEY_LEN];
        rng.fill_bytes(&mut out);
        Self(out)
    }
}

/// A commitment to some value.
///
/// This commitment can be published in advance, and is tied to some value.
/// The commitment doesn't reveal anything about the value, but we can later
/// "open" it, demonstrating that a value had been contained inside.
#[derive(Clone, Encode, Decode, PartialEq)]
pub struct Commitment([u8; HASH_SIZE_BYTES]);

fn make_commitment<T: Encode>(decommitment: &Decommitment, value: &T) -> Commitment {
    let mut hasher = blake3::Hasher::new_keyed(&decommitment.0);
    // Unwrapping here makes sense. Writing to the hasher won't fail because of IO.
    // We also only ever commit to one type of value. If encoding that value were
    // to fail, that would indicate a programming error on our part. Regardless,
    // the end user of our proof library certainly couldn't do anything about it.
    encode_into_std_write(value, &mut hasher, config::standard())
        .expect("Failed to write value in commitment");
    let mut out = [0u8; HASH_SIZE_BYTES];
    hasher.finalize_xof().fill(&mut out);
    Commitment(out)
}

/// Commit to a value.
///
/// This produces a commitment binding to that value, as well as a decommitment
/// we can use to open the commitment later. We need randomness to hide the
/// value being committed to.
pub fn commit<T: Encode, R: RngCore + CryptoRng>(
    rng: &mut R,
    value: &T,
) -> (Commitment, Decommitment) {
    let decommitment = Decommitment::random(rng);
    let commitment = make_commitment(&decommitment, value);
    (commitment, decommitment)
}

/// Check that a value was indeed contained inside of a commitment.
///
/// This function is, in theory, allowed to leak information about the value.
pub fn decommit<T: Encode>(
    value: &T,
    commitment: &Commitment,
    decommitment: &Decommitment,
) -> bool {
    let recommitment = make_commitment(decommitment, value);
    recommitment == *commitment
}

#[cfg(test)]
mod test {
    use super::*;

    use proptest::prelude::*;
    use rand_core::OsRng;

    proptest! {
        #[test]
        fn test_commit_then_decommit(x in any::<u64>()) {
            let (com, decom) = commit(&mut OsRng, &x);
            assert!(decommit(&x, &com, &decom));
        }
    }

    proptest! {
        #[test]
        fn test_commit_to_different_values(x in any::<u64>(), y in any::<u64>()) {
            let (com, decom) = commit(&mut OsRng, &x);
            assert!(x == y || !decommit(&y, &com, &decom));
        }
    }
}
