/// The bits of security this crate attempts to guarantee.
pub const SECURITY_PARAMETER: usize = 128;
/// Because of the birthday bound, our hashes need twice that number of bits.
pub const HASH_SIZE: usize = 2 * SECURITY_PARAMETER;
/// The number of bytes making up our hash size.
pub const HASH_SIZE_BYTES: usize = (HASH_SIZE + 7) / 8;
/// Enough for a tiny amount under 128 bits of security.
pub const REPETITIONS: usize = 218;
/// The context string used for our PRNG.
///
/// This provides some level of domain seperation for the random bytes we
/// generate from a seed.
pub const PRNG_CONTEXT: &str = "boo-hoo v0 PRNG CONTEXT";
/// The context string we use for generating challenges.
///
/// This separates the domain of our hash from future versions of proofs as well.
pub const CHALLENGE_CONTEXT: &str = "boo-hoo v0 challenge CONTEXT";
