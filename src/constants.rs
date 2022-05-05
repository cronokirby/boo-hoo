/// The bits of security this crate attempts to guarantee.
pub const SECURITY_PARAMETER: usize = 128;
/// Because of the birthday bound, our hashes need twice that number of bits.
pub const HASH_SIZE: usize = 2 * SECURITY_PARAMETER;
/// The number of bytes making up our hash size.
pub const HASH_SIZE_BYTES: usize = (HASH_SIZE + 7) / 8;
