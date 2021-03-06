use bincode::{Decode, Encode};
use rand_core::{CryptoRng, RngCore};

use crate::bits::Bit;
use crate::constants::PRNG_CONTEXT;

/// The number of bytes in an RNG seed
const SEED_LEN: usize = blake3::KEY_LEN;

/// Represents the seed to a pseudo-random RNG.
#[derive(Debug, Default, Encode, Decode, Clone)]
pub struct Seed([u8; blake3::KEY_LEN]);

impl Seed {
    /// Generate a random Seed.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; SEED_LEN];
        rng.fill_bytes(&mut bytes[..]);
        Self(bytes)
    }
}

/// The number of bytes we buffer in our RNG.
///
/// Using 64 is a good match with the XOF output from BLAKE3.
const BUF_LEN: usize = 64;

/// A Pseudo-Random generator of bits.
///
/// This is intended to be created from a random seed, providing us with a
/// deterministic source of random bits. This is useful when simulating
/// the MPC protocol in a reproducible way.
#[derive(Clone)]
pub struct BitPRNG {
    reader: blake3::OutputReader,
    /// The buffer holding the next bits of output from the XOF.
    ///
    /// This will always be initialized to some output.
    buf: [u8; BUF_LEN],
    /// The next bit index within that buffer to read from.
    bit_index: usize,
}

impl BitPRNG {
    fn fill_buf(&mut self) {
        self.reader.fill(&mut self.buf);
    }
}

impl BitPRNG {
    /// Create a BitPRNG from a seed.
    ///
    /// This seed entirely determines the stream of bits that this RNG will
    /// produce from that point on.
    pub fn seeded(seed: &Seed) -> Self {
        // We extend the seed to an arbitrary stream of bits, with some domain separation.
        let mut hasher = blake3::Hasher::new_keyed(&seed.0);
        hasher.update(PRNG_CONTEXT.as_bytes());
        Self::from_hasher(hasher)
    }

    /// Create a BitPRNG from a blake3 hasher.
    ///
    /// This will finalize the hasher, and then read bits from its output.
    pub fn from_hasher(hasher: blake3::Hasher) -> Self {
        let reader = hasher.finalize_xof();
        // Create the output with an uninitialized buffer, but fill it immediately
        let mut out = Self {
            reader,
            buf: [0; BUF_LEN],
            bit_index: 0,
        };
        out.fill_buf();
        out
    }

    /// Read the next bit from the output stream of this RNG.
    pub fn next_bit(&mut self) -> Bit {
        if self.bit_index >= 8 * BUF_LEN {
            self.bit_index = 0;
            self.fill_buf();
        }
        let index = self.bit_index;
        self.bit_index += 1;
        // This should optimize to shifts and masks
        Bit::select_u8(self.buf[index / 8], index % 8)
    }

    /// Read the next value mod 3 from the output stream of this RNG
    pub fn next_trit(&mut self) -> u8 {
        loop {
            let a = u64::from(self.next_bit()) as u8;
            let b = u64::from(self.next_bit()) as u8;
            let trit = (a << 1) | b;
            if trit < 3 {
                return trit;
            }
        }
    }
}
