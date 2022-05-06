use bincode::{
    de::Decoder,
    enc::Encoder,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};
use std::{fmt::Debug, ops};

/// Represents a single bit.
///
/// This is a convenience wrapper over a u64, but satisfying the invariant that
/// only the LSB can be set.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bit(u64);

impl Bit {
    /// Return the zero bit.
    pub fn zero() -> Self {
        Bit(0)
    }

    /// Select a given bit from some u64.
    pub fn select(x: u64, bit: usize) -> Self {
        debug_assert!(bit < 64);
        Self((x >> bit) & 1)
    }

    /// Select a given bit from some u8
    pub fn select_u8(x: u8, bit: usize) -> Self {
        debug_assert!(bit < 8);
        Self::select(x as u64, bit)
    }
}

impl From<Bit> for u64 {
    fn from(b: Bit) -> Self {
        b.0
    }
}

impl ops::BitXor for Bit {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out ^= rhs;
        out
    }
}

impl ops::BitXorAssign for Bit {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl ops::BitAnd for Bit {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mut out = self;
        out &= rhs;
        out
    }
}

impl ops::BitAndAssign for Bit {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl ops::Not for Bit {
    type Output = Self;

    fn not(self) -> Self::Output {
        // We don't want to negate anything but the first bit
        Self(1 ^ self.0)
    }
}

/// Represents a buffer containing bits.
///
/// This is used to hold our working stack.
#[derive(Debug, Clone, PartialEq)]
pub struct BitBuf {
    /// The underlying buffer containing our bits.
    ///
    /// This will *never* be empty.
    bits: Vec<u64>,
    /// 0 <= index < 64, representing where in the u64 the next bit should go.
    index: usize,
}

impl BitBuf {
    fn end(&mut self) -> &mut u64 {
        // This is safe because we guarantee that the buffer is never empty.
        self.bits.last_mut().unwrap()
    }
}

impl BitBuf {
    /// Create a new, empty buffer.
    pub fn new() -> Self {
        Self {
            bits: vec![0],
            index: 0,
        }
    }

    /// Create a bit buffer from bytes.
    ///
    /// The bits are considered to start at the lsb of bytes[0], and end at
    /// the msb of bytes[-1].
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let index = 8 * (bytes.len() % 8);
        let mut bits = Vec::with_capacity((bytes.len() + 7) / 8);
        bytes.chunks(8).for_each(|chunk| {
            let mut le_bytes = [0u8; 8];
            le_bytes[..chunk.len()].copy_from_slice(chunk);
            bits.push(u64::from_le_bytes(le_bytes));
        });
        Self { bits, index }
    }

    pub fn push(&mut self, bit: Bit) {
        *self.end() |= bit.0 << self.index;
        self.index += 1;
        // If the index reaches 64, we need to create a new empty slot for bits
        if self.index >= 64 {
            self.bits.push(0);
            self.index = 0;
        }
    }

    /// Return the top bit of the buffer.
    pub fn pop(&mut self) -> Option<Bit> {
        if self.index == 0 {
            if self.bits.is_empty() {
                return None;
            }
            self.index = 63;
            self.bits.pop();
        } else {
            self.index -= 1;
        }
        // The idea is to start with xxXxx, then select, to get 00X00, then ^ to
        // get xx0xx in the buf, and then shift to get 0000X.
        let selected = *self.end() & (1 << self.index);
        *self.end() ^= selected;
        let output = Bit(selected >> self.index);
        Some(output)
    }

    /// Get a bit in the buffer by index.
    pub fn get(&self, index: usize) -> Option<Bit> {
        // Since 64 = 2^6, we have the following logic:
        let hi = index >> 6;
        let lo = index & ((1 << 6) - 1);
        if lo >= self.index {
            return None;
        }
        self.bits.get(hi).map(|x| Bit((x >> lo) & 1))
    }

    /// Return the number of bits held in this buffer.
    pub fn len(&self) -> usize {
        // No underflow since the buffer is never empty
        64 * (self.bits.len() - 1) + self.index
    }

    /// Resize the buffer to a given number of bits, filling with zeros as necessary.
    pub fn resize(&mut self, bit_len: usize) {
        let len = bit_len / 64 + 1;
        self.index = bit_len % 64;
        self.bits.resize(len, 0);
        // Clear all the bits at the end of the buffer.
        *self.end() &= (1 << self.index) - 1;
    }

    /// Xor this buffer of bits with the bits of another.
    ///
    /// This is mainly useful when we split Buffers into multiple secret shares.
    pub(crate) fn xor(&mut self, other: &BitBuf) {
        for (self_i, other_i) in self.bits.iter_mut().zip(other.bits.iter()) {
            *self_i ^= other_i;
        }
        // Clear all the bits past the end of the buffer
        *self.end() &= (1 << self.index) - 1;
    }
}

impl Encode for BitBuf {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        self.len().encode(encoder)?;
        self.bits.encode(encoder)
    }
}

impl Decode for BitBuf {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let bit_len = usize::decode(decoder)?;
        let len = bit_len / 64 + 1;
        let index = len % 64;

        decoder.claim_container_read::<u64>(len)?;
        let mut bits = Vec::with_capacity(len);
        for _ in 0..len {
            decoder.unclaim_bytes_read(core::mem::size_of::<u64>());
            bits.push(u64::decode(decoder)?)
        }
        Ok(Self { bits, index })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use proptest::collection::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_bit_buf()(mut bits in vec(any::<u64>(), 1..100usize), index in 0..64usize) -> BitBuf {
            // Make sure that only the bits before index are set
            *bits.last_mut().unwrap() &= (1 << index) - 1;
            BitBuf { bits, index }
        }
    }

    proptest! {
        #[test]
        fn test_push_then_pop_is_identity(buf in arb_bit_buf(), x in any::<u64>(), index in 0..64usize) {
            let bit = Bit::select(x, index);
            let mut buf2 = buf.clone();
            buf2.push(bit);
            let bit2 = buf2.pop();
            assert_eq!(buf2, buf);
            assert_eq!(bit2, Some(bit));
        }
    }

    proptest! {
        #[test]
        fn test_push_increases_len_by_one(mut buf in arb_bit_buf()) {
            let start_len = buf.len();
            buf.push(Bit::select(0, 0));
            assert_eq!(buf.len(), start_len + 1);
        }
    }

    #[test]
    fn test_bitbuf_get() {
        let buf = BitBuf {
            bits: vec![0, 0b10],
            index: 2,
        };
        assert_eq!(buf.get(65), Some(Bit(1)));
        assert_eq!(buf.get(64), Some(Bit(0)));
        assert_eq!(buf.get(67), None);
    }

    #[test]
    fn test_bitbuf_from_bytes() {
        let buf = BitBuf::from_bytes(&[0xAB, 0xCD]);
        let expected = BitBuf {
            bits: vec![0xCDAB],
            index: 16,
        };
        assert_eq!(buf, expected);
    }
}
