use std::fmt::Debug;

/// Represents a single bit.
///
/// This is a convenience wrapper over a u64, but satisfying the invariant that
/// only the LSB can be set.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Bit(u64);

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
}

impl From<Bit> for u64 {
    fn from(b: Bit) -> Self {
        b.0
    }
}

/// Represents a buffer containing bits.
///
/// This is used to hold our working stack.
#[derive(Debug, Clone, PartialEq)]
struct BitBuf {
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
        unsafe { self.bits.last_mut().unwrap_unchecked() }
    }
}

impl BitBuf {
    /// Create a new, empty buffer.
    pub fn new() -> Self {
        Self {
            bits: Vec::new(),
            index: 0,
        }
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
        self.bits.get(index >> 6).map(|x| Bit(x & ((1 << 6) - 1)))
    }

    /// Return the number of bits held in this buffer.
    pub fn len(&self) -> usize {
        // No underflow since the buffer is never empty
        64 * (self.bits.len() - 1) + self.index
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
}
