use crate::bits::*;
use crate::program::*;
use crate::rng::{BitPRNG, Seed};
use rand_core::{CryptoRng, RngCore};

/// Split a BitBuf into 3 shares which xor to form the original input.
fn split<R: RngCore + CryptoRng>(rng: &mut R, input: BitBuf) -> [BitBuf; 3] {
    let len = input.len();
    let len_bytes = (7 + len) / 8;
    let mut bytes = vec![0u8; len_bytes];

    rng.fill_bytes(&mut bytes);
    let buf0 = BitBuf::from_bytes(&bytes);

    rng.fill_bytes(&mut bytes);
    let buf1 = BitBuf::from_bytes(&bytes);

    // Now, as a result, some of the upper bits in buf2 may be different,
    // but our program has been validated, and will never access these.
    let mut buf2 = input;
    buf2.xor(&buf0);
    buf2.xor(&buf1);

    [buf0, buf1, buf2]
}

struct TriSimulation {
    seeds: [Seed; 3],
    inputs: [BitBuf; 3],
    outputs: [BitBuf; 3],
    messages: [BitBuf; 3],
}

struct TriSimulator {
    seeds: [Seed; 3],
    rngs: [BitPRNG; 3],
    inputs: [BitBuf; 3],
    stacks: [BitBuf; 3],
    messages: [BitBuf; 3],
}

impl TriSimulator {
    /// Create a new trisimulator, initialized with some secret input.
    pub fn create<R: RngCore + CryptoRng>(rng: &mut R, input: BitBuf) -> Self {
        let seeds = [(); 3].map(|_| Seed::random(rng));
        let rngs = [1, 2, 3].map(|i| BitPRNG::seeded(&seeds[i]));
        let inputs = split(rng, input);
        // Empty stacks and messages
        let stacks = [(); 3].map(|_| BitBuf::new());
        let messages = stacks.clone();
        Self {
            seeds,
            rngs,
            inputs,
            stacks,
            messages,
        }
    }

    /// Advance the state through a ! operation.
    fn not(&mut self) {
        for stack in &mut self.stacks {
            // Safe, because the program was validated
            let bit = unsafe { stack.pop().unwrap_unchecked() };
            stack.push(!bit);
        }
    }

    fn op(&mut self, op: Operation) {
        match op {
            Operation::Not => self.not(),
            Operation::And => todo!(),
            Operation::Xor => todo!(),
            Operation::PushArg(_) => todo!(),
            Operation::PushLocal(_) => todo!(),
        }
    }

    pub fn run(self) -> TriSimulation {
        todo!()
    }
}
