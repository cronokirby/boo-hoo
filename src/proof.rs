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
    messages: [BitBuf; 3],
    outputs: [BitBuf; 3],
}

struct TriSimulator {
    seeds: [Seed; 3],
    rngs: [BitPRNG; 3],
    stacks: [BitBuf; 3],
}

impl TriSimulator {
    pub fn create<R: RngCore + CryptoRng>(rng: &mut R, input: BitBuf) -> Self {
        let seeds = [(); 3].map(|_| Seed::random(rng));
        todo!()
    }

    fn op(&mut self, op: Operation) {
        match op {
            Operation::Not => todo!(),
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
