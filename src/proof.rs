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

/// Represents the view of a single party in the MPC protocol.
struct View {
    seed: Seed,
    input: BitBuf,
    messages: BitBuf,
}

struct TriSimulation {
    views: [View; 3],
    outputs: [BitBuf; 3],
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
        let rngs = [0, 1, 2].map(|i| BitPRNG::seeded(&seeds[i]));
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

    fn and(&mut self) {
        let mask_bits = [0, 1, 2].map(|i| self.rngs[i].next_bit());
        let inputs = [0, 1, 2].map(|i| {
            let stack = &mut self.stacks[i];
            // Safe, because of program validation
            let bit0 = unsafe { stack.pop().unwrap_unchecked() };
            let bit1 = unsafe { stack.pop().unwrap_unchecked() };
            (bit0, bit1)
        });

        for i0 in 0..3 {
            let i1 = (i0 + 1) % 3;

            // This is (one component of) an XOR secret sharing of the and of the value
            let res = (inputs[i0].0 & inputs[i0].1)
                ^ (inputs[i0].0 & inputs[i1].1)
                ^ (inputs[i1].0 & inputs[i1].1)
                ^ mask_bits[i0]
                ^ mask_bits[i1];

            // Since this involves "communication" between the simulated parties,
            // we record having received this message
            self.messages[i0].push(res);
            self.stacks[i0].push(res);
        }
    }

    /// Advance the state through a ^ operation.
    fn xor(&mut self) {
        for stack in &mut self.stacks {
            // Both safe, because the program was validated
            let bit0 = unsafe { stack.pop().unwrap_unchecked() };
            let bit1 = unsafe { stack.pop().unwrap_unchecked() };
            // We can do this entirely locally, because of XOR secret sharing.
            stack.push(bit0 ^ bit1);
        }
    }

    /// Advance the state through a push local operation.
    fn push_arg(&mut self, iu32: u32) {
        let i = iu32 as usize;

        for (stack, input) in self.stacks.iter_mut().zip(self.inputs.iter()) {
            // Safe because we validated that the inputs were long enough.
            let arg = unsafe { input.get(i).unwrap_unchecked() };
            stack.push(arg);
        }
    }

    /// Advance the state through a push local operation.
    fn push_local(&mut self, iu32: u32) {
        let i = iu32 as usize;

        for stack in &mut self.stacks {
            // Safe, once again, because of program validation
            let local = unsafe { stack.get(i).unwrap_unchecked() };
            stack.push(local);
        }
    }

    fn op(&mut self, op: Operation) {
        match op {
            Operation::Not => self.not(),
            Operation::And => self.and(),
            Operation::Xor => self.xor(),
            Operation::PushArg(i) => self.push_arg(i),
            Operation::PushLocal(i) => self.push_local(i),
        }
    }

    /// Run the simulation, producing the result.
    ///
    /// The result contains the views of each party, along with the outputs.
    pub fn run(mut self, program: &ValidatedProgram) -> TriSimulation {
        for op in &program.operations {
            self.op(*op);
        }
        // Safe because we know that 3 results will be produced
        let views = unsafe {
            self.seeds
                .into_iter()
                .zip(self.inputs.into_iter())
                .zip(self.messages.into_iter())
                .map(|((seed, input), messages)| View {
                    seed,
                    input,
                    messages,
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_unchecked()
        };
        let outputs = self.stacks;
        TriSimulation { views, outputs }
    }
}
