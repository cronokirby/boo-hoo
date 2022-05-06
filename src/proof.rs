use crate::bits::*;
use crate::commitment;
use crate::commitment::Commitment;
use crate::commitment::Decommitment;
use crate::constants::REPETITIONS;
use crate::program::*;
use crate::rng::{BitPRNG, Seed};
use bincode::Decode;
use bincode::Encode;
use bincode::{config, encode_into_std_write};
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
#[derive(Clone, Encode, Decode)]
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

pub struct Proof {
    commitments: Vec<Commitment>,
    decommitments: Vec<Decommitment>,
    views: Vec<View>,
}

const CHALLENGE_CONTEXT: &'static str = "boo-hoo v0.1.0 challenge context";

/// An internal function for creating a proof, after validating inputs.
///
/// The buffers for input and output must have the exact right length for the program.
fn do_prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    program: &ValidatedProgram,
    input: &BitBuf,
    output: &BitBuf,
) -> Proof {
    let config = config::standard();
    let mut hasher = blake3::Hasher::new_derive_key(CHALLENGE_CONTEXT);
    encode_into_std_write(&program.operations, &mut hasher, config).unwrap();
    encode_into_std_write(&output, &mut hasher, config).unwrap();

    let mut commitments = Vec::with_capacity(REPETITIONS * 3);
    let mut all_decommitments = Vec::with_capacity(REPETITIONS * 3);
    let mut all_views = Vec::with_capacity(REPETITIONS * 3);

    for _ in 0..REPETITIONS {
        let simulation = TriSimulator::create(rng, input.clone()).run(program);

        for view in simulation.views {
            let (com, decom) = commitment::commit(rng, &view);
            encode_into_std_write(&com, &mut hasher, config).unwrap();
            commitments.push(com);
            all_decommitments.push(decom);
            all_views.push(view);
        }
    }

    let mut bit_rng = BitPRNG::from_hasher(hasher);

    let mut decommitments = Vec::with_capacity(REPETITIONS * 2);
    let mut views = Vec::with_capacity(REPETITIONS * 2);

    let mut trit = 0;
    for (i, (decom, view)) in all_decommitments
        .into_iter()
        .zip(all_views.into_iter())
        .enumerate()
    {
        let i_mod_3 = (i % 3) as u8;
        if i_mod_3 == 0 {
            trit = bit_rng.next_trit();
        }
        if i_mod_3 != trit && i_mod_3 != (trit + 1) % 3 {
            continue;
        }
        decommitments.push(decom);
        views.push(view);
    }

    Proof {
        commitments,
        decommitments,
        views,
    }
}
pub enum Error {}

pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    program: &ValidatedProgram,
    input: &[u8],
    output: &[u8],
) -> Result<Proof, Error> {
    todo!()
}
