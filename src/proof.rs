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

/// The and function between two parties.
///
/// When computing an and operation, each party needs the input from the party
/// adjacent to them, and the mask bit from the party adjacent to them. This
/// results in their secret share of the and operation.
fn and(input_a: (Bit, Bit), input_b: (Bit, Bit), mask_a: Bit, mask_b: Bit) -> Bit {
    (input_a.0 & input_a.1) ^ (input_a.0 & input_b.1) & (input_b.0 & input_a.1) ^ mask_a ^ mask_b
}

/// Represents
#[derive(Clone)]
struct Machine {
    input: BitBuf,
    stack: BitBuf,
}

impl Machine {
    fn new(input: BitBuf) -> Self {
        Self {
            input,
            stack: BitBuf::new(),
        }
    }

    /// Pop a bit off the stack.
    ///
    /// This is UB of the stack is empty. This is why validating the program
    /// being run is important.
    fn pop(&mut self) -> Bit {
        unsafe { self.stack.pop().unwrap_unchecked() }
    }

    /// Push a bit onto the stack.
    fn push(&mut self, bit: Bit) {
        self.stack.push(bit);
    }

    /// Negate the top bit on the stack.
    fn not(&mut self) {
        let top = self.pop();
        self.push(!top);
    }

    /// xor the top two bits off the stack.
    fn xor(&mut self) {
        let a = self.pop();
        let b = self.pop();
        self.push(a ^ b);
    }

    /// Push a bit of the input onto the stack.
    fn push_arg(&mut self, i: usize) {
        let arg = unsafe { self.input.get(i).unwrap_unchecked() };
        self.push(arg);
    }

    /// Push a bit from the stack back onto the stack.
    fn push_local(&mut self, i: usize) {
        // Safe, once again, because of program validation
        let local = unsafe { self.stack.get(i).unwrap_unchecked() };
        self.push(local);
    }
}

//
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
    machines: [Machine; 3],
    messages: [BitBuf; 3],
}

impl TriSimulator {
    /// Create a new trisimulator, initialized with some secret input.
    pub fn create<R: RngCore + CryptoRng>(rng: &mut R, input: BitBuf) -> Self {
        let seeds = [(); 3].map(|_| Seed::random(rng));
        let rngs = [0, 1, 2].map(|i| BitPRNG::seeded(&seeds[i]));
        let inputs = split(rng, input);
        let machines = inputs.map(|input| Machine::new(input));
        let messages = [(); 3].map(|_| BitBuf::new());
        Self {
            seeds,
            rngs,
            machines,
            messages,
        }
    }

    fn and(&mut self) {
        let mask_bits = [0, 1, 2].map(|i| self.rngs[i].next_bit());
        let inputs = [0, 1, 2].map(|i| {
            let machine = &mut self.machines[i];
            let bit0 = machine.pop();
            let bit1 = machine.pop();
            (bit0, bit1)
        });

        for i0 in 0..3 {
            let i1 = (i0 + 1) % 3;

            let res = and(inputs[i0], inputs[i1], mask_bits[i0], mask_bits[i1]);

            // Since this involves "communication" between the simulated parties,
            // we record having received this message
            self.messages[i0].push(res);
            self.machines[i0].push(res);
        }
    }

    fn op(&mut self, op: Operation) {
        match op {
            Operation::Not => {
                for machine in &mut self.machines {
                    machine.not();
                }
            }
            Operation::And => self.and(),
            Operation::Xor => {
                for machine in &mut self.machines {
                    machine.xor();
                }
            }
            Operation::PushArg(i) => {
                let i_usize = i as usize;
                for machine in &mut self.machines {
                    machine.push_arg(i_usize);
                }
            }
            Operation::PushLocal(i) => {
                let i_usize = i as usize;
                for machine in &mut self.machines {
                    machine.push_local(i_usize);
                }
            }
        }
    }

    /// Run the simulation, producing the result.
    ///
    /// The result contains the views of each party, along with the outputs.
    pub fn run(mut self, program: &ValidatedProgram) -> TriSimulation {
        for op in &program.operations {
            self.op(*op);
        }
        let mut views = Vec::with_capacity(3);
        let mut outputs = Vec::with_capacity(3);
        for ((seed, machine), messages) in self
            .seeds
            .into_iter()
            .zip(self.machines.into_iter())
            .zip(self.messages.into_iter())
        {
            views.push(View {
                seed,
                input: machine.input,
                messages,
            });
            outputs.push(machine.stack);
        }
        let views = unsafe { views.try_into().unwrap_unchecked() };
        let outputs = unsafe { outputs.try_into().unwrap_unchecked() };
        TriSimulation { views, outputs }
    }
}

pub struct Proof {
    commitments: Vec<Commitment>,
    outputs: Vec<BitBuf>,
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
    encode_into_std_write(REPETITIONS, &mut hasher, config).unwrap();

    let mut commitments = Vec::with_capacity(REPETITIONS * 3);
    let mut outputs = Vec::with_capacity(REPETITIONS * 3);
    let mut all_decommitments = Vec::with_capacity(REPETITIONS * 3);
    let mut all_views = Vec::with_capacity(REPETITIONS * 3);

    for _ in 0..REPETITIONS {
        let simulation = TriSimulator::create(rng, input.clone()).run(program);

        for output in simulation.outputs {
            outputs.push(output);
        }

        for view in simulation.views {
            let (com, decom) = commitment::commit(rng, &view);
            commitments.push(com);
            all_decommitments.push(decom);
            all_views.push(view);
        }
    }
    encode_into_std_write(&commitments, &mut hasher, config).unwrap();
    encode_into_std_write(&outputs, &mut hasher, config).unwrap();

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
        outputs,
        decommitments,
        views,
    }
}
pub enum Error {
    InsufficientInput(usize),
    InsufficientOutput(usize),
}

pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    program: &ValidatedProgram,
    input: &[u8],
    output: &[u8],
) -> Result<Proof, Error> {
    let mut input_buf = BitBuf::from_bytes(input);
    let mut output_buf = BitBuf::from_bytes(output);
    if input_buf.len() < program.input_count {
        return Err(Error::InsufficientInput(input_buf.len()));
    }
    if output_buf.len() < program.output_count {
        return Err(Error::InsufficientOutput(output_buf.len()));
    }
    input_buf.resize(program.input_count);
    output_buf.resize(program.output_count);
    Ok(do_prove(rng, program, &input_buf, &output_buf))
}
