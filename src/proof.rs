use std::fmt;
use std::io::Read;
use std::io::Write;

use crate::bits::*;
use crate::commitment;
use crate::commitment::Commitment;
use crate::commitment::Decommitment;
use crate::constants::{CHALLENGE_CONTEXT, REPETITIONS};
use crate::program::*;
use crate::rng::{BitPRNG, Seed};
use bincode::decode_from_std_read;
use bincode::encode_into_slice;
use bincode::encode_to_vec;
use bincode::error::DecodeError;
use bincode::error::EncodeError;
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
    let mut buf0 = BitBuf::from_bytes(&bytes);
    buf0.resize(input.len());

    rng.fill_bytes(&mut bytes);
    let mut buf1 = BitBuf::from_bytes(&bytes);
    buf1.resize(input.len());

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
    (input_a.0 & input_a.1) ^ (input_a.0 & input_b.1) ^ (input_b.0 & input_a.1) ^ mask_a ^ mask_b
}

/// Represents the view of a single party in the MPC protocol.
#[derive(Clone, Default, Debug, Encode, Decode)]
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
        let machines = inputs.map(Machine::new);
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
            Operation::PopOutput => {
                for machine in &mut self.machines {
                    machine.pop_output();
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
            let (input, output) = machine.input_output();
            views.push(View {
                seed,
                input: input,
                messages,
            });
            outputs.push(output);
        }
        let views = views.try_into().unwrap();
        let outputs = outputs.try_into().unwrap();
        TriSimulation { views, outputs }
    }
}

/// Represents a proof of knowledge of a pre-image of some arbitrary program.
///
/// This is generated through the `prove` function, and should be treated as
/// an opaque blob which can be verified through the `verify` function.
///
/// For serialization and deserialization, the Encode and Decode traits are provided,
/// which can be combined with [bincode](https://docs.rs/bincode/2.0.0-rc.1/bincode/index.html)
/// in order to serialize to bytes, or an arbitrary IO object.
///
/// This object also provides wrapper methods to implement those functions.
#[derive(Clone, Encode, Decode)]
pub struct Proof {
    commitments: Vec<Commitment>,
    outputs: Vec<BitBuf>,
    decommitments: Vec<Decommitment>,
    views: Vec<View>,
}

impl Proof {
    /// Encode this proof into a vector of bytes.
    ///
    /// In principle, this method shouldn't fail.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, EncodeError> {
        encode_to_vec(self, config::standard())
    }

    /// Encode this proof into an arbitrary object implementing `Write`.
    ///
    /// This will return the number of bytes written.
    pub fn encode_to_write<W: Write>(&self, dst: &mut W) -> Result<usize, EncodeError> {
        encode_into_std_write(self, dst, config::standard())
    }

    /// Decode this proof from an arbitrary object implementing `Read`.
    ///
    /// Note that this function will also work with `&[u8]`, since that implements `Read`.
    pub fn decode_from_read<R: Read>(src: &mut R) -> Result<Self, DecodeError> {
        decode_from_std_read(src, config::standard())
    }
}

/// Our challenge is a series of trits, which we draw from a PRNG.
fn challenge(
    ctx: &[u8],
    program: &ValidatedProgram,
    output: &BitBuf,
    commitments: &Vec<Commitment>,
    outputs: &Vec<BitBuf>,
) -> BitPRNG {
    fn update<E: Encode>(hasher: &mut blake3::Hasher, e: E) {
        encode_into_std_write(e, hasher, config::standard()).unwrap();
    }

    let mut hasher = blake3::Hasher::new_derive_key(CHALLENGE_CONTEXT);
    update(&mut hasher, ctx);
    update(&mut hasher, &program.operations);
    update(&mut hasher, output);
    update(&mut hasher, REPETITIONS);
    update(&mut hasher, commitments);
    update(&mut hasher, outputs);

    BitPRNG::from_hasher(hasher)
}

/// An internal function for creating a proof, after validkkoating inputs.
///
/// The buffers for input and output must have the exact right length for the program.
fn do_prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    ctx: &[u8],
    program: &ValidatedProgram,
    input: &BitBuf,
    output: &BitBuf,
) -> Proof {
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

    let mut bit_rng = challenge(ctx, program, output, &commitments, &outputs);

    let mut decommitments = Vec::with_capacity(REPETITIONS * 2);
    let mut views = Vec::with_capacity(REPETITIONS * 2);

    for i in (0..REPETITIONS).map(|i| i * 3) {
        let trit = bit_rng.next_trit() as usize;
        let i0 = i + trit;
        let i1 = i + ((trit + 1) % 3);
        for ij in [i0, i1] {
            decommitments.push(std::mem::take(&mut all_decommitments[ij]));
            views.push(std::mem::take(&mut all_views[ij]));
        }
    }

    Proof {
        commitments,
        outputs,
        decommitments,
        views,
    }
}

struct ReSimulation {
    primary_messages: BitBuf,
    outputs: [BitBuf; 2],
}

struct ReSimulator<'a> {
    primary_messages: BitBuf,
    secondary_messages: &'a BitBuf,
    secondary_messages_i: usize,
    rngs: [BitPRNG; 2],
    machines: [Machine; 2],
}

impl<'a> ReSimulator<'a> {
    fn new(inputs: [&'a BitBuf; 2], seeds: [&'a Seed; 2], secondary_messages: &'a BitBuf) -> Self {
        Self {
            primary_messages: BitBuf::new(),
            secondary_messages,
            secondary_messages_i: 0,
            rngs: seeds.map(BitPRNG::seeded),
            machines: inputs.map(|input| Machine::new(input.clone())),
        }
    }

    fn next_secondary_message(&mut self) -> Option<Bit> {
        let out = self.secondary_messages.get(self.secondary_messages_i);
        self.secondary_messages_i += 1;
        out
    }

    fn and(&mut self) -> Option<()> {
        let masks = [0, 1].map(|i| self.rngs[i].next_bit());
        let inputs = [0, 1].map(|i| {
            let machine = &mut self.machines[i];
            let bit0 = machine.pop();
            let bit1 = machine.pop();
            (bit0, bit1)
        });

        let res = and(inputs[0], inputs[1], masks[0], masks[1]);
        self.machines[0].push(res);
        self.primary_messages.push(res);
        // We just trust the secondary messages to be correct
        let next_message = self.next_secondary_message()?;
        self.machines[1].push(next_message);
        Some(())
    }

    fn op(&mut self, op: Operation) -> Option<()> {
        match op {
            Operation::Not => {
                for machine in &mut self.machines {
                    machine.not();
                }
            }
            Operation::And => self.and()?,
            Operation::Xor => {
                for machine in &mut self.machines {
                    machine.xor();
                }
            }
            Operation::PushArg(i) => {
                for machine in &mut self.machines {
                    machine.push_arg(i as usize)
                }
            }
            Operation::PushLocal(i) => {
                for machine in &mut self.machines {
                    machine.push_local(i as usize)
                }
            }
            Operation::PopOutput => {
                for machine in &mut self.machines {
                    machine.pop_output();
                }
            }
        }
        Some(())
    }

    /// Run the resimulation on a given program.
    ///
    /// This can potentially fail, if not enough messages are passed to the simulator.
    /// This indicates a bad proof.
    pub fn run(mut self, program: &ValidatedProgram) -> Option<ReSimulation> {
        for op in &program.operations {
            self.op(*op)?;
        }

        let primary_messages = self.primary_messages;
        let outputs = self.machines.map(|machine| machine.input_output().1);
        Some(ReSimulation {
            primary_messages,
            outputs,
        })
    }
}

/// Verify a single repetition of the proof.
///
/// The slices `commitments` and `outputs` should have 3 elements, and
/// `decommitments` and `views` should have 2 elements.
fn verify_repetition(
    program: &ValidatedProgram,
    output: &BitBuf,
    commitments: &[Commitment],
    outputs: &[BitBuf],
    trit: u8,
    decommitments: &[Decommitment],
    views: &[View],
) -> bool {
    // Check that the output is correct
    let mut actual_output = outputs[0].clone();
    actual_output.xor(&outputs[1]);
    actual_output.xor(&outputs[2]);

    if actual_output != *output {
        return false;
    }
    // Check input lengths
    if !(0..2).all(|i| views[i].input.len() == program.input_count) {
        return false;
    }

    let i = [trit as usize, ((trit + 1) % 3) as usize];

    // Check that the commitments are valid
    if !(0..2).all(|j| {
        let i_j = i[j];
        commitment::decommit(&views[j], &commitments[i_j], &decommitments[j])
    }) {
        return false;
    }

    // Check that the views are coherent, and produce the right output
    let re_simulation_result = ReSimulator::new(
        [&views[0].input, &views[1].input],
        [&views[0].seed, &views[1].seed],
        &views[1].messages,
    )
    .run(program);
    let re_simulation = match re_simulation_result {
        Some(x) => x,
        None => return false,
    };

    if re_simulation.primary_messages != views[0].messages {
        return false;
    }
    (0..2).all(|j| re_simulation.outputs[j] == outputs[i[j]])
}

fn do_verify(ctx: &[u8], program: &ValidatedProgram, output: &BitBuf, proof: &Proof) -> bool {
    // Check that the proof has enough content
    if proof.commitments.len() != 3 * REPETITIONS {
        return false;
    }
    if proof.outputs.len() != 3 * REPETITIONS {
        return false;
    }
    if proof.decommitments.len() != 2 * REPETITIONS {
        return false;
    }
    if proof.views.len() != 2 * REPETITIONS {
        return false;
    }

    let mut bit_rng = challenge(ctx, program, output, &proof.commitments, &proof.outputs);

    (0..REPETITIONS).all(|i| {
        let trit = bit_rng.next_trit();
        verify_repetition(
            program,
            output,
            &proof.commitments[3 * i..3 * (i + 1)],
            &proof.outputs[3 * i..3 * (i + 1)],
            trit,
            &proof.decommitments[2 * i..2 * (i + 1)],
            &proof.views[2 * i..2 * (i + 1)],
        )
    })
}

/// Represents an error that can happen when proving or verifying.
///
/// At the moment, errors only happen because the size of the input or the output
/// was insufficient for what the program expected. If too little input our output
/// is provided, then proving and verifying will fail.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    InsufficientInput(usize),
    InsufficientOutput(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InsufficientInput(i) => write!(f, "insufficient input of size {}", i),
            Error::InsufficientOutput(i) => write!(f, "insufficient output of size {}", i),
        }
    }
}

impl std::error::Error for Error {}

pub fn prove<R: RngCore + CryptoRng>(
    rng: &mut R,
    ctx: &[u8],
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
    Ok(do_prove(rng, ctx, program, &input_buf, &output_buf))
}

pub fn verify(
    ctx: &[u8],
    program: &ValidatedProgram,
    output: &[u8],
    proof: &Proof,
) -> Result<bool, Error> {
    let mut output_buf = BitBuf::from_bytes(output);
    if output_buf.len() < program.output_count {
        return Err(Error::InsufficientOutput(output_buf.len()));
    }
    output_buf.resize(program.output_count);

    Ok(do_verify(ctx, program, &output_buf, proof))
}

#[cfg(test)]
mod test {
    use rand_core::OsRng;

    use super::*;
    use crate::program::generators::arb_program_and_inputs;
    use proptest::prelude::*;

    fn simple_program() -> ValidatedProgram {
        use Operation::*;

        Program::new([
            PushArg(0),
            PushArg(1),
            PushArg(2),
            PushArg(3),
            Xor,
            Xor,
            Xor,
            PushArg(4),
            PushArg(5),
            PushArg(6),
            PushArg(7),
            Xor,
            Xor,
            Xor,
            And,
            PopOutput,
        ])
        .validate()
        .unwrap()
    }

    const TEST_CTX: &[u8] = b"test context";

    #[test]
    fn test_simple_program_proof_succeeds() {
        let input = &[0b0111_1110];
        let output = &[1];
        let program = simple_program();
        let proof = prove(&mut OsRng, TEST_CTX, &program, input, output);
        assert!(proof.is_ok());
        assert_eq!(
            Ok(true),
            verify(TEST_CTX, &program, output, &proof.unwrap())
        );
    }

    proptest! {
        // This test is slow, so should be run with --include-ignore
        #[test]
        #[ignore]
        fn test_program_proofs_succeed((program, input, output) in arb_program_and_inputs()) {
            let proof = prove(&mut OsRng, TEST_CTX, &program, &input, &[output]);
            assert!(proof.is_ok());
            assert_eq!(Ok(true), verify(TEST_CTX, &program, &[output], &proof.unwrap()));
        }
    }
}
