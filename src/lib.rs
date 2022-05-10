//! A library for Non-Interactive Zero-Knowledge Proofs of Knowledge (NIZKPoKs) for
//! boolean circuits.
//! 
//! **This library is experimental Cryptographic Software: use at your own peril.**
//!
//! The idea is that given a program `P` and some secret input `I` you can provide
//! a proof that you know some input `I` such that the output `O` is equal to `P(I)`.
//! This proof can then be independently checked by anyone knowing the program `P`
//! and the claimed output `O`, and they'll be convinced that you know such an `I`.
//!
//! This is done via the [ZKBoo scheme](https://eprint.iacr.org/2016/163).
//!
//! # Example
//!
//! As an example, let's say that you want to create a proof that you know
//! two secret bits `x0` and `x1` such that `x0 & x1 == 1`. First, you'll need to
//! create a program which represents this circuit:

//! ```rust
//! use boo_hoo::program::*;
//! use Operation::*;

//! let raw_program = Program::new([
//!     PushArg(0),
//!     PushArg(1),
//!     And,
//!     PushOutput
//! ]);
//! ```

//! Circuits are represented with a stack based bytecode. Operations manipulate elements
//! on the stack. We can move an indexed bit of the input onto the stack with `PushArg`.
//! We use this in our program to move the two input bits on the stack. Then,
//! we and them together with `And`. We can also use `Not` or `Xor` as other operations.
//! Finally, we move the top element of the stack into the output buffer, with `PushOutput`.

//! It's possible that our program is malformed, in that it pops from an empty stack,
//! or accesses undefined elements on the stack. Because of this, we first need
//! to validate our program:

//! ```rust
//! let program = raw_program.validate().expect("failed to validate program!");
//! ```

//! The validate method produces a `ValidatedProgram`, which has been validated against
//! obviously incorrect manipulations, and which knows exactly how many input and output
//! bits the program uses. In our case, the program has two input bits, and two output bits.

//! Now, we can generate a proof for this program, using our secret inputs:

//! ```rust
//! use boo_hoo::proof::*;
//! use rand_core::OsRng;

//! let ctx = b"example context";
//! let input = [0b10];
//! let output = [0];
//! let proof = prove(&mut OsRng, ctx, &program, &input, &output).expect("input or output were insufficient")
//! ```

//! The input and the output are provided as `&[u8]`. The bits are read from the first
//! byte in the slice to the least, and from the least significant to the most significant
//! bit inside of each byte. If an insufficient number of input or output bits are provided,
//! then the proof construction will fail.

//! We also pass in a "context". This context makes it so that the proof can only be verified
//! with that context string. This allows binding a proof to a particular application,
//! or even to an arbitrary message. The proof will fail to verify if a different context is used.

//! Now, we can verify the proof:

//! ```rust
//! let result = verify(ctx, &program, &output, &proof);
//! assert_eq!(result, Ok(true));
//! ```

//! And that's all there is to it, really.

//! # Details

//! This is a relatively straightforward implementation of the scheme from the paper.
//! In fact, this implementation is very "by-the-books" and intended to be easy
//! to understand, rather than being particularly performant. Operations are done
//! bit-by-bit, which is much more inefficient than operation on `u32`s or `u64`s directly.
//! In most boolean circuits for real programs, like `SHA256` or other benchmarks,
//! you'll be doing boolean operations on these large bundles, and performance could
//! be greatly improved by processing multiple bits at once.
mod bits;
mod commitment;
mod constants;
mod program;
mod proof;
mod rng;

pub use program::{Program, ValidatedProgram, ProgramError};
pub use proof::{prove, verify, Error, Proof};
