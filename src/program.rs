use bincode::{enc::Encoder, error::EncodeError, Encode};
use std::{error, fmt};

/// Represents an individual operation in the program.
///
/// Each of these manipulates the program stack, potentially reading input.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Operation {
    /// PUSH(!POP)
    Not,
    /// PUSH(POP & POP)
    And,
    /// PUSH(POP ^ POP)
    Xor,
    /// Push an argument bit, with the right index.
    PushArg(u32),
    /// Push a local element, indexed from the bottom of the stack
    PushLocal(u32),
}

impl Encode for Operation {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        match self {
            Operation::Not => 0u8.encode(encoder),
            Operation::And => 1u8.encode(encoder),
            Operation::Xor => 2u8.encode(encoder),
            Operation::PushArg(index) => {
                3u8.encode(encoder)?;
                index.encode(encoder)
            }
            Operation::PushLocal(index) => {
                4u8.encode(encoder)?;
                index.encode(encoder)
            }
        }
    }
}

/// An error that describes an invalid program.
#[derive(Clone, Debug, PartialEq)]
pub enum ProgramError {
    /// The program had an insufficient stack at a given instruction.
    InsufficientStack { instruction: usize, stack: usize },
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgramError::InsufficientStack { instruction, stack } => {
                write!(
                    f,
                    "instr {}: insufficient stack of size {}",
                    instruction, stack
                )
            }
        }
    }
}

impl error::Error for ProgramError {}

/// Represents a program, implementing some kind of boolean circuit.
///
/// The programs represent boolean circuits using a sequence of stack-based
/// operations.
#[derive(Clone, Debug, Encode, PartialEq)]
pub struct Program {
    operations: Vec<Operation>,
}

impl Program {
    /// Create a program from a list of operations.
    ///
    /// The program will execute the operations in order.
    pub fn new(operations: impl Into<Vec<Operation>>) -> Self {
        Self {
            operations: operations.into(),
        }
    }

    /// Validate that a program is well formed.
    ///
    /// A program isn't well formed if it attempts to pop an element off of an
    /// empty stack, or access some other undefined element.
    ///
    /// We produce a new struct to allow for reusing the validated result
    /// without redoing the logic.
    pub fn validate(self) -> Result<ValidatedProgram, ProgramError> {
        let mut required_input: u32 = 0;
        let mut stack: usize = 0;

        for (instruction, op) in self.operations.iter().enumerate() {
            use Operation::*;

            match op {
                Not => {
                    if stack < 1 {
                        return Err(ProgramError::InsufficientStack { instruction, stack });
                    }
                }
                Xor | And => {
                    if stack < 2 {
                        return Err(ProgramError::InsufficientStack { instruction, stack });
                    }
                    stack -= 1;
                }
                Operation::PushArg(i) => {
                    required_input = u32::max(i + 1, required_input);
                    stack += 1;
                }
                Operation::PushLocal(i) => {
                    if (*i as usize) >= stack {
                        return Err(ProgramError::InsufficientStack { instruction, stack });
                    }
                    stack += 1;
                }
            }
        }

        Ok(ValidatedProgram {
            input_count: required_input as usize,
            output_count: stack,
            operations: self.operations,
        })
    }
}

/// Represents a valid program.
///
/// Unlike a general program, we make sure that undefined elements of the stack
/// are never accessed. We also already know the number of input bits required,
/// as well as the number of output bits produced.
///
/// By having this information in a struct, we avoid re-validating a program
/// if it's used multiple times.
#[derive(Clone, Debug)]
pub struct ValidatedProgram {
    pub(crate) input_count: usize,
    pub(crate) output_count: usize,
    pub(crate) operations: Vec<Operation>,
}

// Utility functions for testing
#[cfg(test)]
impl ValidatedProgram {
    fn io(&self) -> (usize, usize) {
        (self.input_count, self.output_count)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use Operation::*;

    #[test]
    fn test_validating_program_with_insufficient_stack() {
        assert!(Program::new([Not]).validate().is_err());
        assert!(Program::new([And]).validate().is_err());
        assert!(Program::new([PushArg(0), And]).validate().is_err());
        assert!(Program::new([PushLocal(0)]).validate().is_err());
    }

    #[test]
    fn test_validating_program_counts_correctly() {
        assert_eq!(
            Ok((2, 2)),
            Program::new([PushArg(0), PushArg(1), Not])
                .validate()
                .map(|x| x.io())
        );
        assert_eq!(
            Ok((1, 2)),
            Program::new([PushArg(0), PushArg(0), Not])
                .validate()
                .map(|x| x.io())
        );
        assert_eq!(
            Ok((1, 1)),
            Program::new([PushArg(0), PushArg(0), Xor])
                .validate()
                .map(|x| x.io())
        );
        assert_eq!(
            Ok((1, 1)),
            Program::new([PushArg(0), PushArg(0), And])
                .validate()
                .map(|x| x.io())
        );
    }
}
