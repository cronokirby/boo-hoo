/// Represents an individual operation in the program.
///
/// Each of these manipulates the program stack, potentially reading input.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Operation {
    /// PUSH(!POP)
    Not,
    /// PUSH(POP & POP)
    And,
    /// PUSH(POP ^ POP)
    Xor,
    /// Push an argument bit, with the right index.
    PushArg(usize),
    /// Push a local element, indexed from the bottom of the stack
    PushLocal(usize)
}

/// Represents a program, implementing some kind of boolean circuit.
///
/// The programs represent boolean circuits using a sequence of stack-based
/// operations.
#[derive(Clone, Debug, PartialEq)]
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
}
