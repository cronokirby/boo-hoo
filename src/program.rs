use std::io;

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

impl Operation {
    /// Serialize this operation into something implementing Write.
    pub fn write_to(&self, w: &mut impl io::Write) -> io::Result<()> {
        match self {
            Operation::Not => w.write_all(&[0]),
            Operation::And => w.write_all(&[1]),
            Operation::Xor => w.write_all(&[2]),
            Operation::PushArg(index) => {
                w.write_all(&[3])?;
                w.write_all(&index.to_le_bytes())
            }
            Operation::PushLocal(index) => {
                w.write_all(&[4])?;
                w.write_all(&index.to_le_bytes())
            }
        }
    }
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

    /// Serialize this program into something implementing Write.
    pub fn write_to(&self, w: &mut impl io::Write) -> io::Result<()> {
        for op in &self.operations {
            op.write_to(w)?;
        }
        Ok(())
    }
}
