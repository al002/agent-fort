mod normalized;
mod normalizer;

pub use normalized::{
    NormalizedCommand, NormalizedOperation, OperationKind, RuntimeContext, RuntimePlatform,
};
pub use normalizer::{NormalizeError, OperationNormalizer, RawOperation};
