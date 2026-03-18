mod normalized;
mod normalizer;

pub use normalized::{
    Fact, Facts, Intent, NormalizedOperation, OperationKind, RuntimeContext, RuntimePlatform,
    Target, TargetKind,
};
pub use normalizer::{NormalizeError, OperationNormalizer, RawOperation};
