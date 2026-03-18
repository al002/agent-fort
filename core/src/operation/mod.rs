mod normalizer;
mod normalized;

pub use normalizer::{NormalizeError, OperationNormalizer, RawOperation};
pub use normalized::{
    Fact, Facts, Intent, NormalizedOperation, OperationKind, RuntimeContext, RuntimePlatform,
    Target, TargetKind,
};
