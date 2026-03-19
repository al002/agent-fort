use crate::capability::CapabilityDelta;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityDecision {
    Allow,
    Ask {
        delta: CapabilityDelta,
        reason: String,
    },
    Deny {
        reason: String,
    },
    Forbid {
        reason: String,
    },
}
