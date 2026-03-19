pub mod capability;
pub mod errors;
pub mod operation;
pub mod policy;
pub mod runtime;
pub mod services;

pub use capability::{
    CapabilityDelta, CapabilityExtractor, CommandIR, CommandParseError, CommandParser, NetEndpoint,
    RequestedCapabilities, apply_delta_to_capability_set, diff_requested_vs_session_grant,
    intersect_requested_with_capabilities, subset_capability_set_within_static,
    subset_requested_vs_backend, subset_requested_vs_capabilities,
};
pub use errors::{ApprovalAppError, SessionAppError, TaskAppError};
pub use operation::{
    NormalizeError, NormalizedCommand, NormalizedOperation, OperationKind, OperationNormalizer,
    RawOperation, RuntimeContext, RuntimePlatform,
};
pub use policy::{CapabilityDecision, CapabilityPolicyEvaluator, EvaluationMode};
pub use runtime::{
    BackendSelectionError, BackendSelector, RuntimeCompileError, RuntimeCompiler, RuntimeExecPlan,
    SelectedBackend,
};
pub use services::{
    ApprovalAppService, ApprovalPort, CancelTaskInput, CancelTaskWrite, CreateSessionInput,
    CreateSessionWrite, CreateTaskInput, CreateTaskWrite, GetApprovalInput, RespondApprovalInput,
    RespondApprovalResult, SessionAppService, SessionConfig, SessionWritePort, TaskAppService,
    TaskPort,
};
