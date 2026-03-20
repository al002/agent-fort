mod command_ir;
mod command_parser;
mod delta;
mod extractor;
mod extractor_registry;
mod matcher;
mod model;

pub use command_ir::{CommandIR, CommandNode, Redirection, RedirectionKind};
pub use command_parser::{CommandParseError, CommandParser};
pub use delta::{CapabilityDelta, apply_delta_to_capability_set, missing_from_session_grant};
pub use extractor::CapabilityExtractor;
pub use extractor_registry::{ExtractorKind, ExtractorRegistry};
pub use matcher::{
    capability_set_within_policy, endpoint_matches_any, endpoint_matches_rule,
    intersect_requested_with_capabilities, normalize_lexical_path, path_matches_any,
    path_matches_pattern, requested_within_backend_limits, requested_within_capabilities,
};
pub use model::{ExtractionConfidence, NetEndpoint, RequestedCapabilities};
