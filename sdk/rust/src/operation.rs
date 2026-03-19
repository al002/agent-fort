use std::collections::{BTreeMap, HashMap};

use af_rpc_proto::TaskOperation;
use prost_types::{Struct as ProstStruct, Value as ProstValue, value::Kind as ProstValueKind};

/// Builds an `exec` task operation with a shell command string payload.
///
/// The resulting payload uses `{"command": "<your command>"}` format, which is
/// accepted by daemon task command extraction.
///
/// # Examples
/// ```
/// use af_sdk::exec_operation;
///
/// let operation = exec_operation("echo hello");
/// assert_eq!(operation.kind, "exec");
/// ```
pub fn exec_operation(command: impl Into<String>) -> TaskOperation {
    let mut payload_fields = BTreeMap::new();
    payload_fields.insert(
        "command".to_string(),
        ProstValue {
            kind: Some(ProstValueKind::StringValue(command.into())),
        },
    );

    TaskOperation {
        kind: "exec".to_string(),
        payload: Some(ProstStruct {
            fields: payload_fields,
        }),
        options: None,
        labels: HashMap::new(),
    }
}
