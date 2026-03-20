use super::*;

pub(super) fn validate_task_operation(operation: Option<&TaskOperation>) -> Option<RpcResponse> {
    let operation = match operation {
        Some(operation) => operation,
        None => {
            return Some(err(
                RpcErrorCode::BadRequest,
                "create_task operation is required",
            ));
        }
    };

    if operation.kind.trim().is_empty() {
        return Some(err(
            RpcErrorCode::BadRequest,
            "create_task operation.kind must not be empty",
        ));
    }

    let payload = struct_to_json(operation.payload.as_ref());
    let options = struct_to_json(operation.options.as_ref());

    if let Some(path) = find_forbidden_runtime_override_key(&payload, "payload") {
        return Some(err(
            RpcErrorCode::BadRequest,
            format!("runtime override is not allowed in task operation: {path}"),
        ));
    }
    if let Some(path) = find_forbidden_runtime_override_key(&options, "options") {
        return Some(err(
            RpcErrorCode::BadRequest,
            format!("runtime override is not allowed in task operation: {path}"),
        ));
    }

    for key in operation.labels.keys() {
        let lower = key.trim().to_ascii_lowercase();
        if lower == "backend"
            || lower == "runtime_backend"
            || lower.starts_with("sandbox.")
            || lower.starts_with("runtime.")
            || lower.starts_with("backend.")
        {
            return Some(err(
                RpcErrorCode::BadRequest,
                format!("runtime override label is not allowed: {key}"),
            ));
        }
    }

    None
}

pub(super) fn task_operation_to_json(operation: &TaskOperation) -> Value {
    json!({
        "kind": operation.kind,
        "payload": struct_to_json(operation.payload.as_ref()),
        "options": struct_to_json(operation.options.as_ref()),
        "labels": operation.labels,
    })
}

pub(super) fn task_operation_from_json(value: &Value) -> Result<TaskOperation, RpcResponse> {
    let object = value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot operation must be object",
        )
    })?;

    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|kind| !kind.is_empty())
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot operation.kind must not be empty",
            )
        })?;

    let payload = maybe_json_to_prost_struct(object.get("payload"))?;
    let options = maybe_json_to_prost_struct(object.get("options"))?;

    let labels = object
        .get("labels")
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|value| (key.clone(), value.to_string()))
                        .ok_or_else(|| {
                            err(
                                RpcErrorCode::InternalError,
                                format!(
                                    "approval snapshot operation.labels must be string map: key={key}"
                                ),
                            )
                        })
                })
                .collect::<Result<HashMap<_, _>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(TaskOperation {
        kind: kind.to_string(),
        payload,
        options,
        labels,
    })
}

pub(super) fn struct_to_json(value: Option<&prost_types::Struct>) -> Value {
    let Some(value) = value else {
        return Value::Object(Default::default());
    };

    let map = value
        .fields
        .iter()
        .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
        .collect::<serde_json::Map<String, Value>>();

    Value::Object(map)
}

fn find_forbidden_runtime_override_key(value: &Value, prefix: &str) -> Option<String> {
    const FORBIDDEN: [&str; 9] = [
        "sandbox",
        "sandbox_overrides",
        "backend",
        "runtime_backend",
        "backend_override",
        "filesystem_mode",
        "governance_mode",
        "syscall_policy",
        "mounts",
    ];

    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase();
                if FORBIDDEN.contains(&lower.as_str()) {
                    return Some(format!("{prefix}.{key}"));
                }
                if let Some(found) =
                    find_forbidden_runtime_override_key(value, &format!("{prefix}.{key}"))
                {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(list) => list.iter().enumerate().find_map(|(index, item)| {
            find_forbidden_runtime_override_key(item, &format!("{prefix}[{index}]"))
        }),
        _ => None,
    }
}

fn maybe_json_to_prost_struct(
    value: Option<&Value>,
) -> Result<Option<prost_types::Struct>, RpcResponse> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => Ok(Some(json_to_prost_struct(value)?)),
    }
}

fn json_to_prost_struct(value: &Value) -> Result<prost_types::Struct, RpcResponse> {
    let object = value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "operation payload/options must be object",
        )
    })?;

    let fields = object
        .iter()
        .map(|(key, value)| (key.clone(), json_to_proto_value(value)))
        .collect::<BTreeMap<_, _>>();

    Ok(prost_types::Struct { fields })
}

fn json_to_proto_value(value: &Value) -> prost_types::Value {
    match value {
        Value::Null => prost_types::Value {
            kind: Some(prost_types::value::Kind::NullValue(0)),
        },
        Value::Bool(flag) => prost_types::Value {
            kind: Some(prost_types::value::Kind::BoolValue(*flag)),
        },
        Value::Number(number) => prost_types::Value {
            kind: Some(prost_types::value::Kind::NumberValue(
                number.as_f64().unwrap_or_default(),
            )),
        },
        Value::String(text) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue(text.clone())),
        },
        Value::Array(list) => prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: list.iter().map(json_to_proto_value).collect(),
                },
            )),
        },
        Value::Object(object) => prost_types::Value {
            kind: Some(prost_types::value::Kind::StructValue(prost_types::Struct {
                fields: object
                    .iter()
                    .map(|(key, value)| (key.clone(), json_to_proto_value(value)))
                    .collect(),
            })),
        },
    }
}

fn proto_value_to_json(value: &prost_types::Value) -> Value {
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::NullValue(_)) | None => Value::Null,
        Some(prost_types::value::Kind::NumberValue(number)) => json!(number),
        Some(prost_types::value::Kind::StringValue(text)) => Value::String(text.clone()),
        Some(prost_types::value::Kind::BoolValue(flag)) => Value::Bool(*flag),
        Some(prost_types::value::Kind::StructValue(object)) => {
            let map = object
                .fields
                .iter()
                .map(|(key, value)| (key.clone(), proto_value_to_json(value)))
                .collect::<serde_json::Map<String, Value>>();
            Value::Object(map)
        }
        Some(prost_types::value::Kind::ListValue(list)) => Value::Array(
            list.values
                .iter()
                .map(proto_value_to_json)
                .collect::<Vec<_>>(),
        ),
    }
}
