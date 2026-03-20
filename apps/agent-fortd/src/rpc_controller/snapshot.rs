use super::*;

pub(super) fn requested_capabilities_to_json(requested: &RequestedCapabilities) -> Value {
    json!({
        "fs_read": requested.fs_read.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_write": requested.fs_write.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_delete": requested.fs_delete.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "net_connect": requested.net_connect.iter().map(|endpoint| json!({
            "host": endpoint.host,
            "port": endpoint.port,
            "protocol": endpoint.protocol,
        })).collect::<Vec<_>>(),
        "host_exec": requested.host_exec,
        "process_control": requested.process_control,
        "privilege": requested.privilege,
        "credential_access": requested.credential_access,
        "unknown": requested.unknown,
        "reason_codes": requested.reason_codes,
        "matched_rules": requested.matched_rules,
        "risk_tags": requested.risk_tags,
    })
}

pub(super) fn capability_delta_to_json(delta: &CapabilityDelta) -> Value {
    json!({
        "fs_read": delta.fs_read.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_write": delta.fs_write.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "fs_delete": delta.fs_delete.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "net_connect": delta.net_connect.iter().map(|endpoint| json!({
            "host": endpoint.host,
            "port": endpoint.port,
            "protocol": endpoint.protocol,
        })).collect::<Vec<_>>(),
        "host_exec": delta.host_exec,
        "process_control": delta.process_control,
        "privilege": delta.privilege,
        "credential_access": delta.credential_access,
    })
}

pub(super) fn approval_items_from_delta(delta: &CapabilityDelta) -> Vec<DomainApprovalItem> {
    let mut items = Vec::new();

    for path in &delta.fs_read {
        items.push(DomainApprovalItem {
            kind: "fs.read".to_string(),
            target: Some(path.display().to_string()),
            summary: "read path outside granted capability".to_string(),
        });
    }
    for path in &delta.fs_write {
        items.push(DomainApprovalItem {
            kind: "fs.write".to_string(),
            target: Some(path.display().to_string()),
            summary: "write path outside granted capability".to_string(),
        });
    }
    for path in &delta.fs_delete {
        items.push(DomainApprovalItem {
            kind: "fs.delete".to_string(),
            target: Some(path.display().to_string()),
            summary: "delete path outside granted capability".to_string(),
        });
    }
    for endpoint in &delta.net_connect {
        let target = match endpoint.port {
            Some(port) => format!("{}:{port}", endpoint.host),
            None => endpoint.host.clone(),
        };
        items.push(DomainApprovalItem {
            kind: "net.connect".to_string(),
            target: Some(target),
            summary: "network endpoint outside granted capability".to_string(),
        });
    }

    if delta.host_exec {
        items.push(DomainApprovalItem {
            kind: "host.exec".to_string(),
            target: None,
            summary: "host execution capability escalation".to_string(),
        });
    }
    if delta.process_control {
        items.push(DomainApprovalItem {
            kind: "process.control".to_string(),
            target: None,
            summary: "process control capability escalation".to_string(),
        });
    }
    if delta.privilege {
        items.push(DomainApprovalItem {
            kind: "privilege".to_string(),
            target: None,
            summary: "privilege capability escalation".to_string(),
        });
    }
    if delta.credential_access {
        items.push(DomainApprovalItem {
            kind: "credential.access".to_string(),
            target: None,
            summary: "credential access capability escalation".to_string(),
        });
    }

    items
}

pub(super) fn approval_snapshot_json(
    operation: &TaskOperation,
    requested: &RequestedCapabilities,
    delta: &CapabilityDelta,
    session_grant_revision_before: u64,
    policy_revision: u64,
    reason: &str,
) -> String {
    json!({
        "schema": APPROVAL_SNAPSHOT_SCHEMA_V2,
        "operation": task_operation_to_json(operation),
        "requested_capabilities": requested_capabilities_to_json(requested),
        "delta_capabilities": capability_delta_to_json(delta),
        "session_grant_revision_before": session_grant_revision_before,
        "policy_revision": policy_revision,
        "reason": reason,
        "reason_codes": requested.reason_codes,
    })
    .to_string()
}

pub(super) fn approval_snapshot_from_json(raw: &str) -> Result<ApprovalSnapshot, RpcResponse> {
    let parsed = serde_json::from_str::<Value>(raw).map_err(|error| {
        err(
            RpcErrorCode::InternalError,
            format!("approval snapshot parse failed: {error}"),
        )
    })?;

    let object = parsed.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot must be a JSON object",
        )
    })?;

    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot missing schema",
            )
        })?;

    if schema != APPROVAL_SNAPSHOT_SCHEMA_V2 {
        return Err(err(
            RpcErrorCode::InternalError,
            format!("unsupported approval snapshot schema: {schema}"),
        ));
    }

    let operation = object.get("operation").ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot missing operation",
        )
    })?;

    let session_grant_revision_before = object
        .get("session_grant_revision_before")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot missing session_grant_revision_before",
            )
        })?;

    let policy_revision = object
        .get("policy_revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot missing policy_revision",
            )
        })?;

    let delta = object.get("delta_capabilities").ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot missing delta_capabilities",
        )
    })?;

    Ok(ApprovalSnapshot {
        operation: task_operation_from_json(operation)?,
        session_grant_revision_before,
        policy_revision,
        delta: capability_delta_from_json(delta)?,
    })
}

fn capability_delta_from_json(value: &Value) -> Result<CapabilityDelta, RpcResponse> {
    let object = value.as_object().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot delta_capabilities must be object",
        )
    })?;

    Ok(CapabilityDelta {
        fs_read: parse_path_array(object.get("fs_read"))?,
        fs_write: parse_path_array(object.get("fs_write"))?,
        fs_delete: parse_path_array(object.get("fs_delete"))?,
        net_connect: parse_net_endpoints(object.get("net_connect"))?,
        host_exec: object
            .get("host_exec")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        process_control: object
            .get("process_control")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        privilege: object
            .get("privilege")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        credential_access: object
            .get("credential_access")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_path_array(value: Option<&Value>) -> Result<Vec<PathBuf>, RpcResponse> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let items = value.as_array().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot path capability must be array",
        )
    })?;

    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let raw = item.as_str().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot path capability item must be string",
            )
        })?;
        output.push(PathBuf::from(raw));
    }
    Ok(output)
}

fn parse_net_endpoints(value: Option<&Value>) -> Result<Vec<af_core::NetEndpoint>, RpcResponse> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let items = value.as_array().ok_or_else(|| {
        err(
            RpcErrorCode::InternalError,
            "approval snapshot net_connect must be array",
        )
    })?;

    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let object = item.as_object().ok_or_else(|| {
            err(
                RpcErrorCode::InternalError,
                "approval snapshot net endpoint must be object",
            )
        })?;

        let host = object
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                err(
                    RpcErrorCode::InternalError,
                    "approval snapshot net endpoint.host is required",
                )
            })?;

        let port = object
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok());

        let protocol = object
            .get("protocol")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        output.push(af_core::NetEndpoint::new(host.to_string(), port, protocol));
    }

    Ok(output)
}
