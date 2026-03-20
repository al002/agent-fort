use std::cell::{RefCell, RefMut};

use af_policy::{
    CommandRule, NetConnectSpec, PatternToken, RuleCapabilities, RuleCondition, RuleSource,
    ShellWrapperKind, ValueRef,
};
use anyhow::{Result as AnyhowResult, anyhow, bail};
use serde::{Deserialize, Serialize};
use starlark::any::ProvidesStaticType;
use starlark::environment::{GlobalsBuilder, Module};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::syntax::{AstModule, Dialect};
use starlark::values::Value;
use starlark::values::list::{ListRef, UnpackList};
use starlark::values::none::NoneType;

use crate::{PolicyInfraError, PolicyInfraResult};

const CAP_HANDLE_PREFIX: &str = "__af_cap__:";
const REF_PREFIX: &str = "__af_ref__:";
const NET_PREFIX: &str = "__af_net__:";
const COND_PREFIX: &str = "__af_cond__:";

#[derive(Debug, Default, Clone, Copy)]
pub struct CommandRuleParser;

impl CommandRuleParser {
    pub fn parse_file(&self, path: &str, source: &str) -> PolicyInfraResult<Vec<CommandRule>> {
        let builder = RefCell::new(RuleBuilder::new(path.to_string()));
        let mut dialect = Dialect::Extended.clone();
        dialect.enable_f_strings = true;
        let ast = AstModule::parse(path, source.to_string(), &dialect).map_err(|error| {
            PolicyInfraError::InvalidPolicy {
                path: path.to_string(),
                message: format!("command rules parse failed: {error}"),
            }
        })?;

        let globals = GlobalsBuilder::standard()
            .with(command_rule_builtins)
            .build();
        let module = Module::new();
        {
            let mut eval = Evaluator::new(&module);
            eval.extra = Some(&builder);
            eval.eval_module(ast, &globals)
                .map_err(|error| PolicyInfraError::InvalidPolicy {
                    path: path.to_string(),
                    message: format!("command rules eval failed: {error}"),
                })?;
        }

        Ok(builder.into_inner().rules)
    }
}

#[derive(Debug, ProvidesStaticType)]
struct RuleBuilder {
    path: String,
    rules: Vec<CommandRule>,
    capability_specs: Vec<RuleCapabilities>,
}

impl RuleBuilder {
    fn new(path: String) -> Self {
        Self {
            path,
            rules: Vec::new(),
            capability_specs: Vec::new(),
        }
    }

    fn push_capabilities(&mut self, capabilities: RuleCapabilities) -> String {
        let next = self.capability_specs.len();
        self.capability_specs.push(capabilities);
        format!("{CAP_HANDLE_PREFIX}{next}")
    }

    fn capabilities_from_handle(&self, handle: &str) -> AnyhowResult<RuleCapabilities> {
        let raw = handle
            .strip_prefix(CAP_HANDLE_PREFIX)
            .ok_or_else(|| anyhow!("capabilities must be created by cap(...)"))?;
        let index = raw
            .parse::<usize>()
            .map_err(|_| anyhow!("invalid cap handle: {handle}"))?;
        self.capability_specs
            .get(index)
            .cloned()
            .ok_or_else(|| anyhow!("unknown cap handle: {handle}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EncodedRef {
    Arg { index: usize },
    ArgAfter { flag: String },
    ArgAfterAny { flags: Vec<String> },
    Positional { index: usize },
    AllPositionals,
    UrlHostFromArg { index: usize },
    Cwd,
    ResolvePath { inner: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncodedNet {
    host: String,
    port: Option<u16>,
    protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EncodedCondition {
    Has { token: String },
    HasAny { tokens: Vec<String> },
    HasAll { tokens: Vec<String> },
    ShellWrapper { wrapper: String },
}

fn rule_builder<'v, 'a>(eval: &Evaluator<'v, 'a, '_>) -> RefMut<'a, RuleBuilder> {
    eval.extra
        .as_ref()
        .expect("rule builder requires Evaluator.extra")
        .downcast_ref::<RefCell<RuleBuilder>>()
        .expect("Evaluator.extra must contain RuleBuilder")
        .borrow_mut()
}

#[starlark_module]
fn command_rule_builtins(builder: &mut GlobalsBuilder) {
    fn command_rule<'v>(
        pattern: UnpackList<Value<'v>>,
        capabilities: &'v str,
        when: Option<&'v str>,
        reason: Option<&'v str>,
        r#match: Option<UnpackList<Value<'v>>>,
        not_match: Option<UnpackList<Value<'v>>>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let pattern = parse_pattern(pattern)?;
        if pattern.is_empty() {
            bail!("pattern cannot be empty");
        }
        let when = when.map(parse_condition_marker).transpose()?;
        let reason = reason.map(|value| value.trim().to_string());
        if reason.as_ref().is_some_and(|value| value.is_empty()) {
            bail!("reason cannot be empty");
        }

        let examples = r#match.map(parse_examples).transpose()?.unwrap_or_default();
        let negative_examples = not_match
            .map(parse_examples)
            .transpose()?
            .unwrap_or_default();

        let mut builder = rule_builder(eval);
        let capabilities = builder.capabilities_from_handle(capabilities)?;
        let line = eval
            .call_stack_top_location()
            .map(|span| span.resolve_span().begin.line + 1)
            .unwrap_or(1);
        let rule = CommandRule {
            source: RuleSource {
                file: builder.path.clone(),
                line,
                ordinal: builder.rules.len() + 1,
            },
            pattern,
            when,
            capabilities,
            reason,
        };
        validate_examples(&rule, &examples, &negative_examples)?;
        builder.rules.push(rule);
        Ok(NoneType)
    }

    fn cap<'v>(
        fs_read: Option<UnpackList<Value<'v>>>,
        fs_write: Option<UnpackList<Value<'v>>>,
        fs_delete: Option<UnpackList<Value<'v>>>,
        net_connect: Option<UnpackList<Value<'v>>>,
        host_exec: Option<bool>,
        process_control: Option<bool>,
        privilege: Option<bool>,
        credential_access: Option<bool>,
        mark_unknown: Option<bool>,
        risk_tags: Option<UnpackList<Value<'v>>>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<String> {
        let spec = RuleCapabilities {
            fs_read: fs_read
                .map(parse_value_ref_list)
                .transpose()?
                .unwrap_or_default(),
            fs_write: fs_write
                .map(parse_value_ref_list)
                .transpose()?
                .unwrap_or_default(),
            fs_delete: fs_delete
                .map(parse_value_ref_list)
                .transpose()?
                .unwrap_or_default(),
            net_connect: net_connect
                .map(parse_net_list)
                .transpose()?
                .unwrap_or_default(),
            host_exec: host_exec.unwrap_or(false),
            process_control: process_control.unwrap_or(false),
            privilege: privilege.unwrap_or(false),
            credential_access: credential_access.unwrap_or(false),
            mark_unknown: mark_unknown.unwrap_or(false),
            risk_tags: risk_tags
                .map(|items| unpack_string_list(items, "risk_tags"))
                .transpose()?
                .unwrap_or_default(),
        };
        Ok(rule_builder(eval).push_capabilities(spec))
    }

    fn net<'v>(
        host: &'v str,
        port: Option<u32>,
        protocol: Option<&'v str>,
    ) -> anyhow::Result<String> {
        if host.trim().is_empty() {
            bail!("net host cannot be empty");
        }
        let port = port
            .map(|value| u16::try_from(value).map_err(|_| anyhow!("net port must be <= 65535")))
            .transpose()?;
        encode_json(
            NET_PREFIX,
            &EncodedNet {
                host: host.to_string(),
                port,
                protocol: protocol.map(|value| value.to_ascii_lowercase()),
            },
        )
    }

    fn arg(index: u32) -> anyhow::Result<String> {
        encode_json(
            REF_PREFIX,
            &EncodedRef::Arg {
                index: index as usize,
            },
        )
    }

    fn arg_after<'v>(flag: &'v str) -> anyhow::Result<String> {
        if flag.trim().is_empty() {
            bail!("arg_after flag cannot be empty");
        }
        encode_json(
            REF_PREFIX,
            &EncodedRef::ArgAfter {
                flag: flag.to_string(),
            },
        )
    }

    fn arg_after_any<'v>(flags: UnpackList<Value<'v>>) -> anyhow::Result<String> {
        let flags = unpack_string_list(flags, "arg_after_any flags")?;
        if flags.is_empty() {
            bail!("arg_after_any flags cannot be empty");
        }
        encode_json(REF_PREFIX, &EncodedRef::ArgAfterAny { flags })
    }

    fn positional(index: u32) -> anyhow::Result<String> {
        encode_json(
            REF_PREFIX,
            &EncodedRef::Positional {
                index: index as usize,
            },
        )
    }

    fn all_positionals() -> anyhow::Result<String> {
        encode_json(REF_PREFIX, &EncodedRef::AllPositionals)
    }

    fn url_host_from_arg(index: u32) -> anyhow::Result<String> {
        encode_json(
            REF_PREFIX,
            &EncodedRef::UrlHostFromArg {
                index: index as usize,
            },
        )
    }

    fn cwd() -> anyhow::Result<String> {
        encode_json(REF_PREFIX, &EncodedRef::Cwd)
    }

    fn resolve_path<'v>(value: &'v str) -> anyhow::Result<String> {
        encode_json(
            REF_PREFIX,
            &EncodedRef::ResolvePath {
                inner: value.to_string(),
            },
        )
    }

    fn has<'v>(token: &'v str) -> anyhow::Result<String> {
        if token.trim().is_empty() {
            bail!("has token cannot be empty");
        }
        encode_json(
            COND_PREFIX,
            &EncodedCondition::Has {
                token: token.to_string(),
            },
        )
    }

    fn has_any<'v>(tokens: UnpackList<Value<'v>>) -> anyhow::Result<String> {
        let tokens = unpack_string_list(tokens, "has_any tokens")?;
        if tokens.is_empty() {
            bail!("has_any tokens cannot be empty");
        }
        encode_json(COND_PREFIX, &EncodedCondition::HasAny { tokens })
    }

    fn has_all<'v>(tokens: UnpackList<Value<'v>>) -> anyhow::Result<String> {
        let tokens = unpack_string_list(tokens, "has_all tokens")?;
        if tokens.is_empty() {
            bail!("has_all tokens cannot be empty");
        }
        encode_json(COND_PREFIX, &EncodedCondition::HasAll { tokens })
    }

    fn shell_wrapper<'v>(kind: &'v str) -> anyhow::Result<String> {
        let normalized = kind.trim().to_ascii_lowercase();
        if !matches!(normalized.as_str(), "none" | "c" | "lc" | "any") {
            bail!("shell_wrapper kind must be one of none/c/lc/any");
        }
        encode_json(
            COND_PREFIX,
            &EncodedCondition::ShellWrapper {
                wrapper: normalized,
            },
        )
    }
}

fn encode_json<T: Serialize>(prefix: &str, value: &T) -> AnyhowResult<String> {
    Ok(format!(
        "{prefix}{}",
        serde_json::to_string(value)
            .map_err(|error| anyhow!("serialize marker failed: {error}"))?
    ))
}

fn decode_json<T>(prefix: &str, raw: &str) -> AnyhowResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = raw
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("invalid marker: expected prefix {prefix}"))?;
    serde_json::from_str(payload).map_err(|error| anyhow!("parse marker failed: {error}"))
}

fn parse_pattern<'v>(pattern: UnpackList<Value<'v>>) -> AnyhowResult<Vec<PatternToken>> {
    pattern
        .items
        .into_iter()
        .map(parse_pattern_token)
        .collect::<AnyhowResult<Vec<_>>>()
}

fn parse_pattern_token<'v>(value: Value<'v>) -> AnyhowResult<PatternToken> {
    if let Some(token) = value.unpack_str() {
        return Ok(PatternToken::Single(token.to_string()));
    }
    let Some(list) = ListRef::from_value(value) else {
        bail!(
            "pattern token must be string or list of strings, got {}",
            value.get_type()
        );
    };
    let alternatives = list
        .content()
        .iter()
        .map(|item| {
            item.unpack_str()
                .ok_or_else(|| anyhow!("pattern alternatives must be strings"))
                .map(str::to_string)
        })
        .collect::<AnyhowResult<Vec<_>>>()?;
    if alternatives.is_empty() {
        bail!("pattern alternatives cannot be empty");
    }
    if alternatives.len() == 1 {
        Ok(PatternToken::Single(alternatives[0].clone()))
    } else {
        Ok(PatternToken::Alts(alternatives))
    }
}

fn parse_value_ref_list<'v>(values: UnpackList<Value<'v>>) -> AnyhowResult<Vec<ValueRef>> {
    values
        .items
        .into_iter()
        .map(|value| {
            value
                .unpack_str()
                .ok_or_else(|| anyhow!("value refs must be strings generated by helper functions"))
                .and_then(parse_value_ref)
        })
        .collect()
}

fn parse_net_list<'v>(values: UnpackList<Value<'v>>) -> AnyhowResult<Vec<NetConnectSpec>> {
    values
        .items
        .into_iter()
        .map(|value| {
            let marker = value
                .unpack_str()
                .ok_or_else(|| anyhow!("net_connect items must come from net(...)"))?;
            let encoded: EncodedNet = decode_json(NET_PREFIX, marker)?;
            Ok(NetConnectSpec {
                host: parse_value_ref(encoded.host.as_str())?,
                port: encoded.port,
                protocol: encoded.protocol,
            })
        })
        .collect()
}

fn parse_value_ref(raw: &str) -> AnyhowResult<ValueRef> {
    if !raw.starts_with(REF_PREFIX) {
        return Ok(ValueRef::Literal(raw.to_string()));
    }

    let encoded: EncodedRef = decode_json(REF_PREFIX, raw)?;
    match encoded {
        EncodedRef::Arg { index } => Ok(ValueRef::Arg(index)),
        EncodedRef::ArgAfter { flag } => Ok(ValueRef::ArgAfter(flag)),
        EncodedRef::ArgAfterAny { flags } => Ok(ValueRef::ArgAfterAny(flags)),
        EncodedRef::Positional { index } => Ok(ValueRef::Positional(index)),
        EncodedRef::AllPositionals => Ok(ValueRef::AllPositionals),
        EncodedRef::UrlHostFromArg { index } => Ok(ValueRef::UrlHostFromArg(index)),
        EncodedRef::Cwd => Ok(ValueRef::Cwd),
        EncodedRef::ResolvePath { inner } => {
            Ok(ValueRef::ResolvePath(Box::new(parse_value_ref(&inner)?)))
        }
    }
}

fn parse_condition_marker(raw: &str) -> AnyhowResult<RuleCondition> {
    let encoded: EncodedCondition = decode_json(COND_PREFIX, raw)?;
    match encoded {
        EncodedCondition::Has { token } => Ok(RuleCondition::Has(token)),
        EncodedCondition::HasAny { tokens } => Ok(RuleCondition::HasAny(tokens)),
        EncodedCondition::HasAll { tokens } => Ok(RuleCondition::HasAll(tokens)),
        EncodedCondition::ShellWrapper { wrapper } => {
            Ok(RuleCondition::ShellWrapper(match wrapper.as_str() {
                "none" => ShellWrapperKind::None,
                "c" => ShellWrapperKind::C,
                "lc" => ShellWrapperKind::Lc,
                "any" => ShellWrapperKind::Any,
                _ => bail!("shell_wrapper kind must be one of none/c/lc/any"),
            }))
        }
    }
}

fn unpack_string_list<'v>(items: UnpackList<Value<'v>>, field: &str) -> AnyhowResult<Vec<String>> {
    items
        .items
        .into_iter()
        .map(|value| {
            value
                .unpack_str()
                .ok_or_else(|| anyhow!("{field} must be strings, got {}", value.get_type()))
                .map(str::to_string)
        })
        .collect()
}

fn parse_examples<'v>(items: UnpackList<Value<'v>>) -> AnyhowResult<Vec<Vec<String>>> {
    items
        .items
        .into_iter()
        .map(|item| {
            if let Some(raw) = item.unpack_str() {
                return parse_string_example(raw);
            }
            let Some(list) = ListRef::from_value(item) else {
                bail!("example must be string or list of strings");
            };
            parse_list_example(&list)
        })
        .collect()
}

fn parse_string_example(raw: &str) -> AnyhowResult<Vec<String>> {
    let tokens =
        shlex::split(raw).ok_or_else(|| anyhow!("example string has invalid shell syntax"))?;
    if tokens.is_empty() {
        bail!("example cannot be empty");
    }
    Ok(tokens)
}

fn parse_list_example(list: &ListRef) -> AnyhowResult<Vec<String>> {
    let tokens = list
        .content()
        .iter()
        .map(|value| {
            value
                .unpack_str()
                .ok_or_else(|| anyhow!("example list tokens must be strings"))
                .map(str::to_string)
        })
        .collect::<AnyhowResult<Vec<_>>>()?;
    if tokens.is_empty() {
        bail!("example cannot be empty");
    }
    Ok(tokens)
}

fn validate_examples(
    rule: &CommandRule,
    examples: &[Vec<String>],
    negative_examples: &[Vec<String>],
) -> AnyhowResult<()> {
    for argv in examples {
        if !rule.matches(argv) {
            bail!(
                "match example did not satisfy rule `{}`: {:?}",
                rule.source.key(),
                argv
            );
        }
    }
    for argv in negative_examples {
        if rule.matches(argv) {
            bail!(
                "not_match example unexpectedly matched rule `{}`: {:?}",
                rule.source.key(),
                argv
            );
        }
    }
    Ok(())
}
