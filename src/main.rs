//! Falcon Guardian collector for GitHub Copilot CLI command hooks.

mod guardian;

use std::{
  env,
  error::Error,
  fmt::Display,
  io::{self, IsTerminal},
  process::ExitCode,
  time::Duration,
};

use clap::{Parser, ValueEnum};
use guardian::{Function, GuardInput, GuardRequest, GuardResponse, Message, ToolCall};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::guardian::BaseUrl;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(version, about)]
struct Args {
  /// Falcon Guardian base URL.
  #[arg(
    long,
    env = "CS_AIDR_BASE_URL",
    default_value = "https://api.crowdstrike.com/aidr/aiguard"
  )]
  base_url: BaseUrl,
  /// Seconds to wait for a verdict, including polling.
  #[arg(long, default_value_t = 30)]
  timeout: u64,
  /// What to do when Falcon Guardian can't give a verdict.
  #[arg(long, value_enum, default_value_t = FailureMode::Open)]
  failure_mode: FailureMode,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum FailureMode {
  /// Let the prompt or tool call through.
  Open,
  /// Block the prompt or tool call.
  Closed,
}

impl FailureMode {
  /// The failure mode in raw `args`.
  fn from_raw_args(args: &[String]) -> Self {
    let closed = args.iter().any(|a| a == "--failure-mode=closed")
      || args
        .windows(2)
        .any(|w| w[0] == "--failure-mode" && w[1] == "closed");
    if closed { Self::Closed } else { Self::Open }
  }
}

/// A GitHub Copilot hook event.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
enum Hook {
  UserPromptSubmit,
  PreToolUse,
  PostToolUse,
}

impl Hook {
  /// The hook event `payload` names.
  fn of(payload: &str) -> Option<Self> {
    #[derive(Deserialize)]
    struct Named {
      hook_event_name: Hook,
    }
    serde_json::from_str::<Named>(payload)
      .ok()
      .map(|n| n.hook_event_name)
  }
}

/// One GitHub Copilot hook payload.
#[derive(Deserialize)]
#[serde(tag = "hook_event_name")]
enum Event {
  UserPromptSubmit(Prompt),
  PreToolUse(ToolUse),
  PostToolUse(ToolOutput),
}

impl Event {
  const fn hook(&self) -> Hook {
    match self {
      Self::UserPromptSubmit(_) => Hook::UserPromptSubmit,
      Self::PreToolUse(_) => Hook::PreToolUse,
      Self::PostToolUse(_) => Hook::PostToolUse,
    }
  }
}

#[derive(Deserialize)]
struct Session {
  session_id: String,
  cwd: String,
}

#[derive(Deserialize)]
struct Prompt {
  #[serde(flatten)]
  session: Session,
  prompt: String,
}

#[derive(Deserialize)]
struct ToolUse {
  #[serde(flatten)]
  session: Session,
  tool_name: String,
  tool_input: Value,
}

#[derive(Deserialize)]
struct ToolOutput {
  #[serde(flatten)]
  tool: ToolUse,
  tool_result: ToolResult,
}

#[derive(Deserialize)]
struct ToolResult {
  text_result_for_llm: String,
}

/// GitHub Copilot's `extra_info` logging schema.
#[derive(Serialize)]
struct ExtraInfo<'a> {
  app_name: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  user_name: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  sensor_aid: Option<&'a str>,
  copilot_hook_event_name: Hook,
  copilot_cwd: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  copilot_tool_name: Option<&'a str>,
}

const GITHUB_COPILOT_PROCESS_TAG: &str = "213584428666189";

fn main() -> ExitCode {
  let args = match Args::try_parse() {
    Ok(args) => args,
    Err(e) if !e.use_stderr() => e.exit(), // --help, --version
    Err(e) => {
      let mode = FailureMode::from_raw_args(&env::args().collect::<Vec<_>>());
      let hook = if io::stdin().is_terminal() {
        None
      } else {
        io::read_to_string(io::stdin())
          .ok()
          .as_deref()
          .and_then(Hook::of)
      };
      return fail(&e, mode, hook);
    }
  };
  let payload = match io::read_to_string(io::stdin()) {
    Ok(payload) => payload,
    Err(e) => return fail(&e, args.failure_mode, None),
  };
  let Some(hook) = Hook::of(&payload) else {
    let e = "payload has no supported hook_event_name";
    return fail(&e, args.failure_mode, None);
  };
  let Some(token) = env::var("CS_AIDR_TOKEN").ok().filter(|t| !t.is_empty()) else {
    let e = format!("CS_AIDR_TOKEN is not set");
    return fail(&e, args.failure_mode, Some(hook));
  };
  let client = guardian::Client::builder()
    .base_url(args.base_url)
    .token(token)
    .timeout(Duration::from_secs(args.timeout))
    .build();
  match run(&payload, &client) {
    Ok(Some(reply)) => {
      println!("{reply}");
      ExitCode::SUCCESS
    }
    Ok(None) => ExitCode::SUCCESS,
    Err(e) => fail(&e, args.failure_mode, Some(hook)),
  }
}

/// Report `e` on stderr and apply `mode`.
fn fail(e: &dyn Display, mode: FailureMode, hook: Option<Hook>) -> ExitCode {
  let reason = format!("Falcon Guardian: {e}");
  eprintln!("{reason}");
  match (mode, hook) {
    (FailureMode::Open, _) => ExitCode::SUCCESS,
    (FailureMode::Closed, Some(hook)) => {
      println!("{}", block(hook, &reason));
      ExitCode::SUCCESS
    }
    (FailureMode::Closed, None) => ExitCode::from(2),
  }
}

/// The Falcon sensor's agent ID (AID), or `None` if it can't be read.
#[cfg(windows)]
fn read_agent_id() -> Option<String> {
  let value = windows_registry::LOCAL_MACHINE
    .open(r"SYSTEM\CurrentControlSet\Services\CSAgent\Sim")
    .and_then(|key| key.get_value("AG"))
    .ok()?;
  if value.ty() != windows_registry::Type::Bytes {
    return None;
  }
  agent_id(&value)
}

/// The Falcon sensor's agent ID (AID), or `None` if it can't be read.
#[cfg(target_os = "macos")]
fn read_agent_id() -> Option<String> {
  let out = std::process::Command::new("/Applications/Falcon.app/Contents/Resources/falconctl")
    .arg("info")
    .output()
    .ok()?;
  if !out.status.success() {
    return None;
  }
  falconctl_agent_id(&out.stdout)
}

/// The AID in `falconctl info` plist output as 32 lowercase hex digits, or
/// `None` if it's missing or malformed.
#[cfg(target_os = "macos")]
fn falconctl_agent_id(plist: &[u8]) -> Option<String> {
  #[derive(Deserialize)]
  struct Info {
    aid: String,
  }
  let Info { aid } = plist::from_bytes(plist).ok()?;
  (aid.len() == 32 && aid.bytes().all(|b| b.is_ascii_hexdigit())).then(|| aid.to_ascii_lowercase())
}

/// The Falcon sensor's agent ID (AID), or `None` if it can't be read.
#[cfg(not(any(windows, target_os = "macos")))]
const fn read_agent_id() -> Option<String> {
  None
}

/// The AID as 32 lowercase hex digits, or `None` unless `bytes` is exactly
/// 16 bytes.
#[cfg_attr(not(windows), allow(dead_code))]
fn agent_id(bytes: &[u8]) -> Option<String> {
  let bytes: [u8; 16] = bytes.try_into().ok()?;
  Some(format!("{:032x}", u128::from_be_bytes(bytes)))
}

fn run(payload: &str, client: &guardian::Client) -> Result<Option<Value>> {
  let event: Event = serde_json::from_str(payload)?;
  let user = env::var("USER").or_else(|_| env::var("USERNAME")).ok();
  let sensor_aid = read_agent_id();
  let request = guard_request(
    &event,
    user.as_deref(),
    sensor_aid.as_deref(),
    std::process::id(),
  );
  reply(event.hook(), &client.guard_chat_completions(&request)?)
}

/// The Falcon Guardian request for `event`.
fn guard_request<'a>(
  event: &'a Event,
  user: Option<&'a str>,
  sensor_aid: Option<&'a str>,
  process_id: u32,
) -> GuardRequest<'a, ExtraInfo<'a>> {
  let (event_type, session, tool, messages) = match event {
    Event::UserPromptSubmit(Prompt { session, prompt }) => (
      "input",
      session,
      None,
      vec![Message::User {
        content: prompt.clone(),
      }],
    ),
    Event::PreToolUse(tool) => (
      "tool_input",
      &tool.session,
      Some(tool),
      vec![tool_call(tool)],
    ),
    Event::PostToolUse(ToolOutput { tool, tool_result }) => (
      "tool_output",
      &tool.session,
      Some(tool),
      vec![
        tool_call(tool),
        Message::Tool {
          content: tool_result.text_result_for_llm.clone(),
        },
      ],
    ),
  };
  GuardRequest {
    guard_input: GuardInput { messages },
    event_type,
    session_id: &session.session_id,
    user_id: user,
    agent_type: "code-assistant",
    is_agent: true,
    process_id: process_id.to_string(),
    process_tags: &[GITHUB_COPILOT_PROCESS_TAG],
    extra_info: ExtraInfo {
      app_name: "GitHub Copilot",
      user_name: user,
      sensor_aid,
      copilot_hook_event_name: event.hook(),
      copilot_cwd: &session.cwd,
      copilot_tool_name: tool.map(|t| t.tool_name.as_str()),
    },
  }
}

/// The assistant message that calls `tool`.
fn tool_call(tool: &ToolUse) -> Message {
  Message::Assistant {
    content: None,
    tool_calls: vec![ToolCall {
      r#type: "function".into(),
      function: Function {
        name: tool.tool_name.clone(),
        arguments: tool.tool_input.to_string(),
      },
    }],
  }
}

/// The GitHub Copilot reply for the Falcon Guardian verdict on `hook`, or
/// `None` to let GitHub Copilot continue unchanged.
fn reply(hook: Hook, res: &GuardResponse) -> Result<Option<Value>> {
  if res.result.blocked {
    let summary = res.summary.as_deref().unwrap_or("blocked by policy");
    return Ok(Some(block(hook, &format!("Falcon Guardian: {summary}"))));
  }
  if !res.result.transformed {
    return Ok(None);
  }
  Ok(Some(match hook {
    Hook::UserPromptSubmit => json!({ "modifiedPrompt": redacted_prompt(res)? }),
    Hook::PreToolUse => json!({ "modifiedArgs": redacted_arguments(res)? }),
    Hook::PostToolUse => modified_result(&redacted_output(res)?),
  }))
}

/// The GitHub Copilot reply that blocks the prompt or tool call for `hook`. A
/// blocked tool output is replaced by `reason`.
fn block(hook: Hook, reason: &str) -> Value {
  match hook {
    Hook::UserPromptSubmit => json!({ "decision": "block", "reason": reason }),
    Hook::PreToolUse => json!({ "permissionDecision": "deny", "permissionDecisionReason": reason }),
    Hook::PostToolUse => modified_result(reason),
  }
}

/// Replaces the tool output the model sees.
fn modified_result(text: &str) -> Value {
  json!({ "modifiedResult": { "resultType": "success", "textResultForLlm": text } })
}

/// The last `guard_output` message.
fn redacted(res: &GuardResponse) -> Result<Message> {
  let GuardInput { mut messages } = res.result.guard_output()?;
  Ok(messages.pop().ok_or("guard_output has no messages")?)
}

fn redacted_prompt(res: &GuardResponse) -> Result<String> {
  match redacted(res)? {
    Message::User { content } => Ok(content),
    _ => Err("guard_output doesn't end with a user message".into()),
  }
}

fn redacted_arguments(res: &GuardResponse) -> Result<Value> {
  let Message::Assistant { tool_calls, .. } = redacted(res)? else {
    return Err("guard_output doesn't end with a tool call".into());
  };
  let call = tool_calls
    .into_iter()
    .next()
    .ok_or("guard_output has no tool call")?;
  Ok(serde_json::from_str(&call.function.arguments)?)
}

fn redacted_output(res: &GuardResponse) -> Result<String> {
  match redacted(res)? {
    Message::Tool { content, .. } => Ok(content),
    _ => Err("guard_output doesn't end with a tool message".into()),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn payload(hook: &str, fields: Value) -> String {
    let mut payload = json!({
      "hook_event_name": hook,
      "session_id": "s1",
      "timestamp": "2026-10-14T12:00:00.000Z",
      "cwd": "/w",
    });
    let Value::Object(fields) = fields else {
      panic!("hook fields must be an object");
    };
    payload.as_object_mut().unwrap().extend(fields);
    payload.to_string()
  }

  fn hook(hook: &str, fields: Value) -> Event {
    serde_json::from_str(&payload(hook, fields)).unwrap()
  }

  fn prompt() -> Event {
    hook(
      "UserPromptSubmit",
      json!({ "prompt": "my SSN is 900-12-3456" }),
    )
  }

  fn pre_tool_use() -> Event {
    hook(
      "PreToolUse",
      json!({ "tool_name": "Write", "tool_input": { "path": "/w/ssn.txt", "file_text": "900-12-3456" } }),
    )
  }

  fn post_tool_use() -> Event {
    hook(
      "PostToolUse",
      json!({
        "tool_name": "Bash",
        "tool_input": { "command": "echo 900-12-3456" },
        "tool_result": {
          "result_type": "success",
          "text_result_for_llm": "900-12-3456\n<shellId: 1 completed with exit code 0>",
        },
      }),
    )
  }

  fn request(event: &Event) -> Value {
    let req = guard_request(
      event,
      Some("dennis"),
      Some("d4208f3f3cf544f196bfe612aa8035fe"),
      4242,
    );
    serde_json::to_value(req).unwrap()
  }

  fn verdict(fields: Value) -> GuardResponse {
    let mut res = json!({ "status": "Success", "summary": "SSN was detected and blocked." });
    res["result"] = fields;
    serde_json::from_value(res).unwrap()
  }

  fn clean() -> GuardResponse {
    verdict(json!({ "blocked": false, "transformed": false }))
  }

  fn blocked() -> GuardResponse {
    verdict(json!({ "blocked": true, "transformed": false }))
  }

  fn transformed(messages: &Value) -> GuardResponse {
    verdict(
      json!({ "blocked": false, "transformed": true, "guard_output": { "messages": messages } }),
    )
  }

  #[test]
  fn failure_mode_survives_usage_errors() {
    let mode = |args: &[&str]| {
      FailureMode::from_raw_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
    };
    assert_eq!(
      mode(&["c", "--bogus", "--failure-mode", "closed"]),
      FailureMode::Closed
    );
    assert_eq!(
      mode(&["c", "--bogus", "--failure-mode=closed"]),
      FailureMode::Closed
    );
    assert_eq!(
      mode(&["c", "--bogus", "--failure-mode", "open"]),
      FailureMode::Open
    );
    assert_eq!(mode(&["c", "--bogus"]), FailureMode::Open);
  }

  #[test]
  fn hook_is_named_even_if_the_payload_is_malformed() {
    let named = |hook: &str| Hook::of(&payload(hook, json!({})));
    assert_eq!(named("PreToolUse"), Some(Hook::PreToolUse));
    assert_eq!(named("Stop"), None);
    assert_eq!(named("preToolUse"), None);
    assert_eq!(Hook::of("not json"), None);
  }

  #[test]
  fn unsupported_events_are_rejected() {
    assert!(serde_json::from_str::<Event>(&payload("Stop", json!({}))).is_err());
  }

  #[test]
  fn agent_id_is_16_bytes_as_lowercase_hex() {
    let ag = [
      0xD4, 0x20, 0x8F, 0x3F, 0x3C, 0xF5, 0x44, 0xF1, 0x96, 0xBF, 0xE6, 0x12, 0xAA, 0x80, 0x35,
      0xFE,
    ];
    assert_eq!(
      agent_id(&ag).as_deref(),
      Some("d4208f3f3cf544f196bfe612aa8035fe")
    );
    assert_eq!(agent_id(&ag[..15]), None);
    assert_eq!(agent_id(&[]), None);
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn falconctl_agent_id_is_lowercase_hex() {
    let info = |aid: &str| {
      format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    {aid}
    <key>cid</key>
    <string>6CB9530D078E415F96CE34BE06631A37</string>
    <key>sensor_loaded</key>
    <true/>
</dict>
</plist>"#
      )
    };
    let aid = |aid: &str| falconctl_agent_id(info(aid).as_bytes());
    assert_eq!(
      aid("<key>aid</key><string>D4208F3F3CF544F196BFE612AA8035FE</string>").as_deref(),
      Some("d4208f3f3cf544f196bfe612aa8035fe")
    );
    assert_eq!(aid("<key>aid</key><string></string>"), None);
    assert_eq!(aid("<key>aid</key><string>not-an-aid</string>"), None);
    assert_eq!(aid(""), None);
    assert_eq!(falconctl_agent_id(b"falconctl: not root"), None);
  }

  #[test]
  fn missing_sensor_aid_is_omitted() {
    let req = serde_json::to_value(guard_request(&prompt(), None, None, 4242)).unwrap();
    assert!(req["extra_info"].get("sensor_aid").is_none());
  }

  #[test]
  fn prompt_is_sent_as_input() {
    assert_eq!(
      request(&prompt()),
      json!({
        "guard_input": { "messages": [{ "role": "user", "content": "my SSN is 900-12-3456" }] },
        "event_type": "input",
        "session_id": "s1",
        "user_id": "dennis",
        "agent_type": "code-assistant",
        "is_agent": true,
        "process_id": "4242",
        "process_tags": ["213584428666189"],
        "extra_info": {
          "app_name": "GitHub Copilot",
          "user_name": "dennis",
          "sensor_aid": "d4208f3f3cf544f196bfe612aa8035fe",
          "copilot_hook_event_name": "UserPromptSubmit",
          "copilot_cwd": "/w",
        },
      })
    );
  }

  #[test]
  fn tool_input_is_sent_as_json_encoded_arguments() {
    let req = request(&pre_tool_use());
    assert_eq!(req["event_type"], "tool_input");
    assert_eq!(req["extra_info"]["copilot_hook_event_name"], "PreToolUse");
    assert_eq!(req["extra_info"]["copilot_tool_name"], "Write");
    assert_eq!(
      req["guard_input"]["messages"],
      json!([{
        "role": "assistant",
        "content": null,
        "tool_calls": [{
          "type": "function",
          "function": {
            "name": "Write",
            "arguments": r#"{"file_text":"900-12-3456","path":"/w/ssn.txt"}"#,
          },
        }],
      }])
    );
  }

  #[test]
  fn tool_output_text_is_sent_verbatim() {
    let req = request(&post_tool_use());
    assert_eq!(req["event_type"], "tool_output");
    assert_eq!(
      req["guard_input"]["messages"][1],
      json!({
        "role": "tool",
        "content": "900-12-3456\n<shellId: 1 completed with exit code 0>",
      })
    );
  }

  #[test]
  fn clean_verdicts_continue() {
    for event in [prompt(), pre_tool_use(), post_tool_use()] {
      assert_eq!(reply(event.hook(), &clean()).unwrap(), None);
    }
  }

  #[test]
  fn blocked_prompt_is_blocked() {
    assert_eq!(
      reply(Hook::UserPromptSubmit, &blocked()).unwrap(),
      Some(
        json!({ "decision": "block", "reason": "Falcon Guardian: SSN was detected and blocked." })
      )
    );
  }

  #[test]
  fn redacted_prompt_rewrites_the_prompt() {
    let res = transformed(&json!([{ "role": "user", "content": "my SSN is <US_SSN>" }]));
    assert_eq!(
      reply(Hook::UserPromptSubmit, &res).unwrap(),
      Some(json!({ "modifiedPrompt": "my SSN is <US_SSN>" }))
    );
  }

  #[test]
  fn blocked_tool_input_is_denied() {
    assert_eq!(
      reply(Hook::PreToolUse, &blocked()).unwrap(),
      Some(json!({
        "permissionDecision": "deny",
        "permissionDecisionReason": "Falcon Guardian: SSN was detected and blocked.",
      }))
    );
  }

  #[test]
  fn redacted_tool_input_rewrites_the_args() {
    let res = transformed(&json!([{
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "type": "function",
        "function": {
          "name": "Write",
          "arguments": r#"{"file_text":"<US_SSN>","path":"/w/ssn.txt"}"#,
        },
      }],
    }]));
    assert_eq!(
      reply(Hook::PreToolUse, &res).unwrap(),
      Some(json!({ "modifiedArgs": { "file_text": "<US_SSN>", "path": "/w/ssn.txt" } }))
    );
  }

  #[test]
  fn blocked_tool_output_is_replaced_by_the_reason() {
    assert_eq!(
      reply(Hook::PostToolUse, &blocked()).unwrap(),
      Some(json!({
        "modifiedResult": {
          "resultType": "success",
          "textResultForLlm": "Falcon Guardian: SSN was detected and blocked.",
        }
      }))
    );
  }

  #[test]
  fn redacted_tool_output_replaces_the_output() {
    let res = transformed(&json!([
      { "role": "assistant", "content": null, "tool_calls": [] },
      { "role": "tool", "content": "<US_SSN>\n" },
    ]));
    assert_eq!(
      reply(Hook::PostToolUse, &res).unwrap(),
      Some(
        json!({ "modifiedResult": { "resultType": "success", "textResultForLlm": "<US_SSN>\n" } })
      )
    );
  }

  #[test]
  fn transformed_verdict_without_guard_output_is_an_error() {
    let res = verdict(json!({ "blocked": false, "transformed": true }));
    for hook in [Hook::UserPromptSubmit, Hook::PreToolUse, Hook::PostToolUse] {
      assert!(reply(hook, &res).is_err());
    }
  }
}
