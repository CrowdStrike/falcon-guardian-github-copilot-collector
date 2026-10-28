//! Falcon Guardian API client.

use std::{
  str::FromStr,
  thread,
  time::{Duration, Instant},
};

use bon::Builder;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;

/// Host suffixes the token may be sent to.
const ALLOWED_HOST_SUFFIXES: &[&str] = &[".crowdstrike.com", ".collector-crowdstrike.com"];

/// A Falcon Guardian base URL.
#[derive(Clone)]
pub struct BaseUrl(Url);

impl FromStr for BaseUrl {
  type Err = String;

  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    let url = Url::parse(s).map_err(|e| e.to_string())?;
    let allowed = url.scheme() == "https"
      && url
        .domain()
        .is_some_and(|host| ALLOWED_HOST_SUFFIXES.iter().any(|s| host.ends_with(s)));
    if allowed {
      Ok(Self(url))
    } else {
      Err(format!(
        "{s} is not an HTTPS URL on a host ending in {}",
        ALLOWED_HOST_SUFFIXES.join(" or ")
      ))
    }
  }
}

/// Falcon Guardian API client.
// Do not derive Debug here.
#[derive(Builder)]
pub struct Client {
  /// Falcon Guardian base URL, such as `https://api.crowdstrike.com/aidr/aiguard`.
  base_url: BaseUrl,
  /// Collector token.
  token: String,
  /// Time to wait for a verdict, including polling.
  timeout: Duration,
  #[builder(skip = reqwest::blocking::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("TLS backend and system config should initialize"))]
  http: reqwest::blocking::Client,
}

impl Client {
  /// Analyze and redact content to avoid manipulation of the model, addition of
  /// malicious content, and other undesirable data transfers.
  pub fn guard_chat_completions<X: Serialize>(
    &self,
    request: &GuardRequest<X>,
  ) -> Result<GuardResponse> {
    let deadline = Instant::now() + self.timeout;
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let url = format!(
      "{}/v1/guard_chat_completions",
      self.base_url.0.as_str().trim_end_matches('/')
    );
    let mut res = self
      .http
      .post(url)
      .bearer_auth(&self.token)
      .timeout(remaining())
      .json(request)
      .send()?;
    let mut polls: u32 = 0;
    loop {
      let status = res.status();
      let location = match step(&self.base_url.0, status, &res.text()?)? {
        Step::Done(body) => return Ok(body),
        Step::Poll(location) => location,
      };
      let delay = Duration::from_millis(500 << polls.min(4));
      polls += 1;
      thread::sleep(delay.min(remaining()));
      if remaining().is_zero() {
        return Err(format!("AIDR gave no verdict within {:?}", self.timeout).into());
      }
      res = self
        .http
        .get(location)
        .bearer_auth(&self.token)
        .timeout(remaining())
        .send()?;
    }
  }
}

/// A `/v1/guard_chat_completions` request. `X` is the collector's `extra_info`
/// logging schema.
#[derive(Serialize)]
pub struct GuardRequest<'a, X> {
  /// Prompt content and role array in `messages`. The `content` is the
  /// multimodal text or image input to analyze. Additional properties such as
  /// `tools` may be provided for analysis.
  pub guard_input: GuardInput,
  /// Event type: `input` (default), `output`, `tool_input`, `tool_output`, or
  /// `tool_listing`.
  pub event_type: &'static str,
  /// Session identifier for correlating multiple API calls within one logical
  /// session.
  pub session_id: &'a str,
  /// User or service account ID.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub user_id: Option<&'a str>,
  /// Classification of the AI agent originating this request: `code-assistant`,
  /// `chatbot`, or `subagent`.
  pub agent_type: &'static str,
  /// Whether the source is an AI coding or agentic agent.
  pub is_agent: bool,
  /// OS-level process identifier or caller-defined process key.
  pub process_id: String,
  /// Sensor process tag identifiers associated with the originating process.
  pub process_tags: &'static [&'static str],
  /// Logging schema.
  pub extra_info: X,
}

/// `guard_input` as sent, and `guard_output` as returned with redactions
/// applied.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct GuardInput {
  pub messages: Vec<Message>,
}

/// An OpenAI Chat Completions message, without tool call IDs.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum Message {
  User {
    content: String,
  },
  Assistant {
    content: Option<String>,
    tool_calls: Vec<ToolCall>,
  },
  Tool {
    content: String,
  },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ToolCall {
  pub r#type: String,
  pub function: Function,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Function {
  pub name: String,
  /// JSON-encoded arguments.
  pub arguments: String,
}

/// The Falcon Guardian response envelope.
#[derive(Deserialize)]
pub struct GuardResponse {
  pub status: String,
  pub summary: Option<String>,
  #[serde(default)]
  pub result: GuardResult,
}

#[derive(Deserialize, Default)]
pub struct GuardResult {
  #[serde(default)]
  pub blocked: bool,
  #[serde(default)]
  pub transformed: bool,
  /// Message to show the user when blocked or transformed. `Some("")` means
  /// show nothing.
  pub display_message: Option<String>,
  guard_output: Option<Value>,
}

impl GuardResult {
  /// The transformed copy of `guard_input`.
  pub fn guard_output(&self) -> Result<GuardInput> {
    let output = self
      .guard_output
      .as_ref()
      .ok_or("transformed result has no guard_output")?;
    Ok(GuardInput::deserialize(output)?)
  }
}

/// What to do after one Falcon Guardian response.
enum Step {
  Done(GuardResponse),
  Poll(Url),
}

/// A HTTP/202 body.
#[derive(Deserialize)]
struct Accepted {
  result: AcceptedResult,
}

#[derive(Deserialize)]
struct AcceptedResult {
  location: String,
}

/// Classify one Falcon Guardian response to a guard or poll request.
fn step(base: &Url, status: StatusCode, body: &str) -> Result<Step> {
  if status == StatusCode::ACCEPTED {
    let location = Url::parse(&serde_json::from_str::<Accepted>(body)?.result.location)?;
    if location.origin() != base.origin() {
      return Err(format!("AIDR poll location {location} is outside {base}").into());
    }
    return Ok(Step::Poll(location));
  }
  match serde_json::from_str::<GuardResponse>(body) {
    Ok(body) if status == StatusCode::OK && body.status == "Success" => Ok(Step::Done(body)),
    Ok(body) => Err(
      format!(
        "AIDR returned HTTP {status} {}: {}",
        body.status,
        body.summary.unwrap_or_default()
      )
      .into(),
    ),
    Err(_) => Err(format!("AIDR returned HTTP {status}").into()),
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  fn aidr() -> Url {
    Url::parse("https://api.crowdstrike.com/aidr/aiguard").unwrap()
  }

  fn accepted(location: &str) -> String {
    json!({
      "status": "Accepted",
      "summary": "Your request is in progress.",
      "result": { "location": location, "retry_counter": 0, "ttl_mins": 5760 },
    })
    .to_string()
  }

  #[test]
  fn base_url_must_be_https_on_a_crowdstrike_host() {
    for url in [
      "https://api.crowdstrike.com/aidr/aiguard",
      "https://x.collector-crowdstrike.com/aidr/aiguard",
      "https://API.CrowdStrike.com",
    ] {
      assert!(url.parse::<BaseUrl>().is_ok(), "{url}");
    }
    for url in [
      "http://api.crowdstrike.com",
      "https://crowdstrike.com",
      "https://evilcrowdstrike.com",
      "https://api.crowdstrike.com.evil.org",
      "https://example.org",
      "https://1.2.3.4",
      "not a url",
    ] {
      assert!(url.parse::<BaseUrl>().is_err(), "{url}");
    }
  }

  #[test]
  fn success_is_the_verdict() {
    let body = json!({ "status": "Success", "result": { "blocked": true } }).to_string();
    let Step::Done(res) = step(&aidr(), StatusCode::OK, &body).unwrap() else {
      panic!("expected a verdict");
    };
    assert!(res.result.blocked);
  }

  #[test]
  fn accepted_polls_the_location() {
    let location = "https://api.crowdstrike.com/aidr/aiguard/aiguard/request/prq_1";
    let Step::Poll(url) = step(&aidr(), StatusCode::ACCEPTED, &accepted(location)).unwrap() else {
      panic!("expected a poll");
    };
    assert_eq!(url.as_str(), location);
  }

  #[test]
  fn accepted_location_off_the_aidr_origin_is_an_error() {
    for location in [
      "https://example.org/aidr/aiguard/request/prq_1",
      "http://api.crowdstrike.com/aidr/aiguard/request/prq_1",
      "https://api.crowdstrike.com:8443/aidr/aiguard/request/prq_1",
    ] {
      assert!(step(&aidr(), StatusCode::ACCEPTED, &accepted(location)).is_err());
    }
  }

  #[test]
  fn errors_carry_the_aidr_summary() {
    let body = json!({ "status": "ValidationError", "summary": "bad input" }).to_string();
    let err = step(&aidr(), StatusCode::BAD_REQUEST, &body).err().unwrap();
    assert_eq!(
      err.to_string(),
      "AIDR returned HTTP 400 Bad Request ValidationError: bad input"
    );
    assert!(step(&aidr(), StatusCode::BAD_GATEWAY, "<html>").is_err());
  }
}
