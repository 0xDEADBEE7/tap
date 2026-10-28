//! Hooks are external commands (never run through a shell) that receive JSON
//! on stdin. Sync hooks may print modified JSON on stdout; async hooks are
//! notified and their output ignored. Hooks only run for in-scope traffic.
//!
//! Every run is bounded by its timeout, and stdin is written while stdout and
//! stderr are read, so payload size never matters. A failing hook leaves the
//! message unchanged and adds a note saying why.

mod json;
mod run;
#[cfg(test)]
mod tests;

use crate::record::{Exchange, Headers};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Largest allowed `timeout_ms` (10 minutes).
pub const MAX_TIMEOUT_MS: u64 = 600_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HookSpec {
    pub mode: HookMode,
    pub command: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HookMode {
    Sync,
    Async,
}

pub fn default_timeout_ms() -> u64 {
    5_000
}

/// The `hooks` object in a session's metadata.json.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct HookConfig {
    #[serde(default)]
    pub on_request: Vec<HookSpec>,
    #[serde(default)]
    pub on_response: Vec<HookSpec>,
    #[serde(default)]
    pub on_event: Vec<HookSpec>,
}

/// A request or response as seen (and possibly changed) by hooks.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HookMessage {
    /// Request hooks: the method; may be changed.
    pub method: Option<String>,
    /// Request hooks: path plus query; may be changed. Scheme/host/port cannot be changed.
    pub path: Option<String>,
    /// Response hooks: the status; may be changed.
    pub status: Option<u16>,
    pub headers: Headers,
    pub body: Bytes,
}

/// Read-only context passed alongside a message.
#[derive(Clone, Debug, Default)]
pub struct HookContext {
    pub session_id: String,
    pub seq: u64,
    pub method: String,
    pub url: String,
}

pub struct Hooks {
    config: HookConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Request,
    Response,
    Event,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Request => "on_request",
            Phase::Response => "on_response",
            Phase::Event => "on_event",
        }
    }
}

impl Hooks {
    pub fn new(config: HookConfig) -> Hooks {
        Hooks { config }
    }

    pub fn config(&self) -> &HookConfig {
        &self.config
    }

    pub fn has_sync_request(&self) -> bool {
        self.config
            .on_request
            .iter()
            .any(|hook| hook.mode == HookMode::Sync)
    }

    pub fn has_sync_response(&self) -> bool {
        self.config
            .on_response
            .iter()
            .any(|hook| hook.mode == HookMode::Sync)
    }

    pub fn has_request(&self) -> bool {
        !self.config.on_request.is_empty()
    }

    pub fn has_response(&self) -> bool {
        !self.config.on_response.is_empty()
    }

    pub fn has_event(&self) -> bool {
        !self.config.on_event.is_empty()
    }

    /// Runs `on_request` hooks: sync hooks in order (each sees the previous
    /// result), then async hooks with the final message. Returns the message to
    /// forward plus notes for the exchange record (failures, what changed).
    /// A failing or invalid hook leaves the message unchanged.
    pub async fn on_request(
        &self,
        context: &HookContext,
        message: HookMessage,
    ) -> (HookMessage, Vec<String>) {
        run_message_hooks(Phase::Request, &self.config.on_request, context, message).await
    }

    /// Same as [`Hooks::on_request`] for `on_response` hooks.
    pub async fn on_response(
        &self,
        context: &HookContext,
        message: HookMessage,
    ) -> (HookMessage, Vec<String>) {
        run_message_hooks(Phase::Response, &self.config.on_response, context, message).await
    }

    /// Runs `on_event` hooks with the finished (already redacted) exchange.
    /// Sync hooks may return a modified exchange.
    pub async fn on_event(&self, mut exchange: Exchange) -> (Exchange, Vec<String>) {
        let phase = Phase::Event;
        let mut notes = Vec::new();
        for hook in sync_hooks(&self.config.on_event) {
            let input = json::event_input(&exchange);
            let outcome = run_sync(hook, &input).await.and_then(|output| {
                output
                    .map(|output| json::apply_event(&exchange, &input, output))
                    .transpose()
            });
            match outcome {
                Ok(Some(applied)) => {
                    notes.extend(change_notes(phase, hook, &applied));
                    exchange = applied.value;
                }
                Ok(None) => {}
                Err(reason) => notes.push(failure_note(phase, hook, &reason)),
            }
        }
        for hook in async_hooks(&self.config.on_event) {
            let (hook, event) = (hook.clone(), exchange.clone());
            tokio::spawn(async move {
                let input = json::encode(&json::event_input(&event));
                notify(phase, &hook, event.seq, input).await;
            });
        }
        (exchange, notes)
    }
}

async fn run_message_hooks(
    phase: Phase,
    hooks: &[HookSpec],
    context: &HookContext,
    mut message: HookMessage,
) -> (HookMessage, Vec<String>) {
    let mut notes = Vec::new();
    for hook in sync_hooks(hooks) {
        let input = json::message_input(phase, context, &message);
        let outcome = run_sync(hook, &input).await.and_then(|output| {
            output
                .map(|output| json::apply_message(phase, &input, &message, output))
                .transpose()
        });
        match outcome {
            Ok(Some(applied)) => {
                notes.extend(change_notes(phase, hook, &applied));
                message = applied.value;
            }
            Ok(None) => {}
            Err(reason) => notes.push(failure_note(phase, hook, &reason)),
        }
    }
    for hook in async_hooks(hooks) {
        let (hook, context, message) = (hook.clone(), context.clone(), message.clone());
        // The input is built and written inside the task so the caller never waits.
        tokio::spawn(async move {
            let input = json::encode(&json::message_input(phase, &context, &message));
            notify(phase, &hook, context.seq, input).await;
        });
    }
    (message, notes)
}

fn sync_hooks(hooks: &[HookSpec]) -> impl Iterator<Item = &HookSpec> {
    hooks.iter().filter(|hook| hook.mode == HookMode::Sync)
}

fn async_hooks(hooks: &[HookSpec]) -> impl Iterator<Item = &HookSpec> {
    hooks.iter().filter(|hook| hook.mode == HookMode::Async)
}

/// Runs a sync hook and parses its output; `None` means it printed nothing.
async fn run_sync(hook: &HookSpec, input: &json::Object) -> Result<Option<Value>, String> {
    let stdout = run::run(&hook.command, hook.timeout_ms, json::encode(input), true).await?;
    json::decode(&stdout)
}

/// Runs an async hook; failures go to stderr, which the session's run process logs to tap.log.
async fn notify(phase: Phase, hook: &HookSpec, seq: u64, input: Vec<u8>) {
    if let Err(reason) = run::run(&hook.command, hook.timeout_ms, input, false).await {
        eprintln!(
            "tap: async {} hook `{}` (exchange {seq}): {reason}",
            phase.name(),
            display(&hook.command)
        );
    }
}

fn failure_note(phase: Phase, hook: &HookSpec, reason: &str) -> String {
    format!(
        "{} hook `{}`: {reason}; unchanged",
        phase.name(),
        display(&hook.command)
    )
}

fn change_notes<T>(phase: Phase, hook: &HookSpec, applied: &json::Applied<T>) -> Vec<String> {
    let mut notes = Vec::new();
    let label = format!("{} hook `{}`", phase.name(), display(&hook.command));
    if !applied.ignored.is_empty() {
        notes.push(format!(
            "{label}: ignored changes to read-only {}",
            applied.ignored.join(", ")
        ));
    }
    if !applied.changed.is_empty() {
        notes.push(format!("{label}: changed {}", applied.changed.join(", ")));
    }
    notes
}

/// The command as shown in notes: one line, long arguments (inline scripts) shortened.
fn display(command: &[String]) -> String {
    let parts: Vec<String> = command
        .iter()
        .map(|part| shorten(&part.split_whitespace().collect::<Vec<_>>().join(" "), 40))
        .collect();
    shorten(&parts.join(" "), 120)
}

fn shorten(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut short: String = text.chars().take(limit - 3).collect();
    short.push_str("...");
    short
}

/// Checks a hook configuration before a session starts (non-empty commands,
/// positive timeouts). Returns a message naming the bad hook.
pub fn validate(config: &HookConfig) -> Result<(), String> {
    let phases = [
        (Phase::Request, &config.on_request),
        (Phase::Response, &config.on_response),
        (Phase::Event, &config.on_event),
    ];
    for (phase, hooks) in phases {
        for (index, hook) in hooks.iter().enumerate() {
            let at = format!("hooks.{}[{index}]", phase.name());
            match hook.command.first() {
                None => {
                    return Err(format!(
                        "{at}: command is empty; set it to the program and its arguments, e.g. [\"python3\", \"hook.py\"]"
                    ))
                }
                Some(program) if program.trim().is_empty() => {
                    return Err(format!(
                        "{at}: the program name (the first element of command) is empty"
                    ))
                }
                Some(_) => {}
            }
            if hook.timeout_ms == 0 || hook.timeout_ms > MAX_TIMEOUT_MS {
                return Err(format!(
                    "{at} (`{}`): timeout_ms must be between 1 and {MAX_TIMEOUT_MS}, got {}",
                    display(&hook.command),
                    hook.timeout_ms
                ));
            }
        }
    }
    Ok(())
}
