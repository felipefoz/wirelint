//! Review warning for control-influenced command input to NI System Exec.vi.
//!
//! Connectivity and supported local transfers are resolved by the format layer.
//! Findings make no claim about attacker access, shell use or exploitability.

use crate::config::RuleConfig;
use crate::formats::FileFacts;
use crate::rules::{Rule, Severity};

pub(super) struct SystemExecCommandInput;

impl Rule for SystemExecCommandInput {
    fn id(&self) -> &'static str {
        "system-exec-command-input"
    }

    fn description(&self) -> &'static str {
        "Review control-influenced command input to NI System Exec.vi"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        let count = facts.system_exec_inputs.as_ref()?.influenced_calls.len();
        if count == 0 {
            return None;
        }
        Some(format!(
            "Front-panel control input reaches the command line of System Exec.vi ({count} call(s)). Review possible command/argument injection; restrict executable and arguments to trusted choices. This is not proof of exploitability."
        ))
    }

    fn cwe(&self) -> &'static [&'static str] {
        &["CWE-78", "CWE-88"]
    }
}
