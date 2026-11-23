//! Shared rule contract and separately maintained quality and security rules.

pub mod quality;
pub mod sast;

use crate::config::RuleConfig;
use crate::formats::FileFacts;
use serde::Deserialize;
use std::fmt;

/// Ordered finding severity, independent of the configured failure threshold.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        })
    }
}

/// Stateless analysis of facts extracted once by the format layer.
///
/// Rules do not read files, print output, or decide process exit status.
pub trait Rule: Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn default_severity(&self) -> Severity;

    /// Returns a finding message when the facts violate this rule.
    fn check(&self, facts: &FileFacts, options: Option<&RuleConfig>) -> Option<String>;

    /// CWE identifiers this rule's findings map to; empty for non-security rules.
    fn cwe(&self) -> &'static [&'static str] {
        &[]
    }
}
