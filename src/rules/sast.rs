//! Built-in security analysis rules, run by `wirelint security`.
//!
//! This module only registers rules; each rule family and its detection logic
//! live together in a submodule.

mod hardcoded_secret;
pub(crate) mod http;
pub(crate) mod system_exec;

use super::Rule;
use hardcoded_secret::HardcodedSecretDefault;
use http::HttpRule;
use system_exec::SystemExecCommandInput;

/// All built-in security rules, run by `wirelint security`.
pub static BUILT_INS: &[&dyn Rule] = &[
    &HardcodedSecretDefault,
    &SystemExecCommandInput,
    &HttpRule::ControlUrl,
    &HttpRule::PlaintextUrl,
    &HttpRule::ServerVerification,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_every_security_rule_once() {
        let ids = BUILT_INS.iter().map(|rule| rule.id()).collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "hardcoded-secret-default",
                "system-exec-command-input",
                "http-control-url",
                "http-plaintext-url",
                "http-server-verification"
            ]
        );
    }
}
