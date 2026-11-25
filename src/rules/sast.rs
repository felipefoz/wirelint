//! Built-in security analysis rules, run by `wirelint sast`.
//!
//! This module only registers rules; each rule and its detection logic live
//! in their own submodule.

mod hardcoded_secret;
mod system_exec;

use super::Rule;
use hardcoded_secret::HardcodedSecretDefault;
use system_exec::SystemExecCommandInput;

/// All built-in security rules, run by `wirelint sast`.
pub static BUILT_INS: &[&dyn Rule] = &[&HardcodedSecretDefault, &SystemExecCommandInput];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_every_security_rule_once() {
        let ids = BUILT_INS.iter().map(|rule| rule.id()).collect::<Vec<_>>();
        assert_eq!(
            ids,
            ["hardcoded-secret-default", "system-exec-command-input"]
        );
    }
}
