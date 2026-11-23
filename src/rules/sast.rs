//! Built-in security analysis rules.

use super::{Rule, Severity};
use crate::config::RuleConfig;
use crate::formats::FileFacts;

/// All built-in security rules, run by `wirelint sast`.
pub static BUILT_INS: &[&dyn Rule] = &[&HardcodedSecretDefault];

const CREDENTIAL_KEYS: &[&[u8]] = &[
    b"password",
    b"passwd",
    b"pwd",
    b"secret",
    b"token",
    b"api_key",
    b"api-key",
    b"apikey",
    b"access_key",
    b"access-key",
    b"client_secret",
    b"client-secret",
    b"private_key",
    b"private-key",
    b"credential",
    b"credentials",
];

/// Reports literal credentials stored in VI string defaults.
struct HardcodedSecretDefault;

impl Rule for HardcodedSecretDefault {
    fn id(&self) -> &'static str {
        "hardcoded-secret-default"
    }

    fn description(&self) -> &'static str {
        "Detect credential-like assignments in VI string defaults"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        facts
            .default_string_values
            .as_ref()?
            .iter()
            .any(|value| contains_hardcoded_secret(&value.bytes))
            .then(|| {
                "A string default contains a non-placeholder value assigned to a credential-like key. Remove it or load the secret securely.".to_owned()
            })
    }

    fn cwe(&self) -> &'static [&'static str] {
        &["CWE-798", "CWE-259"]
    }
}

/// Matches explicit credential-key assignments without retaining or reporting values.
fn contains_hardcoded_secret(bytes: &[u8]) -> bool {
    CREDENTIAL_KEYS.iter().any(|key| {
        if bytes.len() < key.len() {
            return false;
        }
        (0..=bytes.len() - key.len()).any(|start| {
            if !bytes[start..start + key.len()].eq_ignore_ascii_case(key)
                || start
                    .checked_sub(1)
                    .and_then(|index| bytes.get(index))
                    .is_some_and(u8::is_ascii_alphanumeric)
            {
                return false;
            }

            let mut cursor = start + key.len();
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if !matches!(bytes.get(cursor), Some(b'=' | b':')) {
                return false;
            }
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }

            let value = match bytes.get(cursor) {
                Some(quote @ (b'\'' | b'"')) => {
                    let value_start = cursor + 1;
                    let value_end = bytes[value_start..]
                        .iter()
                        .position(|byte| byte == quote)
                        .map_or(bytes.len(), |offset| value_start + offset);
                    &bytes[value_start..value_end]
                }
                Some(_) => {
                    let value_start = cursor;
                    let value_end = bytes[value_start..]
                        .iter()
                        .position(|byte| {
                            byte.is_ascii_whitespace() || matches!(byte, b',' | b';' | b'&' | b'}')
                        })
                        .map_or(bytes.len(), |offset| value_start + offset);
                    &bytes[value_start..value_end]
                }
                None => return false,
            };
            !value.is_empty() && !is_placeholder(value)
        })
    })
}

/// Excludes common template values and environment-variable references.
fn is_placeholder(value: &[u8]) -> bool {
    let Some(start) = value.iter().position(|byte| !byte.is_ascii_whitespace()) else {
        return true;
    };
    let end = value
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .expect("non-whitespace start has a non-whitespace end");
    let value = value[start..=end].to_ascii_lowercase();

    const PLACEHOLDERS: &[&[u8]] = &[
        b"changeme",
        b"change_me",
        b"change-me",
        b"placeholder",
        b"redacted",
        b"dummy",
        b"example",
        b"test",
        b"none",
        b"null",
        b"undefined",
        b"xxxx",
        b"****",
    ];

    PLACEHOLDERS.contains(&value.as_slice())
        || value.starts_with(b"your_")
        || value.starts_with(b"your-")
        || value.starts_with(b"your ")
        || value.starts_with(b"${") && value.ends_with(b"}")
        || value.starts_with(b"{{") && value.ends_with(b"}}")
        || value.starts_with(b"<") && value.ends_with(b">")
        || value.starts_with(b"$")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::DefaultStringValue;

    fn facts(values: Vec<&[u8]>) -> FileFacts {
        FileFacts {
            separate_compiled_code: false,
            has_description: None,
            saved_version: None,
            debugging_enabled: None,
            has_breakpoints: None,
            auto_error_handling: None,
            has_password: None,
            linked_library: None,
            library_members: None,
            orphaned_vi: None,
            has_mutation_history: None,
            terminal_icon_styles: None,
            connector_pane_pattern: None,
            default_string_values: Some(
                values
                    .into_iter()
                    .enumerate()
                    .map(|(type_map_index, bytes)| DefaultStringValue {
                        type_map_index,
                        field_path: Vec::new(),
                        bytes: bytes.to_vec(),
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn reports_credential_assignments_without_exposing_the_value() {
        let rule = &HardcodedSecretDefault;
        for value in [
            b"password = hunter2".as_slice(),
            b"API_KEY: \"sk-example-secret\"".as_slice(),
            b"db_password=letmein".as_slice(),
        ] {
            let message = rule.check(&facts(vec![value]), None).unwrap();
            assert!(!message.contains("hunter2"));
            assert!(!message.contains("sk-example-secret"));
            assert!(!message.contains("letmein"));
        }
    }

    #[test]
    fn ignores_prompts_unlabeled_values_and_placeholders() {
        for value in [
            b"Enter your password".as_slice(),
            b"this-is-a-long-random-looking-value".as_slice(),
            b"password=",
            b"password=changeme",
            b"password=${PASSWORD}",
            b"secret=<placeholder>",
            b"my_password_variable",
        ] {
            assert!(
                HardcodedSecretDefault
                    .check(&facts(vec![value]), None)
                    .is_none(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn requires_default_string_facts_and_exposes_cwe_mapping() {
        assert!(
            HardcodedSecretDefault
                .check(
                    &FileFacts {
                        default_string_values: None,
                        ..facts(Vec::new())
                    },
                    None,
                )
                .is_none()
        );
        assert_eq!(HardcodedSecretDefault.cwe(), &["CWE-798", "CWE-259"]);
        assert_eq!(BUILT_INS.len(), 1);
        assert_eq!(BUILT_INS[0].id(), "hardcoded-secret-default");
        assert_eq!(BUILT_INS[0].default_severity(), Severity::Warning);
    }
}
