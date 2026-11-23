//! Strict, explicit YAML configuration for built-in rules.

use crate::formats::Version;
#[cfg(test)]
use crate::rules::quality::BUILT_INS;
use crate::rules::{Rule, Severity};
use clap::ValueEnum;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

/// Findings at or above this level cause exit status 1; analysis errors always fail.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    #[default]
    Error,
    Warning,
    None,
}

impl FailOn {
    /// Checks the finding severity without changing the reported severity.
    pub fn exceeded_by(self, severity: Severity) -> bool {
        match self {
            Self::Error => severity >= Severity::Error,
            Self::Warning => severity >= Severity::Warning,
            Self::None => false,
        }
    }
}

/// Debugging state that produces a finding, independent of rule enablement.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DebuggingState {
    #[default]
    Enabled,
    Disabled,
}

/// Preferred front-panel terminal display style, independent of rule enablement.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TerminalDisplayStyle {
    #[default]
    DataType,
    Icon,
}

/// Common options and validated options for individual built-in rules.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleConfig {
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub severity: Option<Severity>,
    #[serde(default, deserialize_with = "version_bound")]
    pub minimum_version: Option<Version>,
    #[serde(default, deserialize_with = "version_bound")]
    pub maximum_version: Option<Version>,
    #[serde(default, deserialize_with = "debugging_state")]
    pub fail_when: Option<DebuggingState>,
    #[serde(default, deserialize_with = "terminal_display_style")]
    pub preferred_style: Option<TerminalDisplayStyle>,
    #[serde(default, deserialize_with = "connector_pane_patterns")]
    pub allowed_patterns: Option<Vec<String>>,
}

/// Rejects explicit nulls and invalid states rather than substituting a default.
fn debugging_state<'de, D>(deserializer: D) -> Result<Option<DebuggingState>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    DebuggingState::deserialize(deserializer).map(Some)
}

/// Rejects explicit nulls and invalid styles rather than substituting a default.
fn terminal_display_style<'de, D>(deserializer: D) -> Result<Option<TerminalDisplayStyle>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    TerminalDisplayStyle::deserialize(deserializer).map(Some)
}

/// Requires string entries without YAML's implicit scalar-to-string coercion.
fn connector_pane_patterns<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<serde_yaml_ng::Value>::deserialize(deserializer)?
        .into_iter()
        .map(|value| match value {
            serde_yaml_ng::Value::String(name) => Ok(name),
            _ => Err(serde::de::Error::custom(
                "allowed-patterns entries must be strings",
            )),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// Accepts only a quoted major.minor string, avoiding YAML number coercion.
fn version_bound<'de, D>(deserializer: D) -> Result<Option<Version>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_yaml_ng::Value::deserialize(deserializer)? {
        serde_yaml_ng::Value::String(value) => Version::parse(&value)
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("version bound must be a major.minor string")),
        _ => Err(serde::de::Error::custom(
            "version bound must be a quoted major.minor string",
        )),
    }
}

/// Omitted enablement leaves a built-in rule active.
fn enabled() -> bool {
    true
}

/// Versioned configuration with all built-ins enabled unless overridden.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "schema_version")]
    version: u32,
    #[serde(default)]
    pub fail_on: FailOn,
    #[serde(default, deserialize_with = "folder_names")]
    pub exclude_folders: Vec<String>,
    #[serde(default, deserialize_with = "unique_rules")]
    pub rules: BTreeMap<String, RuleConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: schema_version(),
            fail_on: FailOn::default(),
            exclude_folders: Vec::new(),
            rules: BTreeMap::new(),
        }
    }
}

/// Current YAML schema version; omitted version selects version 1.
fn schema_version() -> u32 {
    1
}

/// Requires string entries without YAML's implicit scalar-to-string coercion.
fn folder_names<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<serde_yaml_ng::Value>::deserialize(deserializer)?
        .into_iter()
        .map(|value| match value {
            serde_yaml_ng::Value::String(name) => Ok(name),
            _ => Err(serde::de::Error::custom(
                "exclude-folders entries must be strings",
            )),
        })
        .collect()
}

/// Rejects duplicate rule IDs rather than silently accepting the last value.
fn unique_rules<'de, D>(deserializer: D) -> Result<BTreeMap<String, RuleConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueRules;
    impl<'de> serde::de::Visitor<'de> for UniqueRules {
        type Value = BTreeMap<String, RuleConfig>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a mapping of unique rule identifiers to rule options")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut rules = BTreeMap::new();
            while let Some((id, options)) = map.next_entry::<String, RuleConfig>()? {
                if rules.insert(id.clone(), options).is_some() {
                    return Err(serde::de::Error::custom(format!("duplicate rule '{id}'")));
                }
            }
            Ok(rules)
        }
    }
    deserializer.deserialize_map(UniqueRules)
}

impl Config {
    /// Loads configuration validated against an explicit rule registry
    /// for the selected command; no ancestor discovery. Returns path-qualified
    /// I/O/schema errors for invalid options or rule IDs.
    pub fn load_for(path: &Path, rules: &[&dyn Rule]) -> io::Result<Self> {
        let result = fs::read_to_string(path).and_then(|text| Self::parse_for(&text, rules));
        result.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("configuration '{}': {error}", path.display()),
            )
        })
    }

    /// Deserializes and validates a complete YAML configuration against `BUILT_INS`.
    #[cfg(test)]
    fn parse(text: &str) -> io::Result<Self> {
        Self::parse_for(text, BUILT_INS)
    }

    /// Deserializes and validates a complete YAML configuration against an
    /// explicit rule registry.
    fn parse_for(text: &str, rules: &[&dyn Rule]) -> io::Result<Self> {
        let config: Self = serde_yaml_ng::from_str(text)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if config.version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported configuration version; expected 1",
            ));
        }
        for name in &config.exclude_folders {
            if name.trim().is_empty()
                || matches!(name.as_str(), "." | "..")
                || name.contains(['/', '\\', '\0'])
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "exclude-folders entry {name:?} must be a nonempty folder name, not a path"
                    ),
                ));
            }
        }
        for (id, options) in &config.rules {
            if id == "minimum-saved-version" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rule 'minimum-saved-version' was renamed to 'saved-version'; rename the configuration key",
                ));
            }
            if !rules.iter().any(|rule| rule.id() == id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown rule '{id}'"),
                ));
            }
            for (name, bound) in [
                ("minimum-version", options.minimum_version),
                ("maximum-version", options.maximum_version),
            ] {
                if id != "saved-version" && bound.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{name} is not supported by rule '{id}'"),
                    ));
                }
            }
            if let (Some(minimum), Some(maximum)) =
                (options.minimum_version, options.maximum_version)
                && minimum > maximum
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "minimum-version must not exceed maximum-version",
                ));
            }
            if id != "debugging-status" && options.fail_when.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("fail-when is not supported by rule '{id}'"),
                ));
            }
            if id != "terminal-style" && options.preferred_style.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("preferred-style is not supported by rule '{id}'"),
                ));
            }
            if id != "connector-pane-pattern" && options.allowed_patterns.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("allowed-patterns is not supported by rule '{id}'"),
                ));
            }
            if let Some(allowed) = &options.allowed_patterns {
                if allowed.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "connector-pane-pattern's allowed-patterns must name at least one pattern",
                    ));
                }
                for name in allowed {
                    if !crate::rules::quality::CONNECTOR_PANE_PATTERNS
                        .iter()
                        .any(|(known, _)| known == name)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unknown connector pane pattern '{name}'"),
                        ));
                    }
                }
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_configuration_covers_all_rules_with_their_defaults() {
        let config = Config::parse(include_str!("../docs/wirelint.example.yaml")).unwrap();
        assert_eq!(config.fail_on, FailOn::default());
        assert_eq!(config.rules.len(), BUILT_INS.len());
        for rule in BUILT_INS {
            let options = config.rules.get(rule.id()).unwrap_or_else(|| {
                panic!("configuration template is missing rule '{}'", rule.id())
            });
            assert!(options.enabled, "template disables rule '{}'", rule.id());
            assert_eq!(
                options.severity,
                Some(rule.default_severity()),
                "template severity differs from the default for '{}'",
                rule.id()
            );
        }
        assert_eq!(
            config.rules["saved-version"].minimum_version,
            Some(crate::rules::quality::DEFAULT_MINIMUM_VERSION)
        );
        assert_eq!(config.rules["saved-version"].maximum_version, None);
        assert_eq!(
            config.rules["debugging-status"].fail_when,
            Some(DebuggingState::default())
        );
        assert_eq!(
            config.rules["terminal-style"].preferred_style,
            Some(TerminalDisplayStyle::default())
        );
    }

    #[test]
    fn loads_defaults_and_explicit_overrides() {
        let defaults = Config::parse("{}").unwrap();
        assert!(defaults.rules.is_empty());
        assert!(defaults.exclude_folders.is_empty());
        assert_eq!(defaults.fail_on, FailOn::Error);
        let config = Config::parse(
            "version: 1\nfail-on: warning\nrules:\n  separate-compiled-code:\n    enabled: false\n    severity: error\n",
        ).unwrap();
        assert_eq!(config.fail_on, FailOn::Warning);
        assert!(!config.rules["separate-compiled-code"].enabled);
        assert_eq!(
            config.rules["separate-compiled-code"].severity,
            Some(Severity::Error)
        );
        assert!(
            Config::parse("rules:\n  separate-compiled-code: {}")
                .unwrap()
                .rules["separate-compiled-code"]
                .enabled
        );
    }

    #[test]
    fn loads_folder_exclusions_and_rejects_paths_or_invalid_names() {
        let config = Config::parse("exclude-folders:\n  - .git\n  - .lv-venv\n").unwrap();
        assert_eq!(config.exclude_folders, [".git", ".lv-venv"]);
        assert!(
            Config::parse("exclude-folders: []")
                .unwrap()
                .exclude_folders
                .is_empty()
        );
        for yaml in [
            "exclude-folders: .git",
            "exclude-folders: [null]",
            "exclude-folders: [true]",
            "exclude-folders: [123]",
            "exclude-folders: ['']",
            "exclude-folders: ['   ']",
            "exclude-folders: ['.']",
            "exclude-folders: ['..']",
            "exclude-folders: ['nested/.git']",
            r"exclude-folders: ['nested\.git']",
            "exclude-folders: ['/absolute']",
            r"exclude-folders: ['C:\absolute']",
            r#"exclude-folders: ["bad\0name"]"#,
            "exclude-folders: []\nexclude-folders: []",
        ] {
            let error = Config::parse(yaml).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{yaml}");
        }
    }

    #[test]
    fn rejects_unknown_duplicate_or_invalid_configuration() {
        for yaml in [
            "version: 2",
            "version: 1\nversion: 1",
            "fail_on: warning",
            "fail-on: info",
            "rules:\n  typo: {}",
            "rules:\n  separate-compiled-code:\n    enable: false",
            "rules:\n  separate-compiled-code:\n    severity: fatal",
            "rules:\n  separate-compiled-code:\n    enabled: false\n    enabled: true",
            "rules:\n  separate-compiled-code: {}\n  separate-compiled-code: {}",
            "rules: []",
            "version: [",
            "{}\n---\n{}",
        ] {
            assert!(Config::parse(yaml).is_err(), "{yaml}");
        }
    }

    #[test]
    fn failure_threshold_is_independent_of_severity() {
        for severity in [Severity::Info, Severity::Warning, Severity::Error] {
            assert_eq!(
                FailOn::Error.exceeded_by(severity),
                severity == Severity::Error
            );
            assert_eq!(
                FailOn::Warning.exceeded_by(severity),
                severity != Severity::Info
            );
            assert!(!FailOn::None.exceeded_by(severity));
        }
    }

    #[test]
    fn validates_rule_specific_version_bounds() {
        for option in ["minimum-version", "maximum-version"] {
            let config =
                Config::parse(&format!("rules:\n  saved-version:\n    {option}: '21.3'\n"))
                    .unwrap();
            let options = &config.rules["saved-version"];
            assert_eq!(
                if option == "minimum-version" {
                    options.minimum_version
                } else {
                    options.maximum_version
                },
                Some(Version {
                    major: 21,
                    minor: 3
                })
            );
            for value in [
                "20.0", "null", "'20'", "'20.10'", "'100.0'", "'20.0.1'", "'-1.0'",
            ] {
                assert!(
                    Config::parse(&format!(
                        "rules:\n  saved-version:\n    {option}: {value}\n"
                    ))
                    .is_err(),
                    "{option}: {value}"
                );
            }
            for rule in [
                "separate-compiled-code",
                "file-description",
                "debugging-status",
            ] {
                assert!(
                    Config::parse(&format!("rules:\n  {rule}:\n    {option}: '20.0'\n")).is_err()
                );
            }
        }
        for (minimum, maximum, valid) in [
            ("20.0", "21.0", true),
            ("20.0", "20.0", true),
            ("20.1", "20.0", false),
            ("21.0", "20.9", false),
        ] {
            for enabled in [true, false] {
                let result = Config::parse(&format!(
                    "rules:\n  saved-version:\n    enabled: {enabled}\n    minimum-version: '{minimum}'\n    maximum-version: '{maximum}'\n"
                ));
                assert_eq!(result.is_ok(), valid, "{minimum}..={maximum}");
            }
        }
    }

    #[test]
    fn rejects_old_version_rule_with_migration_guidance() {
        for options in ["{}", "{enabled: false}", "{minimum-version: '20.0'}"] {
            let error = Config::parse(&format!("rules:\n  minimum-saved-version: {options}\n"))
                .unwrap_err();
            assert!(
                error.to_string().contains("renamed to 'saved-version'"),
                "{error}"
            );
        }
    }

    #[test]
    fn validates_rule_specific_debugging_state() {
        for (value, expected) in [
            ("enabled", DebuggingState::Enabled),
            ("disabled", DebuggingState::Disabled),
        ] {
            let config = Config::parse(&format!(
                "rules:\n  debugging-status:\n    fail-when: {value}\n"
            ))
            .unwrap();
            assert_eq!(config.rules["debugging-status"].fail_when, Some(expected));
        }
        for value in ["true", "false", "null", "0", "Enabled", "other", "[]"] {
            assert!(
                Config::parse(&format!(
                    "rules:\n  debugging-status:\n    fail-when: {value}\n"
                ))
                .is_err(),
                "{value}"
            );
        }
        assert!(
            Config::parse("rules:\n  separate-compiled-code:\n    fail-when: enabled\n").is_err()
        );
    }

    #[test]
    fn validates_rule_specific_preferred_terminal_style() {
        for (value, expected) in [
            ("data-type", TerminalDisplayStyle::DataType),
            ("icon", TerminalDisplayStyle::Icon),
        ] {
            let config = Config::parse(&format!(
                "rules:\n  terminal-style:\n    preferred-style: {value}\n"
            ))
            .unwrap();
            assert_eq!(
                config.rules["terminal-style"].preferred_style,
                Some(expected)
            );
        }
        for value in ["true", "false", "null", "0", "DataType", "other", "[]"] {
            assert!(
                Config::parse(&format!(
                    "rules:\n  terminal-style:\n    preferred-style: {value}\n"
                ))
                .is_err(),
                "{value}"
            );
        }
        assert!(
            Config::parse("rules:\n  separate-compiled-code:\n    preferred-style: icon\n")
                .is_err()
        );
    }
}
