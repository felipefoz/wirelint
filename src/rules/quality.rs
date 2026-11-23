//! Built-in quality and source-control hygiene rules.

use crate::config::{DebuggingState, RuleConfig, TerminalDisplayStyle};
use crate::formats::{FileFacts, Version};
use crate::rules::{Rule, Severity};

/// All built-in quality and hygiene rules, run by `wirelint scan`.
pub static BUILT_INS: &[&dyn Rule] = &[
    &SeparateCompiledCode,
    &SavedVersion,
    &FileDescription,
    &DebuggingStatus,
    &NoBreakpoints,
    &AutoErrorHandling,
    &PasswordSet,
    &OrphanedVi,
    &ClassMutationHistory,
    &TerminalStyle,
    &ConnectorPanePattern,
];

/// Default minimum release for saved LabVIEW files.
pub const DEFAULT_MINIMUM_VERSION: Version = Version {
    major: 20,
    minor: 0,
};

/// Requires the file owner's source-only setting to be enabled.
struct SeparateCompiledCode;

impl Rule for SeparateCompiledCode {
    fn id(&self) -> &'static str {
        "separate-compiled-code"
    }

    fn description(&self) -> &'static str {
        "Require separate compiled code from source"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        (!facts.separate_compiled_code)
            .then(|| "Enable separate compiled code from source (source-only setting).".to_owned())
    }
}

/// Requires each file's saved release to fall within inclusive configured bounds.
struct SavedVersion;

impl Rule for SavedVersion {
    fn id(&self) -> &'static str {
        "saved-version"
    }

    fn description(&self) -> &'static str {
        "Require saved LabVIEW version bounds (default minimum 20.0, no maximum)"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, options: Option<&RuleConfig>) -> Option<String> {
        let maximum = options.and_then(|options| options.maximum_version);
        let minimum = options
            .and_then(|options| options.minimum_version)
            .or_else(|| maximum.is_none().then_some(DEFAULT_MINIMUM_VERSION));
        let version = facts
            .saved_version
            .expect("active version rule requires a version fact");
        if let Some(minimum) = minimum
            && version < minimum
        {
            return Some(format!(
                "Saved LabVIEW version {version} is below the minimum {minimum}."
            ));
        }
        if let Some(maximum) = maximum
            && version > maximum
        {
            return Some(format!(
                "Saved LabVIEW version {version} is above the maximum {maximum}."
            ));
        }
        None
    }
}

/// Requires the file owner's native description to contain non-whitespace text.
struct FileDescription;

impl Rule for FileDescription {
    fn id(&self) -> &'static str {
        "file-description"
    }

    fn description(&self) -> &'static str {
        "Require a non-empty description for each LabVIEW file"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        (!facts
            .has_description
            .expect("active file-description rule requires a description fact"))
        .then(|| "Add a non-empty description to this LabVIEW file.".to_owned())
    }
}

/// Reports VIs whose stored debugging state matches the configured policy.
struct DebuggingStatus;

impl Rule for DebuggingStatus {
    fn id(&self) -> &'static str {
        "debugging-status"
    }

    fn description(&self) -> &'static str {
        "Check VI debugging status (default: flag debugging enabled)"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, options: Option<&RuleConfig>) -> Option<String> {
        let debugging_enabled = facts.debugging_enabled?;
        let fail_when = options
            .and_then(|options| options.fail_when)
            .unwrap_or_default();
        if debugging_enabled != (fail_when == DebuggingState::Enabled) {
            return None;
        }
        Some(if debugging_enabled {
            "Debugging is enabled. Disable Allow debugging in VI Properties > Execution.".to_owned()
        } else {
            "Debugging is disabled. Enable Allow debugging in VI Properties > Execution.".to_owned()
        })
    }
}

/// Rejects VIs saved with the LVSR breakpoints-set flag.
struct NoBreakpoints;

impl Rule for NoBreakpoints {
    fn id(&self) -> &'static str {
        "no-breakpoints"
    }

    fn description(&self) -> &'static str {
        "Disallow saved block diagram breakpoints"
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        facts
            .has_breakpoints
            .filter(|has_breakpoints| *has_breakpoints)
            .map(|_| "Remove all block diagram breakpoints before committing this VI.".to_owned())
    }
}

/// Rejects VIs saved with automatic error handling enabled.
struct AutoErrorHandling;

impl Rule for AutoErrorHandling {
    fn id(&self) -> &'static str {
        "auto-error-handling"
    }

    fn description(&self) -> &'static str {
        "Disallow automatic error handling"
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        facts
            .auto_error_handling
            .filter(|enabled| *enabled)
            .map(|_| {
                "Automatic error handling is enabled. Disable 'Enable automatic error handling' in VI Properties > Execution.".to_owned()
            })
    }
}

/// Reports VI and template files that have a password set.
struct PasswordSet;

impl Rule for PasswordSet {
    fn id(&self) -> &'static str {
        "password-set"
    }

    fn description(&self) -> &'static str {
        "Report VIs with a password set"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        facts
            .has_password
            .filter(|has_password| *has_password)
            .map(|_| {
                "This VI has a password set. Remove it if the VI should remain editable.".to_owned()
            })
    }
}

/// Rejects a VI that references a scanned library which does not list it.
struct OrphanedVi;

impl Rule for OrphanedVi {
    fn id(&self) -> &'static str {
        "orphaned-vi"
    }

    fn description(&self) -> &'static str {
        "Require library-owned VIs to be listed by their owning library"
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        facts
            .orphaned_vi
            .filter(|orphaned| *orphaned)
            .map(|_| "This VI points to a library that does not list it.".to_owned())
    }
}

/// Rejects nonempty class mutation-history content in LabVIEW class XML.
struct ClassMutationHistory;

impl Rule for ClassMutationHistory {
    fn id(&self) -> &'static str {
        "class-mutation-history"
    }

    fn description(&self) -> &'static str {
        "Disallow mutation-history content in LabVIEW classes"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        facts
            .has_mutation_history
            .filter(|has_history| *has_history)
            .map(|_| {
                "This LabVIEW class contains mutation-history content in its NI.LVClass.Geneology XML property.".to_owned()
            })
    }
}

/// Requires every terminal on a VI's block diagram to match a preferred display style.
struct TerminalStyle;

impl Rule for TerminalStyle {
    fn id(&self) -> &'static str {
        "terminal-style"
    }

    fn description(&self) -> &'static str {
        "Require a preferred terminal display style (default: data type) for every control and indicator"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, options: Option<&RuleConfig>) -> Option<String> {
        let styles = facts.terminal_icon_styles.as_ref()?;
        let preferred_icon = options
            .and_then(|options| options.preferred_style)
            .unwrap_or_default()
            == TerminalDisplayStyle::Icon;
        let mismatched = styles
            .iter()
            .filter(|icon_style| **icon_style != preferred_icon)
            .count();
        (mismatched > 0).then(|| {
            format!(
                "This VI has {mismatched} terminal(s) not using {} display. {} View As Icon on the block diagram for the affected controls and indicators.",
                if preferred_icon { "icon" } else { "data type" },
                if preferred_icon { "Enable" } else { "Disable" },
            )
        })
    }
}

/// Name and terminal count of each of LabVIEW's 36 fixed connector pane
/// patterns, indexed by the pattern's catalog offset (its raw `pattern`
/// field, from the VI's own Function TypeDesc, right-shifted by 3).
pub static CONNECTOR_PANE_PATTERNS: [(&str, u8); 36] = [
    ("1", 1),
    ("1x1", 2),
    ("2x1", 3),
    ("3", 3),
    ("3x1", 4),
    ("2x2", 4),
    ("4", 4),
    ("3x2", 5),
    ("4x1", 5),
    ("4x2", 6),
    ("3x3", 6),
    ("4x3", 7),
    ("4x4", 8),
    ("4x1x4", 9),
    ("4x2x4", 10),
    ("4x2x2x4", 12),
    ("3x2x1", 6),
    ("3x2x2", 7),
    ("3x2x3", 8),
    ("3x2x4", 9),
    ("3x2x2x3", 10),
    ("3x2x2x4", 11),
    ("4x2x3", 9),
    ("4x1x1", 6),
    ("4x1x2", 7),
    ("4x1x3", 8),
    ("4x1x1x4", 10),
    ("4x2x1", 7),
    ("4x2x2", 8),
    ("4x2x1x4", 11),
    ("2x1x1", 4),
    ("3x1x1", 5),
    ("3x1x2", 6),
    ("5x2x2x2x5", 16),
    ("6x2x2x2x2x6", 20),
    ("8x2x2x2x2x2x2x8", 28),
];

/// Restricts a VI's connector pane to a configured set of allowed patterns.
struct ConnectorPanePattern;

impl Rule for ConnectorPanePattern {
    fn id(&self) -> &'static str {
        "connector-pane-pattern"
    }

    fn description(&self) -> &'static str {
        "Restrict VI connector panes to a configured set of allowed patterns"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, options: Option<&RuleConfig>) -> Option<String> {
        let pattern_index = facts.connector_pane_pattern?;
        let allowed = options.and_then(|options| options.allowed_patterns.as_ref())?;
        let (name, _terminals) = CONNECTOR_PANE_PATTERNS[pattern_index as usize];
        if allowed.iter().any(|pattern| pattern == name) {
            return None;
        }
        Some(format!(
            "This VI's connector pane uses pattern '{name}', which is not in the allowed set: {}.",
            allowed.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_rules_have_no_cwe_mapping_by_default() {
        for rule in BUILT_INS {
            assert!(rule.cwe().is_empty(), "{}", rule.id());
        }
    }

    #[test]
    fn reports_disabled_separation_only() {
        let rule = &BUILT_INS[0];
        assert!(
            rule.check(
                &FileFacts {
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
                    default_string_values: None,
                },
                None
            )
            .is_some()
        );
        assert!(
            rule.check(
                &FileFacts {
                    separate_compiled_code: true,
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
                    default_string_values: None,
                },
                None
            )
            .is_none()
        );
    }

    #[test]
    fn compares_releases_numerically_at_the_boundary() {
        let rule = &SavedVersion;
        for (version, violation) in [
            (
                Version {
                    major: 19,
                    minor: 9,
                },
                true,
            ),
            (
                Version {
                    major: 20,
                    minor: 0,
                },
                false,
            ),
            (
                Version {
                    major: 20,
                    minor: 1,
                },
                false,
            ),
            (
                Version {
                    major: 21,
                    minor: 0,
                },
                false,
            ),
        ] {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: Some(version),
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
                default_string_values: None,
            };
            assert_eq!(rule.check(&facts, None).is_some(), violation);
        }
    }

    #[test]
    fn saved_version_supports_maximum_only_ranges_and_exact_releases() {
        let version = |major, minor| Version { major, minor };
        for (minimum, maximum, saved, expected) in [
            (None, Some(version(19, 0)), version(18, 9), None),
            (None, Some(version(19, 0)), version(19, 0), None),
            (
                None,
                Some(version(19, 0)),
                version(19, 1),
                Some("Saved LabVIEW version 19.1 is above the maximum 19.0."),
            ),
            (
                None,
                Some(version(20, 9)),
                version(21, 0),
                Some("Saved LabVIEW version 21.0 is above the maximum 20.9."),
            ),
            (
                Some(version(20, 1)),
                Some(version(21, 0)),
                version(20, 0),
                Some("Saved LabVIEW version 20.0 is below the minimum 20.1."),
            ),
            (
                Some(version(20, 1)),
                Some(version(21, 0)),
                version(20, 1),
                None,
            ),
            (
                Some(version(20, 1)),
                Some(version(21, 0)),
                version(20, 9),
                None,
            ),
            (
                Some(version(20, 1)),
                Some(version(21, 0)),
                version(21, 0),
                None,
            ),
            (
                Some(version(20, 1)),
                Some(version(21, 0)),
                version(21, 1),
                Some("Saved LabVIEW version 21.1 is above the maximum 21.0."),
            ),
            (
                Some(version(20, 0)),
                Some(version(20, 0)),
                version(20, 0),
                None,
            ),
            (
                Some(version(20, 0)),
                Some(version(20, 0)),
                version(19, 9),
                Some("Saved LabVIEW version 19.9 is below the minimum 20.0."),
            ),
            (
                Some(version(20, 0)),
                Some(version(20, 0)),
                version(20, 1),
                Some("Saved LabVIEW version 20.1 is above the maximum 20.0."),
            ),
            (
                None,
                None,
                version(19, 9),
                Some("Saved LabVIEW version 19.9 is below the minimum 20.0."),
            ),
            (None, None, version(20, 0), None),
            (
                Some(version(21, 0)),
                None,
                version(20, 9),
                Some("Saved LabVIEW version 20.9 is below the minimum 21.0."),
            ),
            (Some(version(21, 0)), None, version(21, 0), None),
        ] {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: Some(saved),
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
                default_string_values: None,
            };
            let options = RuleConfig {
                enabled: true,
                severity: None,
                minimum_version: minimum,
                maximum_version: maximum,
                fail_when: None,
                preferred_style: None,
                allowed_patterns: None,
            };
            assert_eq!(
                SavedVersion.check(&facts, Some(&options)).as_deref(),
                expected,
                "minimum {minimum:?}, maximum {maximum:?}, saved {saved}"
            );
        }
    }

    #[test]
    fn reports_missing_or_blank_file_descriptions() {
        let rule = &FileDescription;
        for (has_description, violation) in [(Some(false), true), (Some(true), false)] {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description,
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
                default_string_values: None,
            };
            assert_eq!(rule.check(&facts, None).is_some(), violation);
        }
    }

    #[test]
    fn debugging_policy_supports_both_states_and_skips_non_vi_files() {
        for debugging_enabled in [None, Some(false), Some(true)] {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: None,
                debugging_enabled,
                has_breakpoints: None,
                auto_error_handling: None,
                has_password: None,
                linked_library: None,
                library_members: None,
                orphaned_vi: None,
                has_mutation_history: None,
                terminal_icon_styles: None,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(
                DebuggingStatus.check(&facts, None).is_some(),
                debugging_enabled == Some(true)
            );
            for fail_when in [DebuggingState::Enabled, DebuggingState::Disabled] {
                let options = RuleConfig {
                    enabled: true,
                    severity: None,
                    minimum_version: None,
                    maximum_version: None,
                    fail_when: Some(fail_when),
                    preferred_style: None,
                    allowed_patterns: None,
                };
                let finding = DebuggingStatus.check(&facts, Some(&options));
                assert_eq!(
                    finding.is_some(),
                    debugging_enabled == Some(fail_when == DebuggingState::Enabled)
                );
                if let Some(message) = finding {
                    assert!(message.contains(if fail_when == DebuggingState::Enabled {
                        "Debugging is enabled. Disable"
                    } else {
                        "Debugging is disabled. Enable"
                    }));
                }
            }
        }
    }

    #[test]
    fn breakpoint_rule_flags_only_v_is_with_saved_breakpoints() {
        assert_eq!(NoBreakpoints.default_severity(), Severity::Error);
        for (has_breakpoints, expected) in [(None, false), (Some(false), false), (Some(true), true)]
        {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: None,
                debugging_enabled: None,
                has_breakpoints,
                auto_error_handling: None,
                has_password: None,
                linked_library: None,
                library_members: None,
                orphaned_vi: None,
                has_mutation_history: None,
                terminal_icon_styles: None,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(NoBreakpoints.check(&facts, None).is_some(), expected);
        }
    }

    #[test]
    fn password_rule_warns_only_when_a_vi_password_is_set() {
        assert_eq!(PasswordSet.default_severity(), Severity::Warning);
        for (has_password, expected) in [(None, false), (Some(false), false), (Some(true), true)] {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: None,
                debugging_enabled: None,
                has_breakpoints: None,
                auto_error_handling: None,
                has_password,
                linked_library: None,
                library_members: None,
                orphaned_vi: None,
                has_mutation_history: None,
                terminal_icon_styles: None,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(PasswordSet.check(&facts, None).is_some(), expected);
        }
    }

    #[test]
    fn automatic_error_handling_is_an_error_only_when_enabled() {
        assert_eq!(AutoErrorHandling.default_severity(), Severity::Error);
        for (auto_error_handling, expected) in
            [(None, false), (Some(false), false), (Some(true), true)]
        {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: None,
                debugging_enabled: None,
                has_breakpoints: None,
                auto_error_handling,
                has_password: None,
                linked_library: None,
                library_members: None,
                orphaned_vi: None,
                has_mutation_history: None,
                terminal_icon_styles: None,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(AutoErrorHandling.check(&facts, None).is_some(), expected);
        }
    }

    #[test]
    fn orphaned_vi_rule_is_an_error_only_for_unlisted_library_members() {
        assert_eq!(OrphanedVi.default_severity(), Severity::Error);
        for (orphaned_vi, expected) in [(None, false), (Some(false), false), (Some(true), true)] {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: None,
                debugging_enabled: None,
                has_breakpoints: None,
                auto_error_handling: None,
                has_password: None,
                linked_library: None,
                library_members: None,
                orphaned_vi,
                has_mutation_history: None,
                terminal_icon_styles: None,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(OrphanedVi.check(&facts, None).is_some(), expected);
        }
    }

    #[test]
    fn class_mutation_history_rule_flags_only_classes_with_content() {
        assert_eq!(ClassMutationHistory.default_severity(), Severity::Warning);
        for (has_mutation_history, expected) in
            [(None, false), (Some(true), true), (Some(false), false)]
        {
            let facts = FileFacts {
                separate_compiled_code: true,
                has_description: None,
                saved_version: None,
                debugging_enabled: None,
                has_breakpoints: None,
                auto_error_handling: None,
                has_password: None,
                linked_library: None,
                library_members: None,
                orphaned_vi: None,
                has_mutation_history,
                terminal_icon_styles: None,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(ClassMutationHistory.check(&facts, None).is_some(), expected);
        }
    }

    #[test]
    fn terminal_style_rule_defaults_to_requiring_data_type_style() {
        assert_eq!(TerminalStyle.default_severity(), Severity::Warning);
        for (terminal_icon_styles, expected) in [
            (None, false),
            (Some(vec![]), false),
            (Some(vec![false]), false),
            (Some(vec![false, false]), false),
            (Some(vec![true]), true),
            (Some(vec![false, true]), true),
        ] {
            let facts = FileFacts {
                separate_compiled_code: true,
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
                terminal_icon_styles,
                connector_pane_pattern: None,
                default_string_values: None,
            };
            assert_eq!(TerminalStyle.check(&facts, None).is_some(), expected);
        }
    }

    #[test]
    fn terminal_style_rule_honors_a_configured_preferred_style() {
        for (preferred_style, terminal_icon_styles, expected) in [
            (TerminalDisplayStyle::Icon, vec![true, true], false),
            (TerminalDisplayStyle::Icon, vec![true, false], true),
            (TerminalDisplayStyle::DataType, vec![false, false], false),
            (TerminalDisplayStyle::DataType, vec![true, false], true),
        ] {
            let facts = FileFacts {
                separate_compiled_code: true,
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
                terminal_icon_styles: Some(terminal_icon_styles),
                connector_pane_pattern: None,
                default_string_values: None,
            };
            let options = RuleConfig {
                enabled: true,
                severity: None,
                minimum_version: None,
                maximum_version: None,
                fail_when: None,
                preferred_style: Some(preferred_style),
                allowed_patterns: None,
            };
            assert_eq!(
                TerminalStyle.check(&facts, Some(&options)).is_some(),
                expected,
                "{preferred_style:?}"
            );
        }
    }

    fn facts_with_connector_pane_pattern(connector_pane_pattern: Option<u8>) -> FileFacts {
        FileFacts {
            separate_compiled_code: true,
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
            connector_pane_pattern,
            default_string_values: None,
        }
    }

    #[test]
    fn connector_pane_pattern_rule_is_inert_without_a_connector_pane_fact_or_an_allowed_list() {
        assert_eq!(ConnectorPanePattern.default_severity(), Severity::Warning);
        let facts = facts_with_connector_pane_pattern(None);
        assert!(ConnectorPanePattern.check(&facts, None).is_none());
        let facts = facts_with_connector_pane_pattern(Some(0));
        assert!(ConnectorPanePattern.check(&facts, None).is_none());
        let options = RuleConfig {
            enabled: true,
            severity: None,
            minimum_version: None,
            maximum_version: None,
            fail_when: None,
            preferred_style: None,
            allowed_patterns: None,
        };
        assert!(ConnectorPanePattern.check(&facts, Some(&options)).is_none());
    }

    #[test]
    fn connector_pane_pattern_rule_flags_patterns_outside_the_allowed_set() {
        let allowed_patterns = vec!["1".to_owned(), "2x2".to_owned()];
        let options = RuleConfig {
            enabled: true,
            severity: None,
            minimum_version: None,
            maximum_version: None,
            fail_when: None,
            preferred_style: None,
            allowed_patterns: Some(allowed_patterns),
        };
        // Index 0 -> "1" (allowed), index 5 -> "2x2" (allowed), index 2 -> "2x1" (not allowed).
        for (pattern_index, expected) in [(0u8, false), (5, false), (2, true)] {
            let facts = facts_with_connector_pane_pattern(Some(pattern_index));
            let finding = ConnectorPanePattern.check(&facts, Some(&options));
            assert_eq!(finding.is_some(), expected, "{pattern_index}");
            if let Some(message) = finding {
                assert!(message.contains("'2x1'"));
                assert!(message.contains("1, 2x2"));
            }
        }
    }
}
