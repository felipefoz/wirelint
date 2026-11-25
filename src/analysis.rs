//! Rule execution and findings, separate from discovery and presentation.

use crate::config::{Config, FailOn};
use crate::formats;
use crate::rules::{Rule, Severity};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// A rule violation associated with one scan-relative file path.
#[derive(Debug)]
pub struct Finding {
    pub path: PathBuf,
    pub rule: &'static str,
    pub severity: Severity,
    pub message: String,
}

/// A file that could not be analyzed; never represented as a passing check.
#[derive(Debug)]
pub struct AnalysisError {
    pub path: PathBuf,
    pub message: String,
}

/// An enabled rule suppressed by a directive in the same file.
#[derive(Debug)]
pub struct Skipped {
    pub path: PathBuf,
    pub rule: &'static str,
}

/// Findings and errors accumulated in discovery/registry order.
#[derive(Debug, Default)]
pub struct Report {
    pub analyzed: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<AnalysisError>,
    pub skipped: Vec<Skipped>,
}

impl Report {
    /// Errors take precedence over severity-based failure (2, 1, or 0).
    pub fn exit_status(&self, fail_on: FailOn) -> u8 {
        if !self.errors.is_empty() {
            2
        } else if self
            .findings
            .iter()
            .any(|finding| fail_on.exceeded_by(finding.severity))
        {
            1
        } else {
            0
        }
    }
}

/// Reads each file once and runs every enabled rule over the extracted facts.
///
/// File errors are recorded and scanning continues. When all rules are disabled,
/// discovered files are not read and the analyzed count is zero. `rules` is
/// the active registry for the selected command.
pub fn analyze(root: &Path, files: &[PathBuf], config: &Config, rules: &[&dyn Rule]) -> Report {
    let active: Vec<_> = rules
        .iter()
        .filter_map(|rule| {
            let options = config.rules.get(rule.id());
            if options.is_some_and(|options| !options.enabled) {
                None
            } else {
                Some((
                    *rule,
                    options
                        .and_then(|options| options.severity)
                        .unwrap_or_else(|| rule.default_severity()),
                    options,
                ))
            }
        })
        .collect();
    let mut report = Report::default();
    if active.is_empty() {
        return report;
    }
    let read_version = active
        .iter()
        .any(|(rule, _, _)| rule.id() == "saved-version");
    let read_description = active
        .iter()
        .any(|(rule, _, _)| rule.id() == "file-description");
    let read_password = active
        .iter()
        .any(|(rule, _, _)| rule.id() == "password-set");
    let read_orphaned_vi = active.iter().any(|(rule, _, _)| rule.id() == "orphaned-vi");
    let read_connector_pane_pattern = active.iter().any(|(rule, _, options)| {
        rule.id() == "connector-pane-pattern"
            && options.is_some_and(|options| options.allowed_patterns.is_some())
    });
    let read_default_strings = active
        .iter()
        .any(|(rule, _, _)| rule.id() == "hardcoded-secret-default");
    let read_command_inputs = active
        .iter()
        .any(|(rule, _, _)| rule.id() == "system-exec-command-input");
    let read_paths = active.iter().any(|(rule, _, _)| rule.id() == "path-usage");
    let mut analyzed_files = Vec::new();
    for path in files {
        let result = fs::read(root.join(path)).and_then(|bytes| {
            let (mut facts, bookmarks) = formats::read_facts_with_orphaned_vi(
                path,
                &bytes,
                read_version,
                read_description,
                read_password,
                read_orphaned_vi,
                read_connector_pane_pattern,
                read_default_strings,
            )?;
            if read_command_inputs
                && !bookmarks
                    .iter()
                    .any(|bookmark| suppresses(bookmark, "system-exec-command-input"))
            {
                facts.system_exec_inputs = formats::read_system_exec_inputs(path, &bytes)?;
            }
            if read_paths
                && !bookmarks
                    .iter()
                    .any(|bookmark| suppresses(bookmark, "path-usage"))
            {
                facts.path_usage = formats::read_path_usage(path, &bytes)?;
            }
            Ok((facts, bookmarks))
        });
        match result {
            Ok((facts, bookmarks)) => {
                report.analyzed += 1;
                analyzed_files.push((path.clone(), facts, bookmarks));
            }
            Err(error) => report.errors.push(AnalysisError {
                path: path.clone(),
                message: error.to_string(),
            }),
        }
    }
    if read_orphaned_vi {
        apply_orphaned_vi_facts(&mut analyzed_files);
    }
    for (path, facts, bookmarks) in analyzed_files {
        for (rule, severity, options) in &active {
            if bookmarks
                .iter()
                .any(|bookmark| suppresses(bookmark, rule.id()))
            {
                report.skipped.push(Skipped {
                    path: path.clone(),
                    rule: rule.id(),
                });
                continue;
            }
            if let Some(message) = rule.check(&facts, *options) {
                report.findings.push(Finding {
                    path: path.clone(),
                    rule: rule.id(),
                    severity: *severity,
                    message,
                });
            }
            if rule.id() == "system-exec-command-input"
                && let Some(inputs) = &facts.system_exec_inputs
                && let Some((uid, reason)) = inputs.incomplete_calls.first()
            {
                report.errors.push(AnalysisError {
                    path: path.clone(),
                    message: format!(
                        "system-exec-command-input: incomplete analysis of {} call(s); node {uid}: {reason}",
                        inputs.incomplete_calls.len()
                    ),
                });
            }
        }
    }
    report
}

/// Matches an exact two-token, ASCII rule directive; other bookmarks are inert.
fn suppresses(bookmark: &[u8], rule: &str) -> bool {
    formats::directive_rule(bookmark) == Some(rule.as_bytes())
}

/// Resolves only relative VI/library URLs against files discovered in this scan.
fn apply_orphaned_vi_facts(files: &mut [(PathBuf, formats::FileFacts, Vec<Vec<u8>>)]) {
    let mut library_members = HashMap::<PathBuf, HashSet<PathBuf>>::new();
    for (library_path, facts, _) in files.iter() {
        let Some(members) = facts.library_members.as_ref() else {
            continue;
        };
        let resolved_members = members
            .iter()
            .filter_map(|member| resolve_scanned_path(library_path, member))
            .collect();
        library_members.insert(library_path.clone(), resolved_members);
    }

    for (vi_path, facts, _) in files {
        let Some(linked_library) = facts.linked_library.as_deref() else {
            continue;
        };
        let Some(library_path) = resolve_scanned_path(vi_path, &linked_library.to_string_lossy())
        else {
            continue;
        };
        let Some(members) = library_members.get(&library_path) else {
            continue;
        };
        facts.orphaned_vi = Some(!members.contains(vi_path));
    }
}

/// Normalizes a relative URL while refusing absolute paths and scan-root escapes.
fn resolve_scanned_path(base: &Path, path: &str) -> Option<PathBuf> {
    let path = path.replace('\\', "/");
    if path.starts_with('/')
        || path.as_bytes().get(1) == Some(&b':')
        || path.as_bytes().contains(&0)
    {
        return None;
    }
    let mut resolved = base.to_path_buf();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." if !resolved.pop() => return None,
            ".." => {}
            component => resolved.push(component),
        }
    }
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::{resolve_scanned_path, suppresses};
    use std::path::{Path, PathBuf};

    #[test]
    fn matches_only_complete_rule_directives() {
        for (text, expected) in [
            ("#wirelint-ignore file-description", true),
            ("#wirelint-ignore\tfile-description  ", true),
            (" #wirelint-ignore file-description", false),
            ("#wirelint-ignore file-description-extra", false),
            ("#wirelint-ignore file-description extra", false),
            ("#wirelint-ignore no-breakpoints", false),
            ("#WireLint-ignore file-description", false),
            ("#todo #wirelint-ignore file-description", false),
            ("#wirelint file-description", false),
        ] {
            assert_eq!(
                suppresses(text.as_bytes(), "file-description"),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn normalizes_relative_urls_and_rejects_paths_outside_the_scan_root() {
        assert_eq!(
            resolve_scanned_path(Path::new("owner.lvlib"), "../member.vi"),
            Some(PathBuf::from("member.vi"))
        );
        assert_eq!(
            resolve_scanned_path(
                Path::new("nested").join("owner.lvlib").as_path(),
                r"..\Sub\member.vi"
            ),
            Some(PathBuf::from("nested").join("Sub").join("member.vi"))
        );
        assert_eq!(
            resolve_scanned_path(Path::new("owner.lvlib"), "../../outside.vi"),
            None
        );
        assert_eq!(
            resolve_scanned_path(Path::new("nested"), r"..\library\owner.lvlib"),
            Some(PathBuf::from("library").join("owner.lvlib"))
        );
        for path in [
            "/absolute/file.vi",
            r"C:\absolute\file.vi",
            "../../outside.vi",
        ] {
            assert_eq!(
                resolve_scanned_path(Path::new("nested"), path),
                None,
                "{path}"
            );
        }
    }
}
