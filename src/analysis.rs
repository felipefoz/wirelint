//! Rule execution and findings, separate from discovery and presentation.

use crate::config::{Config, FailOn, RuleCategory};
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
    pub object: Option<formats::ObjectId>,
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
pub fn analyze(
    root: &Path,
    files: &[PathBuf],
    config: &Config,
    category: RuleCategory,
    rules: &[&dyn Rule],
) -> Report {
    let rule_options = config.rules(category);
    let active: Vec<_> = rules
        .iter()
        .filter_map(|rule| {
            let options = rule_options.get(rule.id());
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
    let http_enabled = [
        "http-control-url",
        "http-plaintext-url",
        "http-server-verification",
    ]
    .map(|id| active.iter().any(|(rule, _, _)| rule.id() == id));
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
            let directives = formats::read_directives(path, &bytes, bookmarks)?;
            if (read_command_inputs || http_enabled.iter().any(|enabled| *enabled))
                && let Some(links) = formats::read_call_links(path, &bytes)?
            {
                let needs_graph = (read_command_inputs
                    && crate::rules::sast::system_exec::has_calls(&links))
                    || crate::rules::sast::http::has_calls(&links, http_enabled);
                let graph = if needs_graph {
                    formats::read_diagram_graph(&bytes)?
                } else {
                    None
                };
                if read_command_inputs {
                    facts.call_inputs.insert(
                        "system-exec-command-input",
                        crate::rules::sast::system_exec::analyze_links(&links, graph.as_ref()),
                    );
                }
                if http_enabled.iter().any(|enabled| *enabled) {
                    facts
                        .call_inputs
                        .extend(crate::rules::sast::http::analyze_links(
                            &links,
                            graph.as_ref(),
                            http_enabled,
                        ));
                }
            }
            if read_paths {
                facts.path_values = formats::read_path_values(path, &bytes)?;
            }
            Ok((facts, directives))
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
    for (path, mut facts, bookmarks) in analyzed_files {
        for (rule, severity, options) in &active {
            if let Some(evidence) = facts.call_inputs.get(rule.id())
                && let Some((uid, reason)) = evidence.incomplete.first()
            {
                report.errors.push(AnalysisError {
                    path: path.clone(),
                    message: format!(
                        "{}: incomplete analysis of {} call(s); node {uid}: {reason}",
                        rule.id(),
                        evidence.incomplete.len()
                    ),
                });
            }
            if bookmarks
                .iter()
                .any(|bookmark| bookmark.object.is_none() && suppresses(&bookmark.text, rule.id()))
            {
                report.skipped.push(Skipped {
                    path: path.clone(),
                    rule: rule.id(),
                    object: None,
                });
                continue;
            }
            let targets: std::collections::BTreeSet<_> = bookmarks
                .iter()
                .filter(|bookmark| suppresses(&bookmark.text, rule.id()))
                .filter_map(|bookmark| bookmark.object)
                .collect();
            for object in targets {
                if !matches!(rule.id(), "path-usage" | "hardcoded-secret-default")
                    && !rule.supports_call_suppression()
                {
                    report.errors.push(AnalysisError {
                        path: path.clone(),
                        message: format!("{}: object-scoped ignore is not supported for this rule; remove the arrow for a file-wide ignore", rule.id()),
                    });
                } else if suppress_object(&mut facts, rule.id(), object) {
                    report.skipped.push(Skipped {
                        path: path.clone(),
                        rule: rule.id(),
                        object: Some(object),
                    });
                }
            }
            if let Some(message) = rule.check(&facts, *options) {
                report.findings.push(Finding {
                    path: path.clone(),
                    rule: rule.id(),
                    severity: *severity,
                    message,
                });
            }
        }
    }
    report
}

/// Removes only the named rule's source objects, before its message aggregation.
///
/// Incomplete analysis is never removed. A structure or a neighboring object
/// has no implicit scope over descendants or dataflow.
fn suppress_object(facts: &mut formats::FileFacts, rule: &str, object: formats::ObjectId) -> bool {
    fn remove<T>(values: &mut Option<Vec<T>>, matches: impl Fn(&T) -> bool) -> bool {
        let Some(values) = values else { return false };
        let count = values.len();
        values.retain(|value| !matches(value));
        values.len() != count
    }
    match rule {
        "path-usage" => remove(&mut facts.path_values, |value| value.object == Some(object)),
        "hardcoded-secret-default" => {
            let defaults = remove(&mut facts.default_string_values, |value| {
                value.object == Some(object)
            });
            let constants = remove(&mut facts.diagram_string_values, |value| {
                value.object == Some(object)
            });
            defaults || constants
        }
        _ if object.heap == formats::SourceHeap::Diagram => {
            let Some(evidence) = facts.call_inputs.get_mut(rule) else {
                return false;
            };
            let count = evidence.calls.len();
            evidence.calls.retain(|uid| *uid != object.uid);
            evidence.calls.len() != count
        }
        _ => false,
    }
}

/// Matches an exact two-token, ASCII rule directive; other bookmarks are inert.
fn suppresses(bookmark: &[u8], rule: &str) -> bool {
    formats::directive_rule(bookmark) == Some(rule.as_bytes())
}

/// Resolves only relative VI/library URLs against files discovered in this scan.
fn apply_orphaned_vi_facts(files: &mut [(PathBuf, formats::FileFacts, Vec<formats::Directive>)]) {
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
    use super::{resolve_scanned_path, suppress_object, suppresses};
    use crate::formats::{self, ObjectId, SourceHeap};
    use std::path::{Path, PathBuf};

    #[test]
    fn object_ignores_do_not_cross_heaps_rules_or_incomplete_command_paths() {
        let mut facts =
            formats::read_facts(Path::new("test.lvproj"), b"<Project/>", false, false, false)
                .unwrap();
        let diagram = ObjectId {
            heap: SourceHeap::Diagram,
            uid: 10,
        };
        let panel = ObjectId {
            heap: SourceHeap::FrontPanel,
            uid: 10,
        };
        facts.diagram_string_values = Some(vec![
            formats::DiagramStringConstant {
                object: Some(diagram),
                label: Some(b"same".to_vec()),
                bytes: b"password=first".to_vec(),
            },
            formats::DiagramStringConstant {
                object: Some(ObjectId { uid: 20, ..diagram }),
                label: Some(b"same".to_vec()),
                bytes: b"password=second".to_vec(),
            },
        ]);
        facts.default_string_values = Some(vec![formats::DefaultStringValue {
            object: Some(panel),
            type_index: 1,
            field_path: vec![0],
            labels: vec![b"same".to_vec()],
            bytes: b"password=default".to_vec(),
        }]);
        facts.call_inputs.insert(
            "system-exec-command-input",
            formats::CallEvidence {
                calls: vec![10, 20],
                incomplete: vec![(10, "unsupported transfer".to_owned())],
            },
        );
        facts.call_inputs.insert(
            "http-control-url",
            formats::CallEvidence {
                calls: vec![10, 20],
                incomplete: vec![(10, "unsupported transfer".to_owned())],
            },
        );
        assert!(suppress_object(
            &mut facts,
            "hardcoded-secret-default",
            diagram
        ));
        assert_eq!(facts.diagram_string_values.as_ref().unwrap().len(), 1);
        assert_eq!(facts.default_string_values.as_ref().unwrap().len(), 1);
        assert_eq!(
            facts.call_inputs["system-exec-command-input"].calls,
            [10, 20]
        );
        assert!(!suppress_object(
            &mut facts,
            "system-exec-command-input",
            panel
        ));
        assert!(suppress_object(
            &mut facts,
            "system-exec-command-input",
            diagram
        ));
        let inputs = &facts.call_inputs["system-exec-command-input"];
        assert_eq!(inputs.calls, [20]);
        assert_eq!(inputs.incomplete, [(10, "unsupported transfer".to_owned())]);
        assert!(suppress_object(&mut facts, "http-control-url", diagram));
        assert_eq!(facts.call_inputs["http-control-url"].calls, [20]);
        assert_eq!(facts.call_inputs["http-control-url"].incomplete.len(), 1);
        assert_eq!(facts.call_inputs["system-exec-command-input"].calls, [20]);
        assert!(suppress_object(
            &mut facts,
            "hardcoded-secret-default",
            panel
        ));
        assert!(facts.default_string_values.as_ref().unwrap().is_empty());
    }

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
