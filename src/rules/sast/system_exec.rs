//! Review warning for control-influenced command input to NI System Exec.vi.
//!
//! Connectivity and supported local transfers are resolved by the format layer.
//! Findings make no claim about attacker access, shell use or exploitability.

use crate::config::RuleConfig;
use crate::formats::dataflow::{Influence, Trace};
use crate::formats::{CallEvidence, CallLink, DiagramGraph, FileFacts};
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

    fn supports_call_suppression(&self) -> bool {
        true
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        let count = facts.call_inputs.get(self.id())?.calls.len();
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

const COMMAND_SLOT: i32 = 11;

/// Classifies each identified call independently, preserving incomplete paths.
fn analyze(graph: Option<&DiagramGraph>, calls: &[i32]) -> CallEvidence {
    let mut result = CallEvidence::default();
    let Some(graph) = graph else {
        result.incomplete = calls
            .iter()
            .map(|&uid| (uid, "saved block-diagram source is missing".to_owned()))
            .collect();
        return result;
    };
    if !graph.issues.is_empty() {
        result.incomplete = calls
            .iter()
            .map(|&uid| {
                (
                    uid,
                    "saved diagram has unresolved or ambiguous connections".to_owned(),
                )
            })
            .collect();
        return result;
    }
    let mut trace = Trace::new(graph);
    for &uid in calls {
        match trace.call_input(uid, COMMAND_SLOT) {
            Ok(Some(Influence::Control)) => result.calls.push(uid),
            Ok(_) => {}
            Err(reason) => result.incomplete.push((uid, reason.to_owned())),
        }
    }
    result
}

/// Matches the NI platform-library identity, not an arbitrary matching basename.
fn is_system_exec(link: &CallLink) -> bool {
    link.name.len() == 1
        && link.name[0].eq_ignore_ascii_case(b"System Exec.vi")
        && link.path.len() >= 4
        && link.path[link.path.len() - 3..]
            .iter()
            .zip(["Platform", "system.llb", "System Exec.vi"])
            .all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
        && link.path[..link.path.len() - 3]
            .iter()
            .any(|part| part.eq_ignore_ascii_case("<vilib>") || part.eq_ignore_ascii_case("vi.lib"))
}

/// Whether any saved static call targets the NI System Exec VI.
pub(crate) fn has_calls(links: &[CallLink]) -> bool {
    links
        .iter()
        .any(|link| !link.nodes.is_empty() && is_system_exec(link))
}

/// Classifies identified call nodes in an already extracted diagram.
pub(crate) fn analyze_links(links: &[CallLink], graph: Option<&DiagramGraph>) -> CallEvidence {
    let calls = links
        .iter()
        .filter(|link| is_system_exec(link))
        .flat_map(|link| link.nodes.iter().copied())
        .collect::<Vec<_>>();
    analyze(graph, &calls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::dataflow::{CONCAT, FP_TERM, IUSE, TERM, WIRED_INPUT};
    use crate::formats::{GraphIssue, GraphObject};
    use std::path::Path;

    fn caller(name: &str) -> (DiagramGraph, i32) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("sast")
            .join("system-exec-command-input")
            .join(name);
        let bytes = std::fs::read(path).unwrap();
        let graph = crate::formats::read_diagram_graph(&bytes).unwrap().unwrap();
        let uid = graph
            .objects
            .iter()
            .find(|(_, object)| object.class == IUSE)
            .unwrap()
            .0;
        let uid = *uid;
        (graph, uid)
    }

    #[test]
    fn ignores_custom_vis_with_the_same_basename() {
        let mut link = CallLink {
            name: vec![b"System Exec.vi".to_vec()],
            path: vec!["".into(), "System Exec.vi".into()],
            nodes: vec![100],
        };
        assert!(!is_system_exec(&link));
        link.path = ["<vilib>", "Platform", "system.llb", "System Exec.vi"]
            .map(str::to_owned)
            .to_vec();
        assert!(is_system_exec(&link));
        link.name.insert(0, b"Custom.lvlib".to_vec());
        assert!(!is_system_exec(&link));
    }

    #[test]
    fn traces_fanout_without_using_endpoint_order() {
        let (mut graph, call) = caller("control-command.vi");
        let command = graph
            .objects
            .iter()
            .find_map(|(&uid, object)| {
                (object.parent == Some(call)
                    && object.class == TERM
                    && object
                        .dco
                        .is_some_and(|dco| graph.objects[&dco].call_slot == Some(COMMAND_SLOT)))
                .then_some(uid)
            })
            .unwrap();
        let signal = graph
            .signals
            .values_mut()
            .find(|signal| signal.terminals.contains(&command))
            .unwrap();
        graph.objects.insert(
            90_000,
            GraphObject {
                class: FP_TERM,
                parent: Some(signal.diagram),
                flags: Some(WIRED_INPUT),
                dco: None,
                primitive_id: None,
                call_slot: None,
                primitive_slot: None,
                constant_value: None,
                constant_display: None,
                ambiguous_constant_display: false,
            },
        );
        signal.terminals.push(90_000);
        for signal in graph.signals.values_mut() {
            signal.terminals.reverse();
        }
        let result = analyze(Some(&graph), &[call]);
        assert_eq!(result.calls, [call]);
        assert!(result.incomplete.is_empty());
    }

    #[test]
    fn keeps_unknown_transfers_and_topology_separate_from_findings() {
        let (mut graph, call) = caller("concatenate-command.vi");
        let concat = graph
            .objects
            .values_mut()
            .find(|object| object.class == CONCAT)
            .unwrap();
        concat.class = 47;
        let result = analyze(Some(&graph), &[call]);
        assert!(result.calls.is_empty());
        assert_eq!(result.incomplete.len(), 1);
        assert!(result.incomplete[0].1.contains("unsupported operation"));

        graph.issues.push(GraphIssue::UnresolvedTerminal {
            signal: 1,
            terminal: 99_999,
        });
        let result = analyze(Some(&graph), &[call]);
        assert!(result.calls.is_empty());
        assert!(result.incomplete[0].1.contains("unresolved"));
        let result = analyze(None, &[call]);
        assert!(result.incomplete[0].1.contains("source is missing"));
    }

    #[test]
    fn detects_cycles_without_assuming_they_are_safe() {
        let (mut graph, call) = caller("concatenate-command.vi");
        let (&concat, _) = graph
            .objects
            .iter()
            .find(|(_, object)| object.class == CONCAT)
            .unwrap();
        let (&input_signal, signal) = graph
            .signals
            .iter()
            .find(|(_, signal)| {
                signal
                    .terminals
                    .iter()
                    .any(|uid| graph.objects[uid].class == FP_TERM)
                    && signal
                        .terminals
                        .iter()
                        .any(|uid| graph.objects[uid].parent == Some(concat))
            })
            .unwrap();
        let input = *signal
            .terminals
            .iter()
            .find(|uid| graph.objects[uid].parent == Some(concat))
            .unwrap();
        graph.signals.remove(&input_signal);
        let output_signal = graph
            .signals
            .values_mut()
            .find(|signal| {
                signal.terminals.iter().any(|uid| {
                    graph.objects[uid].parent == Some(concat)
                        && graph.objects[uid].flags.unwrap_or(0) & WIRED_INPUT == 0
                })
            })
            .unwrap();
        output_signal.terminals.push(input);
        let result = analyze(Some(&graph), &[call]);
        assert!(result.calls.is_empty());
        assert!(result.incomplete[0].1.contains("cyclic"));
    }

    #[test]
    fn retains_proven_influence_when_another_call_is_incomplete() {
        let (graph, call) = caller("control-command.vi");
        let result = analyze(Some(&graph), &[call, 99_999]);
        assert_eq!(result.calls, [call]);
        assert_eq!(result.incomplete.len(), 1);
        assert_eq!(result.incomplete[0].0, 99_999);
    }
}
