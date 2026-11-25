//! Saved-call regressions and explicit unsupported-topology cases.

use super::*;
use crate::formats::heap::graph::GraphIssue;
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
        },
    );
    signal.terminals.push(90_000);
    for signal in graph.signals.values_mut() {
        signal.terminals.reverse();
    }
    let result = analyze(Some(&graph), &[call]);
    assert_eq!(result.influenced_calls, [call]);
    assert!(result.incomplete_calls.is_empty());
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
    assert!(result.influenced_calls.is_empty());
    assert_eq!(result.incomplete_calls.len(), 1);
    assert!(
        result.incomplete_calls[0]
            .1
            .contains("unsupported operation")
    );

    graph.issues.push(GraphIssue::UnresolvedTerminal {
        signal: 1,
        terminal: 99_999,
    });
    let result = analyze(Some(&graph), &[call]);
    assert!(result.influenced_calls.is_empty());
    assert!(result.incomplete_calls[0].1.contains("unresolved"));
    let result = analyze(None, &[call]);
    assert!(result.incomplete_calls[0].1.contains("source is missing"));
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
    assert!(result.influenced_calls.is_empty());
    assert!(result.incomplete_calls[0].1.contains("cyclic"));
}

#[test]
fn retains_proven_influence_when_another_call_is_incomplete() {
    let (graph, call) = caller("control-command.vi");
    let result = analyze(Some(&graph), &[call, 99_999]);
    assert_eq!(result.influenced_calls, [call]);
    assert_eq!(result.incomplete_calls.len(), 1);
    assert_eq!(result.incomplete_calls[0].0, 99_999);
}
