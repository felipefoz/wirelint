//! Synthetic topology cases and regressions against project-owned saved VIs.

use super::*;
use crate::formats::read_diagram_graph;
use std::path::Path;

/// Encodes heap records independently of the parser, including wide UID attributes.
fn node(bytes: &mut Vec<u8>, tag: i32, scope: u8, attrs: &[(i8, i32)], content: &[u8]) {
    let tag = u16::try_from(tag + 31).unwrap();
    let size = if content.is_empty() { 0 } else { 6 };
    bytes.push((size << 5) | (u8::from(!attrs.is_empty()) << 4) | (scope << 2) | (tag >> 8) as u8);
    bytes.push(tag as u8);
    if !attrs.is_empty() {
        bytes.push(u8::try_from(attrs.len()).unwrap());
        for &(key, value) in attrs {
            bytes.push(key as u8);
            if let Ok(value) = i16::try_from(value)
                && value != i16::MIN
            {
                bytes.extend_from_slice(&value.to_be_bytes());
            } else {
                bytes.extend_from_slice(&i16::MIN.to_be_bytes());
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
    if !content.is_empty() {
        bytes.push(u8::try_from(content.len()).unwrap());
        bytes.extend_from_slice(content);
    }
}

fn open(bytes: &mut Vec<u8>, tag: i32, class: i32, uid: i32) {
    node(bytes, tag, 0, &[(-2, class), (-3, uid)], &[]);
}

fn close(bytes: &mut Vec<u8>, tag: i32) {
    node(bytes, tag, 2, &[], &[]);
}

fn field(bytes: &mut Vec<u8>, tag: i32, value: u32) {
    node(bytes, tag, 1, &[], &value.to_be_bytes());
}

fn signal(bytes: &mut Vec<u8>, uid: i32, ends: &[i32]) {
    node(bytes, SIGNAL_LIST, 0, &[], &[]);
    open(bytes, ARRAY_ELEMENT, SIGNAL, uid);
    node(bytes, TERM_LIST, 0, &[], &[]);
    for &end in ends {
        node(bytes, ARRAY_ELEMENT, 1, &[(-3, end)], &[]);
    }
    close(bytes, TERM_LIST);
    field(bytes, STATE, 1);
    close(bytes, ARRAY_ELEMENT);
    close(bytes, SIGNAL_LIST);
}

fn terminal(bytes: &mut Vec<u8>, uid: i32, class: i32, flags: u32) {
    open(bytes, ARRAY_ELEMENT, class, uid);
    field(bytes, OBJ_FLAGS, flags);
    close(bytes, ARRAY_ELEMENT);
}

#[test]
fn reads_fanout_forward_references_and_node_metadata_without_inferring_direction() {
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    signal(&mut bytes, 90_000, &[70_000, 20, 30]);
    node(&mut bytes, super::super::NODE_LIST, 0, &[], &[]);
    open(&mut bytes, ARRAY_ELEMENT, 47, 10);
    field(&mut bytes, PRIM_RES_ID, 1057);
    node(&mut bytes, PARM_INDEX, 1, &[], &[0xff]);
    node(&mut bytes, TERM_LIST, 0, &[], &[]);
    open(&mut bytes, ARRAY_ELEMENT, TERM, 20);
    field(&mut bytes, OBJ_FLAGS, 0x8000);
    open(&mut bytes, DCO, 48, 21);
    field(&mut bytes, PARM_INDEX, 2);
    field(&mut bytes, PARAM_IDX, 4);
    close(&mut bytes, DCO);
    close(&mut bytes, ARRAY_ELEMENT);
    close(&mut bytes, TERM_LIST);
    close(&mut bytes, ARRAY_ELEMENT);
    terminal(&mut bytes, 70_000, FP_TERM, 0x20040);
    terminal(&mut bytes, 30, FP_TERM, 0x28040);
    // A reference to the primitive must not overwrite its definition.
    node(&mut bytes, ARRAY_ELEMENT, 1, &[(-3, 10)], &[]);
    close(&mut bytes, super::super::NODE_LIST);
    close(&mut bytes, -7);
    let graph = parse(&bytes).unwrap();
    assert!(graph.issues.is_empty());
    assert_eq!(graph.signals[&90_000].terminals, [70_000, 20, 30]);
    assert_eq!(graph.signals[&90_000].state, Some(1));
    assert_eq!(graph.objects[&10].primitive_id, Some(1057));
    assert_eq!(graph.objects[&10].primitive_slot, Some(-1));
    assert_eq!(graph.objects[&20].parent, Some(10));
    assert_eq!(graph.containing_diagram(20), Some(3));
    assert_eq!(graph.objects[&20].dco, Some(21));
    assert_eq!(graph.objects[&20].flags, Some(0x8000));
    assert_eq!(graph.objects[&21].primitive_slot, Some(2));
    assert_eq!(graph.objects[&21].call_slot, Some(4));
}

#[test]
fn retains_unresolved_cross_diagram_duplicate_and_shared_endpoints() {
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    terminal(&mut bytes, 10, FP_TERM, 0);
    signal(&mut bytes, 100, &[10, 10, 999, 3, 20]);
    signal(&mut bytes, 101, &[10]);
    open(&mut bytes, ARRAY_ELEMENT, 33, 40);
    node(&mut bytes, 63, 0, &[], &[]);
    open(&mut bytes, ARRAY_ELEMENT, DIAGRAM, 4);
    terminal(&mut bytes, 20, FP_TERM, 0x8000);
    close(&mut bytes, ARRAY_ELEMENT);
    close(&mut bytes, 63);
    close(&mut bytes, ARRAY_ELEMENT);
    close(&mut bytes, -7);
    let graph = parse(&bytes).unwrap();
    assert_eq!(graph.signals[&100].terminals, [10, 10, 999, 3, 20]);
    assert_eq!(graph.containing_diagram(20), Some(4));
    assert_eq!(graph.objects[&4].parent, Some(40));
    assert_eq!(
        graph.issues,
        [
            GraphIssue::DuplicateEndpoint {
                signal: 100,
                terminal: 10
            },
            GraphIssue::UnresolvedTerminal {
                signal: 100,
                terminal: 999
            },
            GraphIssue::NonTerminalEndpoint {
                signal: 100,
                object: 3
            },
            GraphIssue::CrossDiagramEndpoint {
                signal: 100,
                terminal: 20
            },
            GraphIssue::TooFewEndpoints { signal: 101 },
            GraphIssue::SharedTerminal {
                terminal: 10,
                first: 100,
                second: 101
            },
        ]
    );
}

#[test]
fn rejects_ambiguous_or_malformed_identities_and_fields() {
    for kind in 0..7 {
        let mut bytes = Vec::new();
        open(&mut bytes, -7, DIAGRAM, 3);
        match kind {
            0 => {
                terminal(&mut bytes, 10, TERM, 0);
                terminal(&mut bytes, 10, TERM, 0);
            }
            1 => node(&mut bytes, ARRAY_ELEMENT, 1, &[(-2, TERM)], &[]),
            2 => node(
                &mut bytes,
                ARRAY_ELEMENT,
                1,
                &[(-2, TERM), (-3, 10), (-3, 11)],
                &[],
            ),
            3 => {
                open(&mut bytes, ARRAY_ELEMENT, TERM, 10);
                field(&mut bytes, OBJ_FLAGS, 0);
                field(&mut bytes, OBJ_FLAGS, 1);
                close(&mut bytes, ARRAY_ELEMENT);
            }
            4 => {
                node(&mut bytes, SIGNAL_LIST, 0, &[], &[]);
                open(&mut bytes, ARRAY_ELEMENT, SIGNAL, 100);
                close(&mut bytes, ARRAY_ELEMENT);
                close(&mut bytes, SIGNAL_LIST);
            }
            5 => {
                node(&mut bytes, SIGNAL_LIST, 0, &[], &[]);
                open(&mut bytes, ARRAY_ELEMENT, SIGNAL, 100);
                node(&mut bytes, TERM_LIST, 0, &[], &[]);
                node(&mut bytes, ARRAY_ELEMENT, 1, &[], &[]);
                close(&mut bytes, TERM_LIST);
                close(&mut bytes, ARRAY_ELEMENT);
                close(&mut bytes, SIGNAL_LIST);
            }
            6 => {
                open(&mut bytes, ARRAY_ELEMENT, TERM, 10);
                node(&mut bytes, OBJ_FLAGS, 1, &[], &[0; 5]);
                close(&mut bytes, ARRAY_ELEMENT);
            }
            _ => unreachable!(),
        }
        close(&mut bytes, -7);
        assert_eq!(
            parse(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "case {kind}"
        );
    }
    assert!(parse(&[]).is_err());
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    assert!(parse(&bytes).is_err());
}

#[test]
fn bounds_depth_and_collection_sizes() {
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    for _ in 0..=MAX_DEPTH {
        node(&mut bytes, 63, 0, &[], &[]);
    }
    assert!(
        parse(&bytes)
            .unwrap_err()
            .to_string()
            .contains("nesting limit")
    );
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    for uid in 4..4 + MAX_OBJECTS as i32 {
        terminal(&mut bytes, uid, TERM, 0);
    }
    close(&mut bytes, -7);
    assert!(
        parse(&bytes)
            .unwrap_err()
            .to_string()
            .contains("object limit")
    );
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    signal(&mut bytes, 100, &vec![10; MAX_ENDPOINTS + 1]);
    close(&mut bytes, -7);
    assert!(
        parse(&bytes)
            .unwrap_err()
            .to_string()
            .contains("endpoint limit")
    );
}

#[test]
fn reads_saved_control_wire_and_retains_broken_wire_state() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    let credentials = std::fs::read(
        root.join("sast")
            .join("hardcoded-secret-default")
            .join("credentials-separated.vi"),
    )
    .unwrap();
    let graph = read_diagram_graph(&credentials).unwrap().unwrap();
    assert!(graph.issues.is_empty());
    assert_eq!(graph.signals[&20092].terminals, [20067, 20090]);
    assert_eq!(graph.objects[&20067].class, FP_TERM);
    assert_eq!(graph.objects[&20067].dco, Some(20058));
    assert_eq!(graph.objects[&20090].dco, Some(20081));
    assert_eq!(graph.objects[&20067].flags.unwrap() & 0x8000, 0);
    assert_ne!(graph.objects[&20090].flags.unwrap() & 0x8000, 0);
    let broken = std::fs::read(
        root.join("quality")
            .join("debugging-status")
            .join("broken-wire.vi"),
    )
    .unwrap();
    let graph = read_diagram_graph(&broken).unwrap().unwrap();
    assert!(graph.issues.is_empty());
    assert_eq!(graph.signals[&64].terminals, [51, 85]);
    assert_eq!(graph.signals[&64].state, Some(289));
    assert_eq!(graph.objects[&51].dco, Some(43));
    assert_eq!(graph.objects[&43].class, super::super::BD_CONST_DCO);
}

#[test]
fn distinguishes_missing_source_from_empty_diagram_and_bad_resource() {
    let no_source = crate::test_support::vi_with_library_link("Owner.lvlib");
    assert!(read_diagram_graph(&no_source).unwrap().is_none());
    assert!(read_diagram_graph(b"not an RSRC").is_err());
    let mut bytes = Vec::new();
    open(&mut bytes, -7, DIAGRAM, 3);
    close(&mut bytes, -7);
    let graph = parse(&bytes).unwrap();
    assert!(graph.signals.is_empty());
    assert_eq!(graph.objects.len(), 1);
}

#[test]
fn rejects_unsupported_duplicate_and_corrupt_diagram_resources() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sast")
        .join("hardcoded-secret-default")
        .join("credentials-separated.vi");
    let original = std::fs::read(path).unwrap();
    let word = |bytes: &[u8], at: usize| {
        u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
    };
    let info = word(&original, 16);
    let table = info + word(&original, info + 44);
    let count = word(&original, table) + 1;
    let entries = (0..count).map(|i| table + 4 + 12 * i).collect::<Vec<_>>();
    let diagram = *entries
        .iter()
        .find(|&&at| &original[at..at + 4] == b"BDHb")
        .unwrap();
    for kind in 0..5 {
        let mut bytes = original.clone();
        match kind {
            0 => bytes[diagram..diagram + 4].copy_from_slice(b"BDHc"),
            1 => {
                let other = *entries.iter().find(|&&at| at != diagram).unwrap();
                bytes.copy_within(diagram..diagram + 12, other);
            }
            2 => bytes[diagram + 4..diagram + 8].copy_from_slice(&1u32.to_be_bytes()),
            3 => {
                let section = table + word(&bytes, diagram + 8);
                let record = word(&bytes, 24) + word(&bytes, section + 12);
                bytes[record + 8] ^= 0xff;
            }
            4 => {
                bytes[8..12].copy_from_slice(b"LVCC");
                bytes[info + 8..info + 12].copy_from_slice(b"LVCC");
            }
            _ => unreachable!(),
        }
        assert_eq!(
            read_diagram_graph(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "case {kind}"
        );
    }
}

#[test]
fn reads_existing_vi_fixture_corpus_without_requiring_optional_value_readers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    for path in crate::scan::discover_files(&root, &[]).unwrap() {
        if path.extension().is_none_or(|ext| ext != "vi") {
            continue;
        }
        let bytes = std::fs::read(root.join(&path)).unwrap();
        read_diagram_graph(&bytes).unwrap_or_else(|error| {
            panic!("graph extraction failed for {}: {error}", path.display())
        });
    }
}
