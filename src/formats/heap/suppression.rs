//! Saved comment-arrow resolution, independent of wire geometry and dataflow.
//!
//! References resolve only after every definition is read. An unresolved arrow
//! never becomes a file-wide exception; object identities include their heap.

use super::{
    ARRAY_ELEMENT, BD_CONST_DCO, DIAGRAM, FP_DCO, FP_TERM, LABEL, NODE_LIST, PART_ID, Scope, TEXT,
    TEXT_HAIR, TEXT_RECORD, Z_PLANE_LIST, invalid, walk_heap,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

const ATTACHMENT_CLASS: i32 = 375;
const ATTACHMENT: i32 = 619;
const ATTACHED_OBJECT: i32 = 618;
const PANE: i32 = 284;
const DCO: i32 = 48;
const TERM: i32 = 21;
const MAX_OBJECTS: usize = 100_000;

/// UID namespace of a saved source object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SourceHeap {
    Diagram,
    FrontPanel,
}

impl SourceHeap {
    /// Native resource name, also used in diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Diagram => "BDHb",
            Self::FrontPanel => "FPHb",
        }
    }
}

/// A source object's identity; names and coordinates are not identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ObjectId {
    pub heap: SourceHeap,
    pub uid: i32,
}

/// Exact directive text with a resolved arrow target, or a file-wide scope.
#[derive(Debug)]
pub struct Directive {
    pub text: Vec<u8>,
    pub object: Option<ObjectId>,
}

#[derive(Default)]
struct Definition {
    class: i32,
    parent: Option<i32>,
    diagram: Option<i32>,
    attached: Option<i32>,
    dco: Option<i32>,
}

struct Label {
    depth: usize,
    diagram: Option<i32>,
    text: Option<Vec<u8>>,
    attachment: Option<i32>,
    owned: bool,
}

/// Reads structurally free labels and validates both ends of each directive arrow.
///
/// Duplicate definitions, missing references, cross-diagram links and excessive
/// nesting or object counts are errors. Ordinary non-directive comments are inert.
pub(in crate::formats) fn parse(bytes: &[u8], heap: SourceHeap) -> io::Result<Vec<Directive>> {
    let mut definitions = BTreeMap::new();
    let mut duplicate = false;
    let mut labels = Vec::new();
    let mut open: Vec<Label> = Vec::new();
    walk_heap(bytes, |parents, node, scope, content| {
        if parents.len() >= 256 && scope == Scope::Open {
            return Err(invalid("bookmark heap exceeds the nesting limit"));
        }
        let diagram = parents
            .iter()
            .rev()
            .find(|p| p.class == Some(DIAGRAM))
            .and_then(|p| p.uid);
        if scope != Scope::Close {
            if let (Some(class), Some(uid)) = (node.class, node.uid) {
                if definitions.len() >= MAX_OBJECTS {
                    return Err(invalid("bookmark heap exceeds the object limit"));
                }
                duplicate |= definitions
                    .insert(
                        uid,
                        Definition {
                            class,
                            parent: parents
                                .iter()
                                .rev()
                                .find(|p| p.class.is_some())
                                .and_then(|p| p.uid),
                            diagram,
                            ..Definition::default()
                        },
                    )
                    .is_some();
            }
            if let Some(parent) = parents.last().filter(|parent| parent.class.is_some())
                && let Some(definition) = parent.uid.and_then(|uid| definitions.get_mut(&uid))
            {
                let reference = match (definition.class, node.tag) {
                    (ATTACHMENT_CLASS, ATTACHED_OBJECT) => Some(&mut definition.attached),
                    (FP_TERM, DCO) => Some(&mut definition.dco),
                    _ => None,
                };
                if let Some(reference) = reference {
                    let uid = node
                        .uid
                        .ok_or_else(|| invalid("bookmark object reference has no UID"))?;
                    if reference.replace(uid).is_some() {
                        return Err(invalid("duplicate bookmark object reference"));
                    }
                }
            }
        }
        let free_label = node.tag == ARRAY_ELEMENT
            && node.class == Some(LABEL)
            && parents.len() >= 2
            && matches!(parents[parents.len() - 1].tag, NODE_LIST | Z_PLANE_LIST)
            && match heap {
                SourceHeap::Diagram => parents[parents.len() - 2].class == Some(DIAGRAM),
                SourceHeap::FrontPanel => parents[parents.len() - 2].class == Some(PANE),
            };
        if free_label && scope == Scope::Open {
            open.push(Label {
                depth: parents.len(),
                diagram,
                text: None,
                attachment: None,
                owned: false,
            });
        } else if free_label && scope == Scope::Close {
            labels.push(
                open.pop()
                    .ok_or_else(|| invalid("unmatched bookmark label"))?,
            );
        } else if scope != Scope::Close
            && let Some(label) = open.last_mut()
        {
            let depth = parents.len() - label.depth;
            if depth == 1 && node.tag == PART_ID {
                label.owned = true;
            } else if depth == 1 && node.tag == ATTACHMENT {
                let uid = node
                    .uid
                    .ok_or_else(|| invalid("bookmark attachment reference has no UID"))?;
                if label.attachment.replace(uid).is_some() {
                    return Err(invalid("duplicate bookmark attachment reference"));
                }
            } else if depth == 2
                && node.tag == TEXT
                && parents
                    .last()
                    .is_some_and(|p| p.tag == TEXT_RECORD && p.class == Some(TEXT_HAIR))
                && label.text.replace(content.to_vec()).is_some()
            {
                return Err(invalid("duplicate bookmark label text"));
            }
        }
        Ok(())
    })?;
    let mut constant_terms = BTreeMap::new();
    for (&uid, definition) in &definitions {
        if definition.class == BD_CONST_DCO
            && let Some(parent) = definition.parent
        {
            constant_terms
                .entry(parent)
                .and_modify(|value| *value = None)
                .or_insert(Some(uid));
        }
    }
    let mut directives = Vec::new();
    for label in labels {
        let Some(text) = label
            .text
            .filter(|text| !label.owned && crate::formats::directive_rule(text).is_some())
        else {
            continue;
        };
        if duplicate {
            return Err(invalid("duplicate object UID in bookmark heap"));
        }
        let target = match label.attachment {
            None => None,
            Some(uid) => {
                let attachment = definitions
                    .get(&uid)
                    .filter(|d| d.class == ATTACHMENT_CLASS)
                    .ok_or_else(|| invalid("unresolved bookmark attachment"))?;
                if attachment.diagram != label.diagram {
                    return Err(invalid("cross-diagram bookmark attachment"));
                }
                attachment
                    .attached
                    .map(|uid| {
                        if heap == SourceHeap::Diagram && label.diagram.is_none() {
                            return Err(invalid("bookmark arrow owning diagram has no UID"));
                        }
                        let target = definitions
                            .get(&uid)
                            .ok_or_else(|| invalid("unresolved bookmark arrow target"))?;
                        if target.diagram != label.diagram {
                            return Err(invalid("cross-diagram bookmark arrow target"));
                        }
                        // Constant terminals contain the value DCO; display objects
                        // are its children. Both arrow forms identify that same value.
                        let uid = if let Some(parent) = target.parent
                            && definitions
                                .get(&parent)
                                .is_some_and(|d| matches!(d.class, BD_CONST_DCO | FP_DCO))
                        {
                            parent
                        } else if target.class == TERM
                            && let Some(child) = constant_terms.get(&uid)
                        {
                            child.ok_or_else(|| invalid("ambiguous bookmark constant terminal"))?
                        } else {
                            uid
                        };
                        if heap == SourceHeap::Diagram && target.class == FP_TERM {
                            let uid = target.dco.ok_or_else(|| {
                                invalid("bookmark terminal has no front-panel DCO reference")
                            })?;
                            Ok(ObjectId {
                                heap: SourceHeap::FrontPanel,
                                uid,
                            })
                        } else {
                            Ok(ObjectId { heap, uid })
                        }
                    })
                    .transpose()?
            }
        };
        if heap == SourceHeap::Diagram || target.is_some() {
            directives.push(Directive {
                text,
                object: target,
            });
        }
    }
    Ok(directives)
}

/// Checks cross-heap terminal references against actual front-panel controls.
pub(in crate::formats) fn validate_panel_targets(
    bytes: &[u8],
    uids: &BTreeSet<i32>,
) -> io::Result<()> {
    let mut counts: BTreeMap<_, usize> = uids.iter().map(|&uid| (uid, 0)).collect();
    walk_heap(bytes, |_, node, scope, _| {
        if scope != Scope::Close
            && node.class == Some(FP_DCO)
            && let Some(count) = node.uid.and_then(|uid| counts.get_mut(&uid))
        {
            *count += 1;
        }
        Ok(())
    })?;
    if counts.values().any(|count| *count != 1) {
        return Err(invalid(
            "unresolved or ambiguous front-panel bookmark target",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::node_with_uid as node;
    use super::*;

    fn label(bytes: &mut Vec<u8>, attachment: Option<i16>, owned: bool) {
        node(bytes, ARRAY_ELEMENT, 0, Some(LABEL as i16), Some(90), &[]);
        node(bytes, TEXT_RECORD, 0, Some(TEXT_HAIR as i16), None, &[]);
        node(bytes, TEXT, 1, None, None, b"#wirelint-ignore path-usage");
        node(bytes, TEXT_RECORD, 2, None, None, &[]);
        if owned {
            node(bytes, PART_ID, 1, None, None, &[16]);
        }
        if let Some(uid) = attachment {
            node(bytes, ATTACHMENT, 1, None, Some(uid), &[]);
        }
        node(bytes, ARRAY_ELEMENT, 2, None, None, &[]);
    }

    fn attachment(bytes: &mut Vec<u8>, target: Option<i16>) {
        node(
            bytes,
            ARRAY_ELEMENT,
            0,
            Some(ATTACHMENT_CLASS as i16),
            Some(92),
            &[],
        );
        if let Some(uid) = target {
            node(bytes, ATTACHED_OBJECT, 1, None, Some(uid), &[]);
        }
        node(bytes, ARRAY_ELEMENT, 2, None, None, &[]);
    }

    fn heap(target: Option<i16>, owned: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        node(&mut bytes, -7, 0, Some(DIAGRAM as i16), Some(1), &[]);
        node(&mut bytes, Z_PLANE_LIST, 0, None, None, &[]);
        label(&mut bytes, Some(92), owned);
        attachment(&mut bytes, target);
        node(
            &mut bytes,
            ARRAY_ELEMENT,
            0,
            Some(BD_CONST_DCO as i16),
            Some(10),
            &[],
        );
        node(&mut bytes, super::super::DDO, 0, Some(91), Some(11), &[]);
        node(&mut bytes, super::super::DDO, 2, None, None, &[]);
        node(&mut bytes, ARRAY_ELEMENT, 2, None, None, &[]);
        node(&mut bytes, Z_PLANE_LIST, 2, None, None, &[]);
        node(&mut bytes, -7, 2, None, None, &[]);
        bytes
    }

    #[test]
    fn resolves_forward_arrows_to_the_value_owner_not_the_display_object() {
        for target in [10, 11] {
            let directives = parse(&heap(Some(target), false), SourceHeap::Diagram).unwrap();
            assert_eq!(directives.len(), 1);
            assert_eq!(
                directives[0].object,
                Some(ObjectId {
                    heap: SourceHeap::Diagram,
                    uid: 10
                })
            );
        }

        assert!(
            parse(&heap(Some(10), true), SourceHeap::Diagram)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn constant_terminal_arrows_resolve_to_the_child_value_dco() {
        let mut bytes = heap(Some(30), false);
        bytes.truncate(bytes.len() - 2);
        node(
            &mut bytes,
            ARRAY_ELEMENT,
            0,
            Some(TERM as i16),
            Some(30),
            &[],
        );
        node(&mut bytes, DCO, 0, Some(BD_CONST_DCO as i16), Some(31), &[]);
        node(&mut bytes, DCO, 2, None, None, &[]);
        node(&mut bytes, ARRAY_ELEMENT, 2, None, None, &[]);
        node(&mut bytes, -7, 2, None, None, &[]);
        assert_eq!(
            parse(&bytes, SourceHeap::Diagram).unwrap()[0].object,
            Some(ObjectId {
                heap: SourceHeap::Diagram,
                uid: 31
            })
        );
    }

    #[test]
    fn floating_attachments_remain_global_but_dangling_arrows_never_do() {
        assert_eq!(
            parse(&heap(None, false), SourceHeap::Diagram).unwrap()[0].object,
            None
        );
        assert!(
            parse(&heap(Some(99), false), SourceHeap::Diagram)
                .unwrap_err()
                .to_string()
                .contains("arrow target")
        );
        let mut bytes = Vec::new();
        node(&mut bytes, -7, 0, Some(DIAGRAM as i16), Some(1), &[]);
        node(&mut bytes, Z_PLANE_LIST, 0, None, None, &[]);
        label(&mut bytes, Some(92), false);
        node(&mut bytes, Z_PLANE_LIST, 2, None, None, &[]);
        node(&mut bytes, -7, 2, None, None, &[]);
        assert!(
            parse(&bytes, SourceHeap::Diagram)
                .unwrap_err()
                .to_string()
                .contains("attachment")
        );
    }

    #[test]
    fn rejects_duplicate_definitions_and_cross_diagram_targets() {
        let mut duplicate = heap(Some(10), false);
        node(&mut duplicate, ARRAY_ELEMENT, 1, Some(19), Some(10), &[]);
        assert!(
            parse(&duplicate, SourceHeap::Diagram)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        let mut cross = heap(Some(99), false);
        node(&mut cross, -7, 0, Some(DIAGRAM as i16), Some(2), &[]);
        node(&mut cross, ARRAY_ELEMENT, 1, Some(19), Some(99), &[]);
        node(&mut cross, -7, 2, None, None, &[]);
        assert!(
            parse(&cross, SourceHeap::Diagram)
                .unwrap_err()
                .to_string()
                .contains("cross-diagram")
        );
    }

    #[test]
    fn front_panel_labels_require_an_arrow_and_keep_their_own_namespace() {
        for target in [None, Some(10)] {
            let mut bytes = Vec::new();
            node(&mut bytes, -7, 0, Some(PANE as i16), Some(1), &[]);
            node(&mut bytes, Z_PLANE_LIST, 0, None, None, &[]);
            label(&mut bytes, Some(92), false);
            attachment(&mut bytes, target);
            node(
                &mut bytes,
                ARRAY_ELEMENT,
                1,
                Some(FP_DCO as i16),
                Some(10),
                &[],
            );
            node(&mut bytes, Z_PLANE_LIST, 2, None, None, &[]);
            node(&mut bytes, -7, 2, None, None, &[]);
            let directives = parse(&bytes, SourceHeap::FrontPanel).unwrap();
            if target.is_some() {
                assert_eq!(
                    directives[0].object,
                    Some(ObjectId {
                        heap: SourceHeap::FrontPanel,
                        uid: 10
                    })
                );
                validate_panel_targets(&bytes, &BTreeSet::from([10])).unwrap();
                assert!(validate_panel_targets(&bytes, &BTreeSet::from([11])).is_err());
            } else {
                assert!(directives.is_empty());
            }
        }
    }

    #[test]
    fn diagram_terminal_arrows_resolve_to_front_panel_control_defaults() {
        let mut bytes = heap(Some(30), false);
        // Add the forward-referenced terminal to the same diagram.
        bytes.truncate(bytes.len() - 2);
        node(
            &mut bytes,
            ARRAY_ELEMENT,
            0,
            Some(FP_TERM as i16),
            Some(30),
            &[],
        );
        node(&mut bytes, DCO, 1, None, Some(40), &[]);
        node(&mut bytes, ARRAY_ELEMENT, 2, None, None, &[]);
        node(&mut bytes, -7, 2, None, None, &[]);
        assert_eq!(
            parse(&bytes, SourceHeap::Diagram).unwrap()[0].object,
            Some(ObjectId {
                heap: SourceHeap::FrontPanel,
                uid: 40
            })
        );
    }
}
