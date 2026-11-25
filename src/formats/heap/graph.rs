//! Bounded structural graph of a version-b block-diagram heap.
//!
//! Definitions are keyed by saved UIDs; classless references never replace
//! definitions. Signals retain all ends and their saved state. Structural
//! issues are explicit: this graph does not establish execution, terminal
//! direction, transfer functions, or trust.

use super::{ARRAY_ELEMENT, DIAGRAM, FP_TERM, OBJ_FLAGS, Scope, invalid, object_flags, walk_heap};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

const TERM: i32 = 21;
const SIGNAL: i32 = 23;
const DCO: i32 = 48;
const PARAM_IDX: i32 = 189;
const PARM_INDEX: i32 = 191;
const PRIM_RES_ID: i32 = 203;
const SIGNAL_LIST: i32 = 233;
const STATE: i32 = 246;
const TERM_LIST: i32 = 268;
const MAX_OBJECTS: usize = 100_000;
const MAX_ENDPOINTS: usize = 100_000;
const MAX_DEPTH: usize = 256;

/// Saved object definitions and wire nets, with unresolved topology kept visible.
#[derive(Debug)]
pub struct DiagramGraph {
    pub objects: BTreeMap<i32, GraphObject>,
    pub signals: BTreeMap<i32, Signal>,
    pub issues: Vec<GraphIssue>,
}

/// One heap object; numeric identities and flags have no inferred semantics.
#[derive(Debug)]
pub struct GraphObject {
    pub class: i32,
    pub parent: Option<i32>,
    pub flags: Option<u32>,
    pub dco: Option<i32>,
    pub primitive_id: Option<i32>,
    pub call_slot: Option<i32>,
    pub primitive_slot: Option<i32>,
}

/// A saved signal is a net with any number of endpoints, not a pairwise edge.
#[derive(Debug)]
pub struct Signal {
    pub diagram: i32,
    pub terminals: Vec<i32>,
    pub state: Option<i32>,
}

/// Evidence that prevents interpreting a saved net as fully resolved topology.
#[derive(Debug, Eq, PartialEq)]
pub enum GraphIssue {
    TooFewEndpoints {
        signal: i32,
    },
    UnresolvedTerminal {
        signal: i32,
        terminal: i32,
    },
    NonTerminalEndpoint {
        signal: i32,
        object: i32,
    },
    CrossDiagramEndpoint {
        signal: i32,
        terminal: i32,
    },
    DuplicateEndpoint {
        signal: i32,
        terminal: i32,
    },
    SharedTerminal {
        terminal: i32,
        first: i32,
        second: i32,
    },
}

/// Parses a decompressed heap and validates references after all definitions.
///
/// Malformed identities, ambiguous fields, excessive size/depth and invalid
/// heap nesting return `InvalidData`. Unresolved signal endpoints are retained
/// with issues rather than dropped or interpreted as safe.
pub(super) fn parse(bytes: &[u8]) -> io::Result<DiagramGraph> {
    let mut graph = DiagramGraph {
        objects: BTreeMap::new(),
        signals: BTreeMap::new(),
        issues: Vec::new(),
    };
    let mut term_lists = BTreeSet::new();
    let mut endpoint_count = 0;
    let mut root_diagrams = 0;
    walk_heap(bytes, |stack, node, scope, content| {
        if stack.len() > MAX_DEPTH || (scope == Scope::Open && stack.len() == MAX_DEPTH) {
            return Err(invalid("diagram graph exceeds the nesting limit"));
        }
        if scope == Scope::Close {
            return Ok(());
        }
        if let Some(class) = node.class {
            if matches!(class, DIAGRAM | TERM | FP_TERM | SIGNAL) && node.uid.is_none() {
                return Err(invalid("diagram graph object is missing its UID"));
            }
            if let Some(uid) = node.uid {
                if graph.objects.len() == MAX_OBJECTS {
                    return Err(invalid("diagram graph exceeds the object limit"));
                }
                let enclosing_diagram = stack
                    .iter()
                    .rev()
                    .find(|p| p.class == Some(DIAGRAM))
                    .and_then(|p| p.uid);
                if class == DIAGRAM && enclosing_diagram.is_none() {
                    root_diagrams += 1;
                }
                let object = GraphObject {
                    class,
                    parent: stack
                        .iter()
                        .rev()
                        .find(|p| p.class.is_some() && p.uid.is_some())
                        .and_then(|p| p.uid),
                    flags: None,
                    dco: None,
                    primitive_id: None,
                    call_slot: None,
                    primitive_slot: None,
                };
                if graph.objects.insert(uid, object).is_some() {
                    return Err(invalid("duplicate diagram graph object UID"));
                }
                if class == SIGNAL {
                    if stack.last().is_none_or(|p| p.tag != SIGNAL_LIST) {
                        return Err(invalid("diagram signal is outside its signal list"));
                    }
                    graph.signals.insert(
                        uid,
                        Signal {
                            diagram: enclosing_diagram
                                .ok_or_else(|| invalid("signal has no owning diagram"))?,
                            terminals: Vec::new(),
                            state: None,
                        },
                    );
                }
            }
        }
        if let Some(parent) = stack.last().filter(|p| p.class.is_some())
            && let Some(uid) = parent.uid
            && let Some(object) = graph.objects.get_mut(&uid)
        {
            if node.tag == DCO {
                set_once(
                    &mut object.dco,
                    node.uid
                        .ok_or_else(|| invalid("DCO reference is missing its UID"))?,
                )?;
            }
            if scope == Scope::Leaf {
                if node.tag == OBJ_FLAGS {
                    set_once(&mut object.flags, object_flags(content)?)?;
                }
                let field = match node.tag {
                    PRIM_RES_ID => Some(&mut object.primitive_id),
                    PARAM_IDX => Some(&mut object.call_slot),
                    PARM_INDEX => Some(&mut object.primitive_slot),
                    _ => None,
                };
                if let Some(field) = field {
                    set_once(field, integer(content)?)?;
                }
                if parent.class == Some(SIGNAL) && node.tag == STATE {
                    set_once(
                        &mut graph.signals.get_mut(&uid).unwrap().state,
                        integer(content)?,
                    )?;
                }
            }
            if parent.class == Some(SIGNAL) && node.tag == TERM_LIST && !term_lists.insert(uid) {
                return Err(invalid("duplicate signal terminal list"));
            }
        }
        if node.tag == ARRAY_ELEMENT && stack.len() >= 2 {
            let parents = &stack[stack.len() - 2..];
            if parents[0].class == Some(SIGNAL) && parents[1].tag == TERM_LIST {
                let uid = node
                    .uid
                    .ok_or_else(|| invalid("signal endpoint is missing its UID"))?;
                endpoint_count += 1;
                if endpoint_count > MAX_ENDPOINTS {
                    return Err(invalid("diagram graph exceeds the endpoint limit"));
                }
                graph
                    .signals
                    .get_mut(&parents[0].uid.unwrap())
                    .unwrap()
                    .terminals
                    .push(uid);
            }
        }
        Ok(())
    })?;
    if root_diagrams != 1 {
        return Err(invalid("expected one root diagram in graph heap"));
    }
    for uid in graph.signals.keys() {
        if !term_lists.contains(uid) {
            return Err(invalid("signal is missing its terminal list"));
        }
    }
    graph.validate_endpoints();
    Ok(graph)
}

/// Decodes the signed, variable-width scalar representation used by heap integers.
fn integer(content: &[u8]) -> io::Result<i32> {
    if content.len() > 4 {
        return Err(invalid("oversized diagram graph integer"));
    }
    let fill = if content.first().is_some_and(|byte| byte & 0x80 != 0) {
        0xff
    } else {
        0
    };
    let mut bytes = [fill; 4];
    bytes[4 - content.len()..].copy_from_slice(content);
    Ok(i32::from_be_bytes(bytes))
}

/// Rejects an ambiguous saved scalar rather than choosing an occurrence.
fn set_once<T>(field: &mut Option<T>, value: T) -> io::Result<()> {
    if field.replace(value).is_some() {
        return Err(invalid("duplicate diagram graph field"));
    }
    Ok(())
}

impl DiagramGraph {
    /// Resolves diagram ownership through saved containment, never wire order.
    fn containing_diagram(&self, uid: i32) -> Option<i32> {
        let mut current = uid;
        loop {
            let object = self.objects.get(&current)?;
            if object.class == DIAGRAM {
                return Some(current);
            }
            current = object.parent?;
        }
    }

    /// Checks endpoint identities without inferring direction from list order.
    fn validate_endpoints(&mut self) {
        let mut owners = BTreeMap::new();
        for (&uid, signal) in &self.signals {
            if signal.terminals.len() < 2 {
                self.issues
                    .push(GraphIssue::TooFewEndpoints { signal: uid });
            }
            let mut seen = BTreeSet::new();
            for &terminal in &signal.terminals {
                if !seen.insert(terminal) {
                    self.issues.push(GraphIssue::DuplicateEndpoint {
                        signal: uid,
                        terminal,
                    });
                    continue;
                }
                if let Some(&first) = owners.get(&terminal) {
                    self.issues.push(GraphIssue::SharedTerminal {
                        terminal,
                        first,
                        second: uid,
                    });
                } else {
                    owners.insert(terminal, uid);
                }
                match self.objects.get(&terminal) {
                    None => self.issues.push(GraphIssue::UnresolvedTerminal {
                        signal: uid,
                        terminal,
                    }),
                    Some(object) if !matches!(object.class, TERM | FP_TERM) => {
                        self.issues.push(GraphIssue::NonTerminalEndpoint {
                            signal: uid,
                            object: terminal,
                        });
                    }
                    Some(_) if self.containing_diagram(terminal) != Some(signal.diagram) => {
                        self.issues.push(GraphIssue::CrossDiagramEndpoint {
                            signal: uid,
                            terminal,
                        });
                    }
                    Some(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
