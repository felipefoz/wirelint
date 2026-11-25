//! Local command-input analysis for statically identified NI System Exec calls.
//!
//! A supported path establishes control influence or literal-only construction.
//! Unknown transfer behavior is kept separate from findings and reported as an
//! analysis error by the runner, never treated as validation or sanitization.

use super::call_links::CallLink;
use super::heap::graph::{DiagramGraph, GraphObject};
use std::collections::{BTreeMap, BTreeSet};

const TERM: i32 = 21;
const FP_TERM: i32 = 22;
const CONSTANT: i32 = 19;
const IUSE: i32 = 49;
const IUSE_DCO: i32 = 51;
const CONCAT: i32 = 62;
const CONCAT_DCO: i32 = 63;
const COMMAND_SLOT: i32 = 11;
const WIRED_INPUT: u32 = 0x8000;
const MAX_TRACE_DEPTH: usize = 128;

/// Per-file evidence; call UIDs identify saved nodes, not executable paths.
#[derive(Debug, Default)]
pub struct SystemExecInputs {
    pub influenced_calls: Vec<i32>,
    pub incomplete_calls: Vec<(i32, String)>,
}

/// Classifies each identified call independently, preserving incomplete paths.
pub(super) fn analyze(graph: Option<&DiagramGraph>, calls: &[i32]) -> SystemExecInputs {
    let mut result = SystemExecInputs::default();
    let Some(graph) = graph else {
        result.incomplete_calls = calls
            .iter()
            .map(|&uid| (uid, "saved block-diagram source is missing".to_owned()))
            .collect();
        return result;
    };
    if !graph.issues.is_empty() {
        result.incomplete_calls = calls
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
        match trace.command(uid) {
            Ok(Some(Influence::Control)) => result.influenced_calls.push(uid),
            Ok(_) => {}
            Err(reason) => result.incomplete_calls.push((uid, reason.to_owned())),
        }
    }
    result
}

/// Matches the NI platform-library identity, not an arbitrary matching basename.
pub(super) fn is_system_exec(link: &CallLink) -> bool {
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

/// A proven influence path can coexist with unsupported contributors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Influence {
    Literal,
    Control,
}

/// Indexes existing topology once; traversal never follows wire-list order.
struct Trace<'a> {
    graph: &'a DiagramGraph,
    nets: BTreeMap<i32, i32>,
    children: BTreeMap<i32, Vec<i32>>,
    memo: BTreeMap<i32, Result<Influence, &'static str>>,
    visiting: BTreeSet<i32>,
}

impl<'a> Trace<'a> {
    fn new(graph: &'a DiagramGraph) -> Self {
        let nets = graph
            .signals
            .iter()
            .flat_map(|(&signal, net)| {
                net.terminals
                    .iter()
                    .map(move |&terminal| (terminal, signal))
            })
            .collect();
        let mut children = BTreeMap::<_, Vec<_>>::new();
        for (&uid, object) in &graph.objects {
            if let Some(parent) = object.parent {
                children.entry(parent).or_default().push(uid);
            }
        }
        Self {
            graph,
            nets,
            children,
            memo: BTreeMap::new(),
            visiting: BTreeSet::new(),
        }
    }

    /// The saved NI pane assigns command line to slot 11, standard input to 10.
    fn command(&mut self, uid: i32) -> Result<Option<Influence>, &'static str> {
        let call = self
            .graph
            .objects
            .get(&uid)
            .ok_or("linked call node is missing")?;
        if call.class != IUSE {
            return Err("linked object is not a supported static subVI call");
        }
        let terms = self
            .children
            .get(&uid)
            .ok_or("call terminals are missing")?;
        let mut command = None;
        for &terminal in terms {
            let object = &self.graph.objects[&terminal];
            if object.class != TERM {
                continue;
            }
            let dco = object.dco.and_then(|uid| self.graph.objects.get(&uid));
            if let Some(dco) = dco
                && dco.class == IUSE_DCO
                && dco.call_slot == Some(COMMAND_SLOT)
                && (dco.parent != Some(terminal)
                    || dco.flags.unwrap_or(0) & 1 != 0
                    || command.replace(terminal).is_some())
            {
                return Err("ambiguous command input slot");
            }
        }
        let terminal = command.ok_or("command input slot is missing")?;
        let wired = self.graph.objects[&terminal].flags.unwrap_or(0) & WIRED_INPUT != 0;
        if wired != self.nets.contains_key(&terminal) {
            return Err("command input flags and saved wire disagree");
        }
        if !wired {
            return Ok(None);
        }
        self.input(terminal, 0).map(Some)
    }

    /// Resolves a receiving terminal through its unique driving endpoint.
    fn input(&mut self, uid: i32, depth: usize) -> Result<Influence, &'static str> {
        if depth >= MAX_TRACE_DEPTH {
            return Err("command path exceeds the tracing depth limit");
        }
        if let Some(result) = self.memo.get(&uid) {
            return *result;
        }
        if !self.visiting.insert(uid) {
            return Err("cyclic command-input path");
        }
        let result = self.input_source(uid, depth);
        self.visiting.remove(&uid);
        self.memo.insert(uid, result);
        result
    }

    fn input_source(&mut self, uid: i32, depth: usize) -> Result<Influence, &'static str> {
        let signal = self
            .nets
            .get(&uid)
            .ok_or("command path has no saved wire")?;
        let mut source = None;
        for &terminal in &self.graph.signals[signal].terminals {
            let object = &self.graph.objects[&terminal];
            let flags = object.flags.ok_or("terminal direction flags are missing")?;
            if flags & WIRED_INPUT == 0 && source.replace(terminal).is_some() {
                return Err("command wire has multiple possible sources");
            }
        }
        let uid = source.ok_or("command wire has no resolved source")?;
        let terminal = &self.graph.objects[&uid];
        if terminal.class == FP_TERM {
            return Ok(Influence::Control);
        }
        if terminal
            .dco
            .and_then(|dco| self.graph.objects.get(&dco))
            .is_some_and(|dco| dco.class == CONSTANT)
        {
            return Ok(Influence::Literal);
        }
        let parent = terminal
            .parent
            .and_then(|parent| self.graph.objects.get(&parent))
            .ok_or("unsupported command source terminal")?;
        if parent.class == CONSTANT {
            return Ok(Influence::Literal);
        }
        self.operation(uid, parent, depth + 1)
    }

    /// Concatenation preserves influence; other operations have no transfer rule.
    fn operation(
        &mut self,
        output: i32,
        parent: &GraphObject,
        depth: usize,
    ) -> Result<Influence, &'static str> {
        if parent.class != CONCAT {
            return Err("unsupported operation on the command-input path");
        }
        let node = self.graph.objects[&output].parent.unwrap();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for &terminal in &self.children[&node] {
            let object = &self.graph.objects[&terminal];
            if object.class != TERM {
                continue;
            }
            let dco = object
                .dco
                .and_then(|dco| self.graph.objects.get(&dco))
                .filter(|dco| dco.class == CONCAT_DCO && dco.parent == Some(terminal))
                .ok_or("Concatenate Strings terminal metadata is missing")?;
            if dco.flags.unwrap_or(0) & 1 != 0 {
                outputs.push(terminal);
            } else {
                if object.flags.unwrap_or(0) & WIRED_INPUT == 0 {
                    return Err("unwired Concatenate Strings input is unsupported");
                }
                inputs.push(terminal);
            }
        }
        if outputs != [output] || inputs.is_empty() {
            return Err("unsupported Concatenate Strings terminal layout");
        }
        let mut unknown = None;
        for terminal in inputs {
            match self.input(terminal, depth) {
                Ok(Influence::Control) => return Ok(Influence::Control),
                Ok(Influence::Literal) => {}
                Err(reason) => unknown = Some(reason),
            }
        }
        unknown.map_or(Ok(Influence::Literal), Err)
    }
}

#[cfg(test)]
mod tests;
