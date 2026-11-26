//! Reusable local dataflow tracing over saved block-diagram call inputs.

use super::heap::graph::{DiagramGraph, GraphObject};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const TERM: i32 = 21;
pub(crate) const FP_TERM: i32 = 22;
const CONSTANT: i32 = 19;
pub(crate) const IUSE: i32 = 49;
const IUSE_DCO: i32 = 51;
pub(crate) const CONCAT: i32 = 62;
const CONCAT_DCO: i32 = 63;
pub(crate) const WIRED_INPUT: u32 = 0x8000;
const MAX_TRACE_DEPTH: usize = 128;

/// A proven influence path can coexist with unsupported contributors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Influence {
    Literal,
    Control,
}

/// Supported direct scalar values from a saved diagram constant.
pub(crate) enum Scalar<'a> {
    Boolean(bool),
    String(&'a [u8]),
}

/// Indexes existing topology once; traversal never follows wire-list order.
pub(crate) struct Trace<'a> {
    graph: &'a DiagramGraph,
    nets: BTreeMap<i32, i32>,
    children: BTreeMap<i32, Vec<i32>>,
    memo: BTreeMap<i32, Result<Influence, &'static str>>,
    visiting: BTreeSet<i32>,
}

impl<'a> Trace<'a> {
    pub(crate) fn new(graph: &'a DiagramGraph) -> Self {
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

    /// Reads a directly wired scalar constant; `None` means an unwired input.
    pub(crate) fn literal_input(
        &self,
        call: i32,
        slot: i32,
    ) -> Result<Option<Scalar<'a>>, &'static str> {
        let Some(terminal) = self.call_terminal(call, slot)? else {
            return Ok(None);
        };
        let source = &self.graph.objects[&self.source(terminal)?];
        let uid = source
            .dco
            .ok_or("input is not a directly wired scalar constant")?;
        let constant = self
            .graph
            .objects
            .get(&uid)
            .filter(|object| object.class == CONSTANT)
            .ok_or("input is not a directly wired scalar constant")?;
        let value = constant
            .constant_value
            .as_deref()
            .ok_or("constant value is missing")?;
        if constant.ambiguous_constant_display {
            return Err("ambiguous scalar constant display");
        }
        match constant.constant_display {
            Some(79) => match value {
                [0, 0] | [0] => Ok(Some(Scalar::Boolean(false))),
                [1] => Ok(Some(Scalar::Boolean(true))),
                _ => Err("unsupported Boolean constant value"),
            },
            Some(81) => {
                if value.len() < 4 {
                    return Err("truncated string constant");
                }
                let len = u32::from_be_bytes(value[..4].try_into().unwrap()) as usize;
                if len != value.len() - 4 {
                    return Err("invalid string constant length");
                }
                Ok(Some(Scalar::String(&value[4..])))
            }
            _ => Err("unsupported or ambiguous scalar constant type"),
        }
    }

    /// Resolves a saved static call's input at the requested connector slot.
    pub(crate) fn call_input(
        &mut self,
        uid: i32,
        slot: i32,
    ) -> Result<Option<Influence>, &'static str> {
        let Some(terminal) = self.call_terminal(uid, slot)? else {
            return Ok(None);
        };
        self.input(terminal, 0).map(Some)
    }

    /// Returns the wired input terminal, or `None` when it is unwired.
    pub(crate) fn call_terminal(&self, uid: i32, slot: i32) -> Result<Option<i32>, &'static str> {
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
        let mut input = None;
        for &terminal in terms {
            let object = &self.graph.objects[&terminal];
            if object.class != TERM {
                continue;
            }
            let dco = object.dco.and_then(|uid| self.graph.objects.get(&uid));
            if let Some(dco) = dco
                && dco.class == IUSE_DCO
                && dco.call_slot == Some(slot)
                && (dco.parent != Some(terminal)
                    || dco.flags.unwrap_or(0) & 1 != 0
                    || input.replace(terminal).is_some())
            {
                return Err("ambiguous call input slot");
            }
        }
        let terminal = input.ok_or("call input slot is missing")?;
        let wired = self.graph.objects[&terminal].flags.unwrap_or(0) & WIRED_INPUT != 0;
        if wired != self.nets.contains_key(&terminal) {
            return Err("call input flags and saved wire disagree");
        }
        if !wired {
            return Ok(None);
        }
        Ok(Some(terminal))
    }

    /// Resolves a receiving terminal through its unique driving endpoint.
    fn input(&mut self, uid: i32, depth: usize) -> Result<Influence, &'static str> {
        if depth >= MAX_TRACE_DEPTH {
            return Err("input path exceeds the tracing depth limit");
        }
        if let Some(result) = self.memo.get(&uid) {
            return *result;
        }
        if !self.visiting.insert(uid) {
            return Err("cyclic input path");
        }
        let result = self.input_source(uid, depth);
        self.visiting.remove(&uid);
        self.memo.insert(uid, result);
        result
    }

    fn input_source(&mut self, uid: i32, depth: usize) -> Result<Influence, &'static str> {
        let uid = self.source(uid)?;
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
            .ok_or("unsupported input source terminal")?;
        if parent.class == CONSTANT {
            return Ok(Influence::Literal);
        }
        self.operation(uid, parent, depth + 1)
    }

    /// Resolves the sole driving endpoint of a receiving terminal.
    pub(crate) fn source(&self, uid: i32) -> Result<i32, &'static str> {
        let signal = self.nets.get(&uid).ok_or("input path has no saved wire")?;
        let mut source = None;
        for &terminal in &self.graph.signals[signal].terminals {
            let object = &self.graph.objects[&terminal];
            let flags = object.flags.ok_or("terminal direction flags are missing")?;
            if flags & WIRED_INPUT == 0 && source.replace(terminal).is_some() {
                return Err("input wire has multiple possible sources");
            }
        }
        source.ok_or("input wire has no resolved source")
    }

    /// Concatenation preserves influence; other operations have no transfer rule.
    fn operation(
        &mut self,
        output: i32,
        parent: &GraphObject,
        depth: usize,
    ) -> Result<Influence, &'static str> {
        if parent.class != CONCAT {
            return Err("unsupported operation on the input path");
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
