//! Bounded decoding of version-b object heaps: block-diagram free-label
//! bookmarks, terminal display styles, and string constants from `BDHb`, and
//! front-panel control defaults and name labels from `FPHb`. The opt-in graph
//! reader preserves object identity and signal connections without interpreting
//! dataflow or compiled code.

pub(super) mod graph;

use super::{invalid, rsrc};
use flate2::bufread::ZlibDecoder;
use std::io::{self, Read};

const MAX_HEAP_SIZE: usize = 64 * 1024 * 1024;
const ARRAY_ELEMENT: i32 = -6;
const CLASS: i32 = -2;
const UID: i32 = -3;
const DIAGRAM: i32 = 27;
const LABEL: i32 = 10;
const TEXT_HAIR: i32 = 1;
const NODE_LIST: i32 = 164;
const Z_PLANE_LIST: i32 = 303;
const TEXT_RECORD: i32 = 270;
const TEXT: i32 = 3;
const DDO: i32 = 52;
const PARTS_LIST: i32 = 194;
const PART_ID: i32 = 192;
/// `PARTID.NAME_LABEL`, distinct from captions and other label parts.
const NAME_LABEL: u32 = 16;
/// `SL__fPTerm`: a front-panel control/indicator's terminal on the block diagram.
const FP_TERM: i32 = 22;
/// `OF__objFlags`: the terminal's object-flags field, including its display style.
const OBJ_FLAGS: i32 = 172;
/// `SL__fPDCO`: a front-panel control or indicator object in the FPHb heap.
const FP_DCO: i32 = 18;
/// `SL__bDConstDCO` and `SL__stdString`: a string constant and its display object.
const BD_CONST_DCO: i32 = 19;
const STD_STRING: i32 = 81;
/// `OF__typeDesc`: a heap TypeID field.
const TYPE_DESC: i32 = 283;
/// `OF__DefaultData`: an object's default value in flattened form.
const DEFAULT_DATA: i32 = 571;
/// `OF__ConstValue`: the flattened value stored on a diagram constant.
const CONST_VALUE: i32 = 589;
/// Terminal object-flags bit selecting icon-style display; clear is data-type style.
const ICON_STYLE_FLAG: u32 = 0x0400_0000;

#[derive(Clone, Copy)]
struct Node {
    tag: i32,
    class: Option<i32>,
    uid: Option<i32>,
}

/// Facts obtained from one block-diagram heap.
pub(super) struct DiagramHeapFacts {
    pub bookmarks: Vec<Vec<u8>>,
    pub terminal_icon_styles: Vec<bool>,
    pub string_constants: Vec<DiagramStringConstant>,
}

/// Reads the sole compressed BDHb section, rejecting malformed or oversized heaps.
pub(super) fn read_bdhb(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    count_minus_one: usize,
    section_offset: usize,
    read_constants: bool,
) -> io::Result<DiagramHeapFacts> {
    let heap = read_heap(
        "BDHb",
        table,
        table_size,
        data,
        count_minus_one,
        section_offset,
    )?;
    let (bookmarks, styles) =
        parse_heap(&heap).map_err(|error| invalid(format!("BDHb heap: {error}")))?;
    let constants = if read_constants {
        parse_diagram_strings(&heap).map_err(|error| invalid(format!("BDHb heap: {error}")))?
    } else {
        Vec::new()
    };
    Ok(DiagramHeapFacts {
        bookmarks,
        terminal_icon_styles: styles,
        string_constants: constants,
    })
}

/// A scalar diagram string constant's saved value and optional object label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagramStringConstant {
    pub label: Option<Vec<u8>>,
    pub bytes: Vec<u8>,
}

/// A front-panel control's stored default value, as kept in its heap object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ControlDefault {
    /// One-based heap TypeID, resolved through `DTHP` into `VCTP`.
    pub(super) type_id: usize,
    /// Name label owned by this control's display object, when present.
    pub(super) label: Option<Vec<u8>>,
    /// The value in LabVIEW's flattened form, exactly as stored.
    pub(super) data: Vec<u8>,
}

/// Reads the sole compressed FPHb section and returns each front-panel
/// control's stored `DefaultData`, type, and name label.
///
/// LabVIEW omits `DefaultData` for an empty or zero default, so a control
/// without the field is not reported. Malformed or ambiguous label parts
/// produce an `InvalidData` error.
pub(super) fn read_fphb(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    count_minus_one: usize,
    section_offset: usize,
) -> io::Result<Vec<ControlDefault>> {
    let heap = read_heap(
        "FPHb",
        table,
        table_size,
        data,
        count_minus_one,
        section_offset,
    )?;
    parse_front_panel(&heap).map_err(|error| invalid(format!("FPHb heap: {error}")))
}

/// Decompresses one version-b heap section and strips its length prefix.
fn read_heap(
    name: &str,
    table: &[u8],
    table_size: usize,
    data: &[u8],
    count_minus_one: usize,
    section_offset: usize,
) -> io::Result<Vec<u8>> {
    if count_minus_one != 0 || section_offset < table_size {
        return Err(invalid(format!("unsupported {name} section table")));
    }
    let section = rsrc::slice(table, section_offset, 20)?;
    if rsrc::number(section, 0)? != 0 {
        return Err(invalid(format!("unsupported {name} section index")));
    }
    let offset = rsrc::number(section, 12)?;
    let record = rsrc::slice(data, offset, data.len().saturating_sub(offset))?;
    let payload = rsrc::slice(record, 4, rsrc::number(record, 0)?)?;
    let expected = rsrc::number(payload, 0)?;
    if expected > MAX_HEAP_SIZE {
        return Err(invalid(format!("{name} heap exceeds the size limit")));
    }
    let compressed = &payload[4..];
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decoded = Vec::new();
    decoder
        .by_ref()
        .take((MAX_HEAP_SIZE + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|error| invalid(format!("invalid compressed {name} heap: {error}")))?;
    if decoded.len() != expected || decoder.total_in() as usize != compressed.len() {
        return Err(invalid(format!(
            "inconsistent compressed {name} heap length"
        )));
    }
    let length = rsrc::number(&decoded, 0)?;
    if length != decoded.len() - 4 {
        return Err(invalid(format!("inconsistent {name} heap length")));
    }
    decoded.drain(..4);
    Ok(decoded)
}

/// Reads only graph topology, without running string/default-value extraction.
pub(super) fn read_graph(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    count_minus_one: usize,
    section_offset: usize,
) -> io::Result<graph::DiagramGraph> {
    let heap = read_heap(
        "BDHb",
        table,
        table_size,
        data,
        count_minus_one,
        section_offset,
    )?;
    graph::parse(&heap).map_err(|error| invalid(format!("BDHb graph: {error}")))
}

/// How a heap node relates to the scope stack.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Scope {
    /// Opens a scope; following nodes are its children until its `Close`.
    Open,
    /// A field without children.
    Leaf,
    /// Closes the most recently opened scope.
    Close,
}

/// Tokenizes a heap and validates its scope nesting, calling `visit` with the
/// enclosing scopes, the node, its scope kind, and its content. For `Close`,
/// the parents exclude the node being closed.
fn walk_heap<'a>(
    bytes: &'a [u8],
    mut visit: impl FnMut(&[Node], Node, Scope, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut cursor = 0;
    let mut stack: Vec<Node> = Vec::new();
    while cursor < bytes.len() {
        let header = take(bytes, &mut cursor, 2)?;
        let size = header[0] >> 5;
        let attributes = header[0] & 0x10 != 0;
        let scope = (header[0] >> 2) & 3;
        let raw_tag = (((header[0] & 3) as i32) << 8) | header[1] as i32;
        let tag = if raw_tag == 1023 {
            signed(bytes, &mut cursor, 4)?
        } else {
            raw_tag - 31
        };
        let mut class = None;
        let mut uid = None;
        if attributes {
            let count = unsigned_variable(bytes, &mut cursor)?;
            for _ in 0..count {
                let id = signed_variable(bytes, &mut cursor)?;
                let value = signed_short_variable(bytes, &mut cursor)?;
                if id == CLASS && class.replace(value).is_some() {
                    return Err(invalid("duplicate heap class attribute"));
                }
                if id == UID && uid.replace(value).is_some() {
                    return Err(invalid("duplicate heap UID attribute"));
                }
            }
        }
        let length = match size {
            0 | 7 => 0,
            1..=4 => size as usize,
            6 => unsigned_variable(bytes, &mut cursor)?,
            _ => return Err(invalid("unsupported heap value size")),
        };
        let content = take(bytes, &mut cursor, length)?;
        let node = Node { tag, class, uid };
        match scope {
            0 => {
                visit(&stack, node, Scope::Open, content)?;
                stack.push(node);
            }
            1 => visit(&stack, node, Scope::Leaf, content)?,
            2 => {
                let parent = stack
                    .pop()
                    .ok_or_else(|| invalid("unmatched heap closing tag"))?;
                if parent.tag != tag {
                    return Err(invalid("mismatched heap closing tag"));
                }
                visit(&stack, parent, Scope::Close, &[])?;
            }
            _ => return Err(invalid("unsupported heap scope")),
        }
    }
    if !stack.is_empty() {
        return Err(invalid("unclosed heap scope"));
    }
    Ok(())
}

/// Walks heap scopes so only diagram-owned free labels and terminal objects
/// contribute facts.
fn parse_heap(bytes: &[u8]) -> io::Result<(Vec<Vec<u8>>, Vec<bool>)> {
    let mut bookmarks = Vec::new();
    let mut terminal_icon_styles = Vec::new();
    walk_heap(bytes, |stack, node, scope, content| {
        if scope == Scope::Close {
            return Ok(());
        }
        if node.tag == TEXT && stack.len() >= 4 {
            let parents = &stack[stack.len() - 4..];
            if parents[0].class == Some(DIAGRAM)
                && matches!(parents[1].tag, NODE_LIST | Z_PLANE_LIST)
                && parents[2].tag == ARRAY_ELEMENT
                && parents[2].class == Some(LABEL)
                && parents[3].tag == TEXT_RECORD
                && parents[3].class == Some(TEXT_HAIR)
                && content.starts_with(b"#")
            {
                bookmarks.push(content.to_vec());
            }
        }
        if node.tag == OBJ_FLAGS
            && stack
                .last()
                .is_some_and(|parent| parent.tag == ARRAY_ELEMENT && parent.class == Some(FP_TERM))
        {
            terminal_icon_styles.push(object_flags(content)? & ICON_STYLE_FLAG != 0);
        }
        Ok(())
    })?;
    Ok((bookmarks, terminal_icon_styles))
}

#[derive(Default)]
struct LabelPart {
    part_id: Option<u32>,
    text: Option<Vec<u8>>,
}

#[derive(Default)]
struct NameLabel {
    label: Option<Vec<u8>>,
    part: Option<LabelPart>,
}

impl NameLabel {
    /// Reads only the name-label part directly owned by the object's DDO.
    fn visit(
        &mut self,
        parents: &[Node],
        node: Node,
        scope: Scope,
        content: &[u8],
    ) -> io::Result<()> {
        if matches!(scope, Scope::Open | Scope::Close)
            && node.tag == ARRAY_ELEMENT
            && node.class == Some(LABEL)
            && parents.len() == 3
            && parents[1].tag == DDO
            && parents[2].tag == PARTS_LIST
        {
            if scope == Scope::Open {
                self.part = Some(LabelPart::default());
            } else if let Some(part) = self.part.take()
                && part.part_id == Some(NAME_LABEL)
                && let Some(text) = part.text
                && self.label.replace(text).is_some()
            {
                return Err(invalid("duplicate object name label"));
            }
        } else if let Some(part) = self.part.as_mut()
            && matches!(scope, Scope::Open | Scope::Leaf)
        {
            if parents.len() == 4 && node.tag == PART_ID {
                if content.len() > 4 {
                    return Err(invalid("oversized label partID"));
                }
                let mut bytes = [0; 4];
                bytes[4 - content.len()..].copy_from_slice(content);
                if part.part_id.replace(u32::from_be_bytes(bytes)).is_some() {
                    return Err(invalid("duplicate label partID"));
                }
            } else if parents.len() == 5
                && parents[4].tag == TEXT_RECORD
                && parents[4].class == Some(TEXT_HAIR)
                && node.tag == TEXT
                && part.text.replace(content.to_vec()).is_some()
            {
                return Err(invalid("duplicate label text"));
            }
        }
        Ok(())
    }
}

/// Extracts scalar string constants from their own `bDConstDCO` objects.
///
/// Missing or malformed saved values are errors, never empty strings.
fn parse_diagram_strings(bytes: &[u8]) -> io::Result<Vec<DiagramStringConstant>> {
    struct OpenConstant<'a> {
        depth: usize,
        ddo_class: Option<i32>,
        ddo_seen: bool,
        duplicate_ddo: bool,
        data: Option<&'a [u8]>,
        duplicate_data: bool,
        name: NameLabel,
    }
    let mut open: Vec<OpenConstant> = Vec::new();
    let mut strings = Vec::new();
    walk_heap(bytes, |stack, node, scope, content| {
        if node.class == Some(BD_CONST_DCO) && scope == Scope::Open {
            open.push(OpenConstant {
                depth: stack.len(),
                ddo_class: None,
                ddo_seen: false,
                duplicate_ddo: false,
                data: None,
                duplicate_data: false,
                name: NameLabel::default(),
            });
        } else if node.class == Some(BD_CONST_DCO) && scope == Scope::Close {
            let constant = open
                .pop()
                .ok_or_else(|| invalid("unmatched diagram constant"))?;
            if constant.ddo_class == Some(STD_STRING) {
                if constant.duplicate_ddo || constant.duplicate_data {
                    return Err(invalid("duplicate string constant DDO or ConstValue"));
                }
                let data = constant
                    .data
                    .ok_or_else(|| invalid("string constant has no ConstValue"))?;
                let length = rsrc::number(data, 0)?;
                let value = rsrc::slice(data, 4, length)?;
                if length != data.len() - 4 {
                    return Err(invalid("string constant has trailing ConstValue data"));
                }
                strings.push(DiagramStringConstant {
                    label: constant.name.label,
                    bytes: value.to_vec(),
                });
            }
        } else if let Some(constant) = open.last_mut() {
            let parents = &stack[constant.depth..];
            if parents.len() == 1 && scope == Scope::Open && node.tag == DDO {
                if constant.ddo_seen {
                    constant.duplicate_ddo = true;
                } else {
                    constant.ddo_seen = true;
                    constant.ddo_class = node.class;
                }
            } else if parents.len() == 1
                && matches!(scope, Scope::Open | Scope::Leaf)
                && node.tag == CONST_VALUE
            {
                if constant.data.is_some() {
                    constant.duplicate_data = true;
                } else {
                    constant.data = Some(content);
                }
            }
            if constant.ddo_class == Some(STD_STRING) {
                constant.name.visit(parents, node, scope, content)?;
            }
        }
        Ok(())
    })?;
    Ok(strings)
}

/// Collects direct defaults and name labels of front-panel controls.
fn parse_front_panel(bytes: &[u8]) -> io::Result<Vec<ControlDefault>> {
    struct OpenControl {
        depth: usize,
        type_id: Option<usize>,
        data: Option<Vec<u8>>,
        name: NameLabel,
    }
    let mut open: Vec<OpenControl> = Vec::new();
    let mut defaults = Vec::new();
    walk_heap(bytes, |stack, node, scope, content| {
        let is_control = node.tag == ARRAY_ELEMENT && node.class == Some(FP_DCO);
        match scope {
            Scope::Open if is_control => open.push(OpenControl {
                depth: stack.len(),
                type_id: None,
                data: None,
                name: NameLabel::default(),
            }),
            Scope::Close if is_control => {
                let control = open
                    .pop()
                    .ok_or_else(|| invalid("unmatched FPHb control scope"))?;
                if let Some(data) = control.data {
                    let type_id = control
                        .type_id
                        .ok_or_else(|| invalid("FPHb control default has no typeDesc"))?;
                    defaults.push(ControlDefault {
                        type_id,
                        label: control.name.label,
                        data,
                    });
                }
            }
            _ => {
                let Some(control) = open.last_mut() else {
                    return Ok(());
                };
                let parents = &stack[control.depth..];
                control.name.visit(parents, node, scope, content)?;
                if parents.len() == 1 && matches!(scope, Scope::Open | Scope::Leaf) {
                    if node.tag == TYPE_DESC && control.type_id.is_none() {
                        control.type_id = Some(type_id(content)?);
                    } else if node.tag == DEFAULT_DATA
                        && control.data.replace(content.to_vec()).is_some()
                    {
                        return Err(invalid("duplicate FPHb control DefaultData"));
                    }
                }
            }
        }
        Ok(())
    })?;
    Ok(defaults)
}

/// Reads a heap TypeID field: a signed big-endian integer of 1 to 4 bytes that
/// must be positive.
fn type_id(content: &[u8]) -> io::Result<usize> {
    if content.is_empty() || content.len() > 4 {
        return Err(invalid("unsupported heap TypeID width"));
    }
    let mut bytes = if content[0] & 0x80 != 0 {
        [0xff; 4]
    } else {
        [0; 4]
    };
    bytes[4 - content.len()..].copy_from_slice(content);
    usize::try_from(i32::from_be_bytes(bytes))
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("heap TypeID must be positive"))
}

/// Reads a terminal's `objFlags` field as a big-endian unsigned integer.
fn object_flags(content: &[u8]) -> io::Result<u32> {
    if content.len() > 4 {
        return Err(invalid("oversized BDHb terminal objFlags field"));
    }
    let mut bytes = [0; 4];
    bytes[4 - content.len()..].copy_from_slice(content);
    Ok(u32::from_be_bytes(bytes))
}

/// Advances through a bounded heap range.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let value = rsrc::slice(bytes, *cursor, length)?;
    *cursor += length;
    Ok(value)
}

/// Reads a signed big-endian integer of a supported width.
fn signed(bytes: &[u8], cursor: &mut usize, length: usize) -> io::Result<i32> {
    let value = take(bytes, cursor, length)?;
    Ok(match length {
        1 => i8::from_be_bytes([value[0]]) as i32,
        2 => i16::from_be_bytes([value[0], value[1]]) as i32,
        4 => i32::from_be_bytes(value.try_into().unwrap()),
        _ => unreachable!(),
    })
}

/// Reads LabVIEW's unsigned 1/2/4-byte variable field.
fn unsigned_variable(bytes: &[u8], cursor: &mut usize) -> io::Result<usize> {
    let first = take(bytes, cursor, 1)?[0];
    let value = match first {
        255 => u16::from_be_bytes(take(bytes, cursor, 2)?.try_into().unwrap()) as u32,
        254 => u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().unwrap()),
        _ => first as u32,
    };
    usize::try_from(value).map_err(|_| invalid("heap value is too large"))
}

/// Reads LabVIEW's signed 1/2/4-byte attribute identifier.
fn signed_variable(bytes: &[u8], cursor: &mut usize) -> io::Result<i32> {
    match signed(bytes, cursor, 1)? {
        -128 => signed(bytes, cursor, 2),
        -127 => signed(bytes, cursor, 4),
        value => Ok(value),
    }
}

/// Reads a signed 2/4-byte attribute value.
fn signed_short_variable(bytes: &[u8], cursor: &mut usize) -> io::Result<i32> {
    match signed(bytes, cursor, 2)? {
        -32768 => signed(bytes, cursor, 4),
        value => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(heap: &mut Vec<u8>, tag: i32, scope: u8, class: Option<i16>, content: &[u8]) {
        let tag = (tag + 31) as u16;
        let size = if content.is_empty() { 0 } else { 6 };
        heap.push((size << 5) | (u8::from(class.is_some()) << 4) | (scope << 2) | (tag >> 8) as u8);
        heap.push(tag as u8);
        if let Some(class) = class {
            heap.extend_from_slice(&[1, 0xfe]);
            heap.extend_from_slice(&class.to_be_bytes());
        }
        if !content.is_empty() {
            heap.push(content.len() as u8);
            heap.extend_from_slice(content);
        }
    }

    fn label(heap: &mut Vec<u8>, parent: i32, text: &[u8]) {
        node(heap, parent, 0, None, &[]);
        node(heap, ARRAY_ELEMENT, 0, Some(LABEL as i16), &[]);
        node(heap, TEXT_RECORD, 0, Some(TEXT_HAIR as i16), &[]);
        node(heap, TEXT, 1, None, text);
        node(heap, TEXT_RECORD, 2, None, &[]);
        node(heap, ARRAY_ELEMENT, 2, None, &[]);
        node(heap, parent, 2, None, &[]);
    }

    fn terminal(heap: &mut Vec<u8>, object_flags: u32) {
        node(heap, ARRAY_ELEMENT, 0, Some(FP_TERM as i16), &[]);
        node(heap, OBJ_FLAGS, 1, None, &object_flags.to_be_bytes());
        node(heap, ARRAY_ELEMENT, 2, None, &[]);
    }

    #[test]
    fn reads_only_diagram_free_labels_including_nested_diagrams() {
        let mut heap = Vec::new();
        node(&mut heap, -7, 0, Some(DIAGRAM as i16), &[]);
        label(&mut heap, Z_PLANE_LIST, b"#wirelint file-description");
        label(&mut heap, 200, b"#wirelint no-breakpoints");
        label(&mut heap, NODE_LIST, b"not #a-bookmark");
        node(&mut heap, 63, 0, None, &[]);
        node(&mut heap, ARRAY_ELEMENT, 0, Some(DIAGRAM as i16), &[]);
        label(&mut heap, Z_PLANE_LIST, b"#other");
        node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        node(&mut heap, 63, 2, None, &[]);
        node(&mut heap, -7, 2, None, &[]);
        let (bookmarks, terminal_icon_styles) = parse_heap(&heap).unwrap();
        assert_eq!(
            bookmarks,
            vec![b"#wirelint file-description".to_vec(), b"#other".to_vec()]
        );
        assert!(terminal_icon_styles.is_empty());
        heap.pop();
        assert!(parse_heap(&heap).is_err());
    }

    #[test]
    fn reads_terminal_icon_styles_in_order_alongside_bookmarks() {
        let mut heap = Vec::new();
        node(&mut heap, -7, 0, Some(DIAGRAM as i16), &[]);
        label(&mut heap, Z_PLANE_LIST, b"#wirelint file-description");
        terminal(&mut heap, 0x0402_0040); // icon style, matches the confirmed sample bit
        terminal(&mut heap, 0x0002_0040); // data-type style, bit clear
        terminal(&mut heap, 0x0400_0000); // icon style, no other bits set
        node(&mut heap, -7, 2, None, &[]);
        let (bookmarks, terminal_icon_styles) = parse_heap(&heap).unwrap();
        assert_eq!(bookmarks, vec![b"#wirelint file-description".to_vec()]);
        assert_eq!(terminal_icon_styles, vec![true, false, true]);
    }

    #[test]
    fn ignores_obj_flags_outside_a_terminal_array_element() {
        let mut heap = Vec::new();
        node(&mut heap, -7, 0, Some(DIAGRAM as i16), &[]);
        node(
            &mut heap,
            OBJ_FLAGS,
            1,
            None,
            &ICON_STYLE_FLAG.to_be_bytes(),
        );
        node(&mut heap, ARRAY_ELEMENT, 0, Some(LABEL as i16), &[]);
        node(
            &mut heap,
            OBJ_FLAGS,
            1,
            None,
            &ICON_STYLE_FLAG.to_be_bytes(),
        );
        node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        node(&mut heap, -7, 2, None, &[]);
        let (_, terminal_icon_styles) = parse_heap(&heap).unwrap();
        assert!(terminal_icon_styles.is_empty());
    }

    #[test]
    fn rejects_oversized_terminal_obj_flags() {
        let mut heap = Vec::new();
        node(&mut heap, ARRAY_ELEMENT, 0, Some(FP_TERM as i16), &[]);
        node(&mut heap, OBJ_FLAGS, 1, None, &[0, 0, 0, 0, 1]);
        node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        assert!(parse_heap(&heap).is_err());
    }

    #[test]
    fn rejects_invalid_heap_scopes_and_lengths() {
        assert!(parse_heap(&[0x08, 24]).is_err());
        assert!(parse_heap(&[0x04, 24, 0x00]).is_err());
        assert!(parse_heap(&[0xa4, 24]).is_err());
    }

    fn control(heap: &mut Vec<u8>, type_id: &[u8], default: Option<&[u8]>, nested: &[u8]) {
        node(heap, ARRAY_ELEMENT, 0, Some(FP_DCO as i16), &[]);
        node(heap, TYPE_DESC, 1, None, type_id);
        node(heap, 52, 0, None, &[]);
        node(heap, TYPE_DESC, 1, None, &[0x63]);
        node(heap, DEFAULT_DATA, 1, None, b"ddo-level, not the control");
        heap.extend_from_slice(nested);
        node(heap, 52, 2, None, &[]);
        if let Some(default) = default {
            node(heap, DEFAULT_DATA, 1, None, default);
        }
        node(heap, ARRAY_ELEMENT, 2, None, &[]);
    }

    #[test]
    fn reads_direct_default_data_of_each_front_panel_control() {
        let mut inner = Vec::new();
        control(&mut inner, &[0x07], Some(b"\0\0\0\x02in"), &[]);
        let mut heap = Vec::new();
        node(&mut heap, 54, 0, None, &[]);
        control(&mut heap, &[0x0a], Some(b"\0\0\0\x02pw"), &[]);
        control(&mut heap, &[0x01], None, &[]);
        control(&mut heap, &[0x01, 0x05], Some(b"\0\0\0\x03out"), &inner);
        node(&mut heap, 54, 2, None, &[]);
        assert_eq!(
            parse_front_panel(&heap).unwrap(),
            vec![
                ControlDefault {
                    type_id: 10,
                    label: None,
                    data: b"\0\0\0\x02pw".to_vec(),
                },
                ControlDefault {
                    type_id: 7,
                    label: None,
                    data: b"\0\0\0\x02in".to_vec(),
                },
                ControlDefault {
                    type_id: 261,
                    label: None,
                    data: b"\0\0\0\x03out".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn reads_only_each_controls_own_name_label() {
        fn part(heap: &mut Vec<u8>, id: u8, text: &[u8]) {
            node(heap, ARRAY_ELEMENT, 0, Some(LABEL as i16), &[]);
            node(heap, TEXT_RECORD, 0, Some(TEXT_HAIR as i16), &[]);
            node(heap, TEXT, 1, None, text);
            node(heap, TEXT_RECORD, 2, None, &[]);
            node(heap, PART_ID, 1, None, &[id]);
            node(heap, ARRAY_ELEMENT, 2, None, &[]);
        }
        fn named_control(heap: &mut Vec<u8>, name: &[u8], nested: &[u8]) {
            node(heap, ARRAY_ELEMENT, 0, Some(FP_DCO as i16), &[]);
            node(heap, TYPE_DESC, 1, None, &[1]);
            node(heap, DDO, 0, Some(81), &[]);
            node(heap, PARTS_LIST, 0, None, &[]);
            part(heap, 82, b"Password caption");
            part(heap, NAME_LABEL as u8, name);
            node(heap, PARTS_LIST, 2, None, &[]);
            heap.extend_from_slice(nested);
            node(heap, DDO, 2, None, &[]);
            node(heap, DEFAULT_DATA, 1, None, b"value");
            node(heap, ARRAY_ELEMENT, 2, None, &[]);
        }
        let mut nested = Vec::new();
        named_control(&mut nested, b"Inner", &[]);
        let mut heap = Vec::new();
        named_control(&mut heap, b"Password", &nested);
        named_control(&mut heap, b"Username", &[]);
        let controls = parse_front_panel(&heap).unwrap();
        assert_eq!(
            controls
                .iter()
                .map(|c| c.label.as_deref())
                .collect::<Vec<_>>(),
            vec![
                Some(&b"Inner"[..]),
                Some(&b"Password"[..]),
                Some(&b"Username"[..])
            ]
        );
    }

    fn diagram_constant(heap: &mut Vec<u8>, class: i16, name: Option<&[u8]>, data: Option<&[u8]>) {
        node(heap, 48, 0, Some(BD_CONST_DCO as i16), &[]);
        node(heap, DDO, 0, Some(class), &[]);
        node(heap, PARTS_LIST, 0, None, &[]);
        for (id, text) in [
            (82, b"Password caption".as_slice()),
            (16, name.unwrap_or(b"")),
        ] {
            if text.is_empty() {
                continue;
            }
            node(heap, ARRAY_ELEMENT, 0, Some(LABEL as i16), &[]);
            node(heap, PART_ID, 1, None, &[id]);
            node(heap, TEXT_RECORD, 0, Some(TEXT_HAIR as i16), &[]);
            node(heap, TEXT, 1, None, text);
            node(heap, TEXT_RECORD, 2, None, &[]);
            node(heap, ARRAY_ELEMENT, 2, None, &[]);
        }
        node(heap, PARTS_LIST, 2, None, &[]);
        node(heap, DDO, 2, None, &[]);
        if let Some(data) = data {
            node(heap, CONST_VALUE, 1, None, data);
        }
        node(heap, 48, 2, None, &[]);
    }

    #[test]
    fn reads_labeled_and_unlabeled_string_constants_in_nested_diagrams() {
        let mut heap = Vec::new();
        node(&mut heap, -7, 0, Some(DIAGRAM as i16), &[]);
        diagram_constant(
            &mut heap,
            STD_STRING as i16,
            Some(b"Password"),
            Some(b"\0\0\0\x06secret"),
        );
        node(&mut heap, 63, 0, None, &[]);
        node(&mut heap, ARRAY_ELEMENT, 0, Some(DIAGRAM as i16), &[]);
        diagram_constant(&mut heap, STD_STRING as i16, None, Some(b"\0\0\0\x05token"));
        diagram_constant(&mut heap, 80, Some(b"Password"), Some(b"\0\0\0\x05value"));
        node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        node(&mut heap, 63, 2, None, &[]);
        node(&mut heap, -7, 2, None, &[]);
        assert_eq!(
            parse_diagram_strings(&heap).unwrap(),
            vec![
                DiagramStringConstant {
                    label: Some(b"Password".to_vec()),
                    bytes: b"secret".to_vec()
                },
                DiagramStringConstant {
                    label: None,
                    bytes: b"token".to_vec()
                },
            ]
        );
    }

    #[test]
    fn rejects_missing_or_malformed_string_constant_values() {
        for data in [
            None,
            Some(&b"\0\0\0\x05abc"[..]),
            Some(&b"\0\0\0\x01ab"[..]),
        ] {
            let mut heap = Vec::new();
            diagram_constant(&mut heap, STD_STRING as i16, None, data);
            assert!(parse_diagram_strings(&heap).is_err());
        }
        let mut heap = Vec::new();
        diagram_constant(&mut heap, 80, None, None);
        assert!(parse_diagram_strings(&heap).unwrap().is_empty());
    }

    #[test]
    fn rejects_ambiguous_control_name_labels() {
        let mut heap = Vec::new();
        node(&mut heap, ARRAY_ELEMENT, 0, Some(FP_DCO as i16), &[]);
        node(&mut heap, DDO, 0, Some(81), &[]);
        node(&mut heap, PARTS_LIST, 0, None, &[]);
        for text in [b"First".as_slice(), b"Second".as_slice()] {
            node(&mut heap, ARRAY_ELEMENT, 0, Some(LABEL as i16), &[]);
            node(&mut heap, PART_ID, 1, None, &[NAME_LABEL as u8]);
            node(&mut heap, TEXT_RECORD, 0, Some(TEXT_HAIR as i16), &[]);
            node(&mut heap, TEXT, 1, None, text);
            node(&mut heap, TEXT_RECORD, 2, None, &[]);
            node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        }
        node(&mut heap, PARTS_LIST, 2, None, &[]);
        node(&mut heap, DDO, 2, None, &[]);
        node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        assert!(parse_front_panel(&heap).is_err());
    }

    #[test]
    fn rejects_defaults_without_a_valid_type_id() {
        let mut heap = Vec::new();
        node(&mut heap, ARRAY_ELEMENT, 0, Some(FP_DCO as i16), &[]);
        node(&mut heap, DEFAULT_DATA, 1, None, b"value");
        node(&mut heap, ARRAY_ELEMENT, 2, None, &[]);
        assert!(parse_front_panel(&heap).is_err());
        for content in [&[][..], &[0xff], &[0, 0, 0, 0, 1]] {
            assert!(type_id(content).is_err(), "{content:?}");
        }
        assert_eq!(type_id(&[0x7f, 0xff]).unwrap(), 0x7fff);
    }
}
