//! Bounded extraction of string defaults from a VI's front-panel controls.
//!
//! Each control in the `FPHb` front-panel heap that has a non-empty default
//! stores it as `DefaultData`, in LabVIEW's flattened form, together with a heap
//! TypeID. `DTHP` maps heap TypeIDs onto a slice of the `VCTP` consolidated type
//! pool. This reader resolves each control's Type Descriptor, walks its
//! flattened value, and records every string it contains with the labels on its
//! path. Controls are independent, so a control whose type this reader cannot
//! decode is skipped without affecting the others.

use super::heap::ControlDefault;
use super::{Version, connector, invalid, rsrc};
use std::io;

const MAX_TYPE_COUNT: usize = 1_000_000;
const MAX_WALK_NODES: usize = 1_000_000;
const MAX_NESTING_DEPTH: usize = 128;
const TD_FLAG_HAS_LABEL: u8 = 1 << 6;
const MAX_LABEL_SEARCH: usize = 256;

/// A raw string default and its location among the VI's front-panel controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultStringValue {
    /// Owning front-panel control, including for strings nested in its value.
    pub object: Option<super::ObjectId>,
    /// One-based `VCTP` top-level type index of the control holding the value.
    pub type_index: usize,
    /// Cluster/array element indexes from the control's value to this string.
    pub field_path: Vec<usize>,
    /// The control's front-panel name (or type label), then Type Descriptor
    /// labels for each `field_path` step. Missing labels are empty.
    pub labels: Vec<Vec<u8>>,
    /// Stored bytes, without text decoding or normalization.
    pub bytes: Vec<u8>,
}

/// Decodes the string defaults of front-panel controls.
///
/// `dthp` is the `DTHP` block's `(count, index_shift)` slice of `VCTP`.
/// Malformed `VCTP` data or a control TypeID outside that slice is an
/// `InvalidData` error; a control whose value uses an unsupported type, or
/// does not match its type, is skipped.
pub(super) fn read_default_strings(
    types: &[u8],
    dthp: (usize, usize),
    controls: &[ControlDefault],
    version: Version,
) -> io::Result<Vec<DefaultStringValue>> {
    let (flat_offsets, top_level) = connector::parse_vctp_lists(types)
        .map_err(|error| invalid(format!("VCTP TypeDesc lists: {error}")))?;
    let (count, index_shift) = dthp;
    let mut output = Vec::new();
    for control in controls {
        if control.type_id == 0 || control.type_id > count {
            return Err(invalid(
                "FPHb control TypeID is outside the DTHP type slice",
            ));
        }
        let type_index = index_shift
            .checked_add(control.type_id - 1)
            .ok_or_else(|| invalid("DTHP type index overflow"))?;
        let flat = top_level_type(&top_level, type_index)?;
        let mut strings = Vec::new();
        let mut cursor = 0;
        let decoded = walk_fill(
            &Walk {
                types,
                flat_offsets: &flat_offsets,
                data: &control.data,
                version,
                type_index,
            },
            flat,
            &mut cursor,
            &mut ValuePath::default(),
            &mut strings,
            &mut 0,
            0,
        );
        if decoded.is_ok() && cursor == control.data.len() {
            for value in &mut strings {
                value.object = control.object;
            }
            if let Some(label) = control.label.as_ref().filter(|label| !label.is_empty()) {
                for value in &mut strings {
                    value.labels[0].clone_from(label);
                }
            }
            output.append(&mut strings);
        }
    }
    Ok(output)
}

/// Reads `DTHP`'s `(count, index_shift)` slice of the `VCTP` type pool.
///
/// LabVIEW omits the shift when the count is zero. Any other layout,
/// including LabVIEW 7.1 and older, is an `InvalidData` error.
pub(super) fn read_dthp(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    (count_minus_one, section_offset): (usize, usize),
) -> io::Result<(usize, usize)> {
    if count_minus_one != 0 || section_offset < table_size {
        return Err(invalid("unsupported DTHP section table"));
    }
    let section = rsrc::slice(table, section_offset, 20)?;
    if rsrc::number(section, 0)? != 0 {
        return Err(invalid("unsupported DTHP section index"));
    }
    let record_offset = rsrc::number(section, 12)?;
    let record = rsrc::slice(
        data,
        record_offset,
        data.len().saturating_sub(record_offset),
    )?;
    let payload = rsrc::slice(record, 4, rsrc::number(record, 0)?)?;
    let mut cursor = 0;
    let count = connector::read_variable(payload, &mut cursor)?;
    let index_shift = if count == 0 {
        0
    } else {
        connector::read_variable(payload, &mut cursor)?
    };
    if cursor != payload.len() {
        return Err(invalid("unexpected DTHP heap type slice layout"));
    }
    Ok((count, index_shift))
}

/// Inputs shared by every step of one control's value walk.
struct Walk<'a> {
    types: &'a [u8],
    flat_offsets: &'a [usize],
    data: &'a [u8],
    version: Version,
    type_index: usize,
}

/// Advances one flattened value and records any nested string defaults.
///
/// `cursor` indexes the control's flattened data; `path` is pushed and popped
/// around every Type Descriptor and recursive cluster/array value.
fn walk_fill(
    walk: &Walk,
    flat_index: usize,
    cursor: &mut usize,
    path: &mut ValuePath,
    output: &mut Vec<DefaultStringValue>,
    budget: &mut usize,
    depth: usize,
) -> io::Result<()> {
    *budget = budget
        .checked_add(1)
        .ok_or_else(|| invalid("default value traversal budget overflow"))?;
    if *budget > MAX_WALK_NODES || depth > MAX_NESTING_DEPTH {
        return Err(invalid(
            "default value nesting or element count exceeds the limit",
        ));
    }
    let data = walk.data;
    let mut descriptor = descriptor(walk.types, walk.flat_offsets, flat_index)?;
    path.labels.push(std::mem::take(&mut descriptor.label));
    // Errors abort this control's walk, so the label only needs popping on success.
    let result = match descriptor.kind {
        0x00 => Ok(()),
        0x01 | 0x05 | 0x15 => skip(data, cursor, 1),
        0x02 | 0x06 | 0x16 => skip(data, cursor, 2),
        0x03 | 0x07 | 0x17 | 0x09 | 0x19 | 0x34 | 0x35 | 0x41 => skip(data, cursor, 4),
        0x04 | 0x08 => skip(data, cursor, 8),
        0x0b | 0x1b => skip(data, cursor, 16),
        0x0c | 0x1c => skip(data, cursor, 8),
        0x0d | 0x1d => skip(data, cursor, 16),
        0x0e | 0x1e => skip(data, cursor, 32),
        0x20 => skip(data, cursor, 2),
        0x21 => skip(
            data,
            cursor,
            if walk.version.major > 4 || walk.version.minor >= 5 {
                1
            } else {
                2
            },
        ),
        0x30 | 0x33 | 0x37 => {
            let length = read_u32(data, cursor)?;
            let bytes = take(data, cursor, length)?.to_vec();
            output.push(DefaultStringValue {
                object: None,
                type_index: walk.type_index,
                field_path: path.fields.clone(),
                labels: path.labels.clone(),
                bytes,
            });
            Ok(())
        }
        0x40 | 0xa0 => {
            let dimensions = descriptor
                .dimensions
                .ok_or_else(|| invalid("array TypeDesc is missing its dimensions"))?;
            let element = *descriptor
                .clients
                .first()
                .ok_or_else(|| invalid("array TypeDesc is missing its element type"))?;
            let mut element_count = 1usize;
            for _ in 0..dimensions {
                let length = read_u32(data, cursor)? & 0x7fff_ffff;
                element_count = element_count
                    .checked_mul(length)
                    .ok_or_else(|| invalid("array element count overflow"))?;
                if element_count > MAX_WALK_NODES {
                    return Err(invalid("array element count exceeds the limit"));
                }
            }
            for index in 0..element_count {
                path.fields.push(index);
                walk_fill(walk, element, cursor, path, output, budget, depth + 1)?;
                path.fields.pop();
            }
            Ok(())
        }
        0x50 => {
            for (index, child) in descriptor.clients.iter().copied().enumerate() {
                path.fields.push(index);
                walk_fill(walk, child, cursor, path, output, budget, depth + 1)?;
                path.fields.pop();
            }
            Ok(())
        }
        kind => Err(invalid(format!(
            "unsupported TypeDesc kind 0x{kind:02x} in a default value"
        ))),
    };
    path.labels.pop();
    result
}

/// Field indexes and Type Descriptor labels of the value currently walked.
#[derive(Default)]
struct ValuePath {
    fields: Vec<usize>,
    labels: Vec<Vec<u8>>,
}

struct TypeDescriptor {
    kind: u8,
    dimensions: Option<usize>,
    clients: Vec<usize>,
    label: Vec<u8>,
}

/// Reads the structural fields needed to walk a cluster or array, plus the
/// descriptor's label when its `HasLabel` flag is set.
fn descriptor(types: &[u8], offsets: &[usize], index: usize) -> io::Result<TypeDescriptor> {
    let offset = *offsets
        .get(index)
        .ok_or_else(|| invalid("TypeDesc flat index is out of range"))?;
    let mut cursor = offset;
    let (kind, flags, length) = connector::read_td_header(types, &mut cursor)?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("TypeDesc range overflow"))?;
    rsrc::slice(types, offset, length)?;
    let mut descriptor = TypeDescriptor {
        kind,
        dimensions: None,
        clients: Vec::new(),
        label: Vec::new(),
    };
    match kind {
        0x40 | 0xa0 => {
            let dimension_count = read_u16(types, &mut cursor)? as usize;
            if dimension_count > 32 {
                return Err(invalid("array TypeDesc dimension count exceeds the limit"));
            }
            let dimension_bytes = dimension_count
                .checked_mul(4)
                .ok_or_else(|| invalid("array TypeDesc dimensions overflow"))?;
            rsrc::slice(types, cursor, dimension_bytes)?;
            cursor += dimension_bytes;
            descriptor.dimensions = Some(dimension_count);
            descriptor
                .clients
                .push(connector::read_variable(types, &mut cursor)?);
        }
        0x50 => {
            let client_count = connector::read_variable(types, &mut cursor)?;
            if client_count > MAX_TYPE_COUNT {
                return Err(invalid("cluster TypeDesc client count exceeds the limit"));
            }
            for _ in 0..client_count {
                descriptor
                    .clients
                    .push(connector::read_variable(types, &mut cursor)?);
            }
        }
        0x30 | 0x37 if end.saturating_sub(cursor) >= 4 => cursor += 4,
        _ => {}
    }
    if cursor > end {
        return Err(invalid("TypeDesc properties exceed their declared length"));
    }
    if descriptor
        .clients
        .iter()
        .any(|client| *client >= offsets.len())
    {
        return Err(invalid("TypeDesc client index is out of range"));
    }
    if flags & TD_FLAG_HAS_LABEL != 0 {
        descriptor.label = trailing_label(&types[cursor..end]).to_vec();
    }
    Ok(descriptor)
}

/// Locates the Pascal-string label LabVIEW stores at the end of a Type
/// Descriptor whose `HasLabel` flag is set.
///
/// Type-specific properties are not fully decoded, so this follows pylabview's
/// approach: within the last 256 bytes after the decoded properties, the first
/// length byte whose text runs exactly to the descriptor's end, with only
/// printable bytes or tab/CR/LF, is the label. No match yields an empty label.
fn trailing_label(rest: &[u8]) -> &[u8] {
    (rest.len().saturating_sub(MAX_LABEL_SEARCH)..rest.len())
        .find_map(|start| {
            let text = &rest[start + 1..];
            (usize::from(rest[start]) == text.len()
                && !text.is_empty()
                && text
                    .iter()
                    .all(|byte| *byte >= 0x20 || matches!(byte, b'\t' | b'\r' | b'\n')))
            .then_some(text)
        })
        .unwrap_or_default()
}

/// Resolves a one-based type index through VCTP's top-level list.
fn top_level_type(top_level: &[usize], type_index: usize) -> io::Result<usize> {
    if type_index == 0 {
        return Err(invalid("type index zero is invalid"));
    }
    top_level
        .get(type_index - 1)
        .copied()
        .ok_or_else(|| invalid("type index is outside the VCTP top-level list"))
}

/// Reads one bounded big-endian 16-bit value and advances the cursor.
fn read_u16(bytes: &[u8], cursor: &mut usize) -> io::Result<u16> {
    let value = take(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

/// Reads one bounded big-endian 32-bit value and advances the cursor.
fn read_u32(bytes: &[u8], cursor: &mut usize) -> io::Result<usize> {
    let value = take(bytes, cursor, 4)?;
    Ok(u32::from_be_bytes(value.try_into().unwrap()) as usize)
}

/// Advances over a bounded value without interpreting its contents.
fn skip(bytes: &[u8], cursor: &mut usize, length: usize) -> io::Result<()> {
    take(bytes, cursor, length).map(|_| ())
}

/// Returns a bounded byte range and advances the cursor only on success.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let value = rsrc::slice(bytes, *cursor, length)?;
    *cursor += length;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION: Version = Version {
        major: 24,
        minor: 0,
    };

    fn variable(value: usize) -> Vec<u8> {
        assert!(value < 0x8000);
        (value as u16).to_be_bytes().to_vec()
    }

    fn type_desc(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = (4u16 + body.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0, kind]);
        bytes.extend_from_slice(body);
        bytes
    }

    fn labeled(kind: u8, body: &[u8], label: &[u8]) -> Vec<u8> {
        let mut contents = body.to_vec();
        contents.push(label.len() as u8);
        contents.extend_from_slice(label);
        let mut bytes = type_desc(kind, &contents);
        bytes[2] = TD_FLAG_HAS_LABEL;
        bytes
    }

    fn type_pool(descriptors: &[Vec<u8>], top_level: &[usize]) -> Vec<u8> {
        let mut bytes = (descriptors.len() as u32).to_be_bytes().to_vec();
        for descriptor in descriptors {
            bytes.extend_from_slice(descriptor);
        }
        bytes.extend_from_slice(&variable(top_level.len()));
        for index in top_level {
            bytes.extend_from_slice(&variable(*index));
        }
        bytes
    }

    fn string(value: &[u8]) -> Vec<u8> {
        let mut bytes = (value.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(value);
        bytes
    }

    fn control(type_id: usize, data: Vec<u8>) -> ControlDefault {
        ControlDefault {
            object: None,
            type_id,
            label: None,
            data,
        }
    }

    fn defaults(
        pool: &[u8],
        dthp: (usize, usize),
        controls: &[ControlDefault],
    ) -> io::Result<Vec<DefaultStringValue>> {
        read_default_strings(pool, dthp, controls, VERSION)
    }

    #[test]
    fn resolves_controls_through_the_dthp_slice() {
        let pool = type_pool(
            &[
                type_desc(0x00, &[]),
                labeled(0x03, &[], b"Count"),
                labeled(0x30, &[0xff; 4], b"DB Password"),
            ],
            &[0, 1, 1, 2, 2],
        );
        let values = defaults(
            &pool,
            (4, 2),
            &[
                control(1, 42u32.to_be_bytes().to_vec()),
                control(3, string(b"hunter22")),
            ],
        )
        .unwrap();
        assert_eq!(
            values,
            vec![DefaultStringValue {
                object: None,
                type_index: 4,
                field_path: Vec::new(),
                labels: vec![b"DB Password".to_vec()],
                bytes: b"hunter22".to_vec(),
            }]
        );
    }

    #[test]
    fn walks_cluster_and_array_members_with_their_labels() {
        let pool = type_pool(
            &[
                labeled(0x30, &[0xff; 4], b"API Key"),
                type_desc(0x21, &[]),
                labeled(0x50, &[0, 2, 0, 1, 0, 0], b"Settings"),
                type_desc(0x40, &[0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0]),
            ],
            &[2, 3],
        );
        let mut cluster = vec![1];
        cluster.extend_from_slice(&string(b"key-1"));
        let mut array = 2u32.to_be_bytes().to_vec();
        array.extend_from_slice(&string(b"x"));
        array.extend_from_slice(&string(b"yz"));
        let values = defaults(&pool, (2, 1), &[control(1, cluster), control(2, array)]).unwrap();
        let located = values
            .iter()
            .map(|value| {
                (
                    value.type_index,
                    value.field_path.clone(),
                    value.labels.clone(),
                    value.bytes.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            located,
            vec![
                (
                    1,
                    vec![1],
                    vec![b"Settings".to_vec(), b"API Key".to_vec()],
                    b"key-1".to_vec()
                ),
                (
                    2,
                    vec![0],
                    vec![Vec::new(), b"API Key".to_vec()],
                    b"x".to_vec()
                ),
                (
                    2,
                    vec![1],
                    vec![Vec::new(), b"API Key".to_vec()],
                    b"yz".to_vec()
                ),
            ]
        );
    }

    #[test]
    fn prefers_control_name_and_preserves_nested_type_labels() {
        let pool = type_pool(
            &[
                labeled(0x30, &[0xff; 4], b"Member"),
                labeled(0x50, &[0, 1, 0, 0], b"Old Type Name"),
            ],
            &[0, 1],
        );
        let mut named = control(2, string(b"value"));
        named.label = Some(b"Settings".to_vec());
        let mut empty = control(1, string(b"fallback"));
        empty.label = Some(Vec::new());
        let values = defaults(&pool, (2, 1), &[named, empty]).unwrap();
        assert_eq!(
            values[0].labels,
            vec![b"Settings".to_vec(), b"Member".to_vec()]
        );
        assert_eq!(values[1].labels, vec![b"Member".to_vec()]);
    }

    #[test]
    fn skips_controls_that_cannot_be_decoded_without_losing_others() {
        let pool = type_pool(
            &[type_desc(0x30, &[0xff; 4]), type_desc(0x64, &[])],
            &[0, 1],
        );
        let mut trailing = string(b"ok");
        trailing.push(0);
        let values = defaults(
            &pool,
            (2, 1),
            &[
                control(2, vec![1, 2, 3]),
                control(1, vec![0, 0, 0, 9, b'a']),
                control(1, trailing),
                control(1, string(b"kept")),
            ],
        )
        .unwrap();
        assert_eq!(
            values.iter().map(|value| &value.bytes).collect::<Vec<_>>(),
            vec![b"kept"]
        );
    }

    #[test]
    fn rejects_type_ids_outside_the_dthp_slice_or_vctp() {
        let pool = type_pool(&[type_desc(0x30, &[0xff; 4])], &[0]);
        for (dthp, type_id) in [((1, 1), 2), ((1, 1), 0), ((2, 1), 2)] {
            assert!(
                defaults(&pool, dthp, &[control(type_id, string(b"x"))]).is_err(),
                "{dthp:?} {type_id}"
            );
        }
        let bad_cluster = type_pool(&[type_desc(0x50, &[0, 1, 0, 5])], &[0]);
        assert!(
            defaults(&bad_cluster, (1, 1), &[control(1, Vec::new())])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reads_dthp_slices_and_rejects_unexpected_layouts() {
        fn dthp(payload: &[u8]) -> io::Result<(usize, usize)> {
            let mut data = (payload.len() as u32).to_be_bytes().to_vec();
            data.extend_from_slice(payload);
            let mut table = vec![0; 60];
            table[52..56].copy_from_slice(&0u32.to_be_bytes());
            read_dthp(&table, 40, &data, (0, 40))
        }
        assert_eq!(dthp(&[0, 11, 0, 3]).unwrap(), (11, 3));
        assert_eq!(dthp(&[0, 0]).unwrap(), (0, 0));
        assert!(dthp(&[0, 11]).is_err());
        assert!(dthp(&[0, 1, 0, 3, 0]).is_err());
    }

    #[test]
    fn finds_trailing_labels_like_pylabview() {
        assert_eq!(trailing_label(b"\xff\xff\xff\xff\x04Name"), b"Name");
        assert_eq!(trailing_label(b"\x02a\x01"), b"");
        assert_eq!(trailing_label(b"\x03ab"), b"");
        assert_eq!(trailing_label(b""), b"");
    }
}
