//! Bounded extraction of string defaults from a VI's typed `DFDS` data space.
//!
//! The reader walks every selected type-map entry in order because the saved
//! values are an unkeyed byte stream. It decodes supported non-string values
//! only far enough to advance safely to later strings.

use super::{Version, connector, invalid, rsrc};
use flate2::bufread::ZlibDecoder;
use std::io::{self, Read};

const MAX_SECTION_SIZE: usize = 64 * 1024 * 1024;
const MAX_TYPE_COUNT: usize = 1_000_000;
const MAX_WALK_NODES: usize = 1_000_000;
const MAX_NESTING_DEPTH: usize = 128;
const FLAG_DEFAULT_DATA: u32 = 1 << 13;
const FLAG_ALIGN_PADDING: u32 = 1;
const FLAG_SKIP_DATA: u32 = (1 << 3) | (1 << 10) | (1 << 11);
const TD_FLAG_HAS_LABEL: u8 = 1 << 6;
const MAX_LABEL_SEARCH: usize = 256;

/// A raw string default and its location within the VI's type map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultStringValue {
    /// Type-map entry index associated with this saved value.
    pub type_map_index: usize,
    /// Cluster/array element indexes from the type-map entry to this value.
    pub field_path: Vec<usize>,
    /// Type Descriptor labels from the type-map entry down to this value: one
    /// entry for the top-level type, then one per `field_path` step. A level
    /// without a stored label is empty. Bytes are not decoded.
    pub labels: Vec<Vec<u8>>,
    /// Stored bytes, without text decoding or normalization.
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(super) struct VersionInfo {
    pub(super) version: Version,
    pub(super) word: u32,
}

/// Reads the requested VI's type map, consolidated types, and default values.
///
/// The returned strings preserve their raw bytes and one-based type-map
/// indexes. Missing sections, malformed offsets, and unsupported serialized
/// types are `InvalidData` errors.
pub(super) fn read_default_strings(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    dfds: (usize, usize),
    tm80: (usize, usize),
    vctp: (usize, usize),
    version: VersionInfo,
) -> io::Result<Vec<DefaultStringValue>> {
    let dfds = read_section(table, table_size, data, dfds, b"DFDS", version.version)
        .map_err(|error| invalid(format!("DFDS default data: {error}")))?;
    let tm80 = read_section(table, table_size, data, tm80, b"TM80", version.version)
        .map_err(|error| invalid(format!("TM80 type map: {error}")))?;
    let types = connector::read_vctp(table, table_size, data, vctp)
        .map_err(|error| invalid(format!("VCTP type pool: {error}")))?;
    let (flat_offsets, top_level) = connector::parse_vctp_lists(&types)
        .map_err(|error| invalid(format!("VCTP TypeDesc lists: {error}")))?;
    let (index_shift, flags) = parse_type_map(&tm80)
        .map_err(|error| invalid(format!("TM80 type-map decoding: {error}")))?;
    walk_default_data(
        &types,
        &flat_offsets,
        &top_level,
        &flags,
        index_shift,
        &dfds,
        version,
    )
    .map_err(|error| invalid(format!("DFDS value decoding: {error}")))
}

/// Reads one section's payload, applying its version-dependent compression.
fn read_section(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    (count_minus_one, section_offset): (usize, usize),
    name: &[u8; 4],
    version: Version,
) -> io::Result<Vec<u8>> {
    if count_minus_one != 0 || section_offset < table_size {
        return Err(invalid(format!(
            "unsupported {} section table",
            String::from_utf8_lossy(name)
        )));
    }
    let section = rsrc::slice(table, section_offset, 20).map_err(|error| {
        invalid(format!(
            "invalid {} section descriptor: {error}",
            name_text(name)
        ))
    })?;
    if rsrc::number(section, 0)? != 0 {
        return Err(invalid(format!(
            "unsupported {} section index",
            String::from_utf8_lossy(name)
        )));
    }
    let record_offset = rsrc::number(section, 12)?;
    let record = rsrc::slice(
        data,
        record_offset,
        data.len().saturating_sub(record_offset),
    )
    .map_err(|error| invalid(format!("invalid {} data record: {error}", name_text(name))))?;
    let payload = rsrc::slice(record, 4, rsrc::number(record, 0)?)
        .map_err(|error| invalid(format!("invalid {} payload: {error}", name_text(name))))?;
    let compressed = match name {
        b"TM80" => version.major >= 10,
        b"DFDS" => version.major >= 8,
        _ => false,
    };
    if compressed {
        decode_zlib_section(payload, name)
    } else {
        if payload.len() > MAX_SECTION_SIZE {
            return Err(invalid(format!(
                "{} section exceeds the size limit",
                name_text(name)
            )));
        }
        Ok(payload.to_vec())
    }
}

fn name_text(name: &[u8; 4]) -> &'static str {
    match name {
        b"TM80" => "TM80",
        b"DFDS" => "DFDS",
        _ => "unknown",
    }
}

/// Decompresses a length-prefixed zlib section within the shared size bound.
fn decode_zlib_section(payload: &[u8], name: &[u8; 4]) -> io::Result<Vec<u8>> {
    if payload.len() < 4 {
        return Err(invalid(format!(
            "truncated {} compressed section",
            String::from_utf8_lossy(name)
        )));
    }
    let expected = rsrc::number(payload, 0)?;
    if expected > MAX_SECTION_SIZE {
        return Err(invalid(format!(
            "{} section exceeds the size limit",
            String::from_utf8_lossy(name)
        )));
    }
    let compressed = &payload[4..];
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decoded = Vec::new();
    decoder
        .by_ref()
        .take((MAX_SECTION_SIZE + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|error| {
            invalid(format!(
                "invalid compressed {} section: {error}",
                String::from_utf8_lossy(name)
            ))
        })?;
    if decoded.len() != expected || decoder.total_in() as usize != compressed.len() {
        return Err(invalid(format!(
            "inconsistent compressed {} section length",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(decoded)
}

/// Reads TM80's index shift and per-type flags, rejecting trailing bytes.
fn parse_type_map(bytes: &[u8]) -> io::Result<(usize, Vec<u32>)> {
    let mut cursor = 0;
    let count = connector::read_variable(bytes, &mut cursor)?;
    if count > MAX_TYPE_COUNT {
        return Err(invalid("TM80 type-map count exceeds the size limit"));
    }
    let index_shift = if count == 0 {
        0
    } else {
        connector::read_variable(bytes, &mut cursor)?
    };
    let mut flags = Vec::with_capacity(count);
    for _ in 0..count {
        flags.push(
            u32::try_from(connector::read_variable(bytes, &mut cursor)?)
                .map_err(|_| invalid("TM80 type-map flags exceed 32 bits"))?,
        );
    }
    if cursor != bytes.len() {
        return Err(invalid("unexpected trailing data in TM80 type map"));
    }
    Ok((index_shift, flags))
}

/// Walks selected defaults sequentially; every branch must consume its full value.
fn walk_default_data(
    types: &[u8],
    flat_offsets: &[usize],
    top_level: &[usize],
    type_map: &[u32],
    index_shift: usize,
    data: &[u8],
    version: VersionInfo,
) -> io::Result<Vec<DefaultStringValue>> {
    let mut cursor = 0;
    let mut output = Vec::new();
    let mut budget = 0;
    for (entry_offset, flags) in type_map.iter().copied().enumerate() {
        if flags & FLAG_SKIP_DATA != 0 {
            continue;
        }
        let type_map_index = index_shift
            .checked_add(entry_offset)
            .ok_or_else(|| invalid("TM80 type-map index overflow"))?;
        if flags & (FLAG_DEFAULT_DATA | FLAG_ALIGN_PADDING) == 0 {
            let flat = top_level_type(top_level, type_map_index)?;
            if descriptor_kind(types, flat_offsets, flat)? == 0x50
                && flags & ((1 << 2) | (1 << 4) | (1 << 5) | (1 << 6)) != 0
            {
                walk_fill(
                    types,
                    flat_offsets,
                    flat,
                    flags,
                    data,
                    &mut cursor,
                    version.version,
                    type_map_index,
                    &mut ValuePath::default(),
                    &mut output,
                    &mut budget,
                    version.word,
                    0,
                )?;
            }
            continue;
        }
        let flat = top_level_type(top_level, type_map_index)?;
        walk_fill(
            types,
            flat_offsets,
            flat,
            flags,
            data,
            &mut cursor,
            version.version,
            type_map_index,
            &mut ValuePath::default(),
            &mut output,
            &mut budget,
            version.word,
            0,
        )?;
    }
    if cursor != data.len() {
        return Err(invalid("unconsumed bytes remain in DFDS data"));
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
/// Advances one typed value and records any nested string defaults.
///
/// `cursor` is shared across the whole DFDS stream; `path` is pushed and
/// popped around every Type Descriptor and recursive cluster/array value.
fn walk_fill(
    types: &[u8],
    flat_offsets: &[usize],
    flat_index: usize,
    type_map_flags: u32,
    data: &[u8],
    cursor: &mut usize,
    version: Version,
    type_map_index: usize,
    path: &mut ValuePath,
    output: &mut Vec<DefaultStringValue>,
    budget: &mut usize,
    version_word: u32,
    depth: usize,
) -> io::Result<()> {
    *budget = budget
        .checked_add(1)
        .ok_or_else(|| invalid("DFDS traversal budget overflow"))?;
    if *budget > MAX_WALK_NODES || depth > MAX_NESTING_DEPTH {
        return Err(invalid(
            "DFDS type nesting or element count exceeds the limit",
        ));
    }
    let mut descriptor = descriptor(types, flat_offsets, flat_index)?;
    path.labels.push(std::mem::take(&mut descriptor.label));
    // Errors abort the whole walk, so the label only needs popping on success.
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
            if version.major > 4 || version.minor >= 5 {
                1
            } else {
                2
            },
        ),
        0x30 | 0x33 | 0x37 => {
            let length = read_u32(data, cursor)?;
            let bytes = take(data, cursor, length)?.to_vec();
            output.push(DefaultStringValue {
                type_map_index,
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
                    .ok_or_else(|| invalid("DFDS array element count overflow"))?;
                if element_count > MAX_WALK_NODES {
                    return Err(invalid("DFDS array element count exceeds the limit"));
                }
            }
            for index in 0..element_count {
                path.fields.push(index);
                walk_fill(
                    types,
                    flat_offsets,
                    element,
                    type_map_flags,
                    data,
                    cursor,
                    version,
                    type_map_index,
                    path,
                    output,
                    budget,
                    version_word,
                    depth + 1,
                )?;
                path.fields.pop();
            }
            Ok(())
        }
        0x50 => {
            let children =
                special_cluster_children(&descriptor.clients, type_map_flags, version_word)?;
            for (index, child) in children {
                path.fields.push(index);
                walk_fill(
                    types,
                    flat_offsets,
                    child,
                    type_map_flags,
                    data,
                    cursor,
                    version,
                    type_map_index,
                    path,
                    output,
                    budget,
                    version_word,
                    depth + 1,
                )?;
                path.fields.pop();
            }
            Ok(())
        }
        0x31 => Err(invalid("unsupported String2 DFDS value")),
        0x32 => Err(invalid("unsupported Path DFDS value")),
        kind => Err(invalid(format!(
            "unsupported TypeDesc kind 0x{kind:02x} in DFDS"
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

/// Selects serialized children for known special type-map cluster flags.
fn special_cluster_children(
    clients: &[usize],
    flags: u32,
    version_word: u32,
) -> io::Result<Vec<(usize, usize)>> {
    let selected = if flags & (1 << 2) != 0 {
        let version = (
            ((version_word >> 28) & 0x0f) * 10 + ((version_word >> 24) & 0x0f),
            (version_word >> 20) & 0x0f,
            (version_word >> 16) & 0x0f,
            (version_word >> 13) & 0x07,
        );
        if version < (10, 0, 0, 2) {
            vec![2]
        } else {
            vec![1]
        }
    } else if flags & (1 << 4) != 0 {
        vec![1, 2, 3]
    } else if flags & (1 << 5) != 0 {
        vec![3]
    } else if flags & (1 << 6) != 0 {
        vec![2]
    } else {
        return Ok(clients.iter().copied().enumerate().collect());
    };
    let mut values = Vec::with_capacity(selected.len());
    for index in selected {
        let child = *clients
            .get(index)
            .ok_or_else(|| invalid("special DSTM cluster child index is out of range"))?;
        values.push((index, child));
    }
    if flags & (1 << 9) != 0 && !values.is_empty() {
        values.remove(0);
    }
    Ok(values)
}

struct TypeDescriptor {
    kind: u8,
    dimensions: Option<usize>,
    clients: Vec<usize>,
    label: Vec<u8>,
}

/// Returns one flat Type Descriptor's type code after validating its range.
fn descriptor_kind(types: &[u8], offsets: &[usize], index: usize) -> io::Result<u8> {
    Ok(descriptor(types, offsets, index)?.kind)
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

/// Resolves a one-based type-map index through VCTP's top-level list.
fn top_level_type(top_level: &[usize], type_map_index: usize) -> io::Result<usize> {
    if type_map_index == 0 {
        return Err(invalid("TM80 type-map index zero is invalid"));
    }
    top_level
        .get(type_map_index - 1)
        .copied()
        .ok_or_else(|| invalid("TM80 type-map index is out of range"))
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

    fn type_map(index_shift: usize, flags: &[u32]) -> Vec<u8> {
        let mut bytes = variable(flags.len());
        if !flags.is_empty() {
            bytes.extend_from_slice(&variable(index_shift));
            for flag in flags {
                bytes.extend_from_slice(&variable(*flag as usize));
            }
        }
        bytes
    }

    fn defaults(
        pool: &[u8],
        map: &[u8],
        data: &[u8],
        version: Version,
    ) -> io::Result<Vec<DefaultStringValue>> {
        let (offsets, top_level) = connector::parse_vctp_lists(pool)?;
        let (index_shift, flags) = parse_type_map(map)?;
        walk_default_data(
            pool,
            &offsets,
            &top_level,
            &flags,
            index_shift,
            data,
            VersionInfo {
                version,
                word: version_word(version),
            },
        )
    }

    fn version_word(version: Version) -> u32 {
        (((version.major / 10) as u32) << 28)
            | (((version.major % 10) as u32) << 24)
            | ((version.minor as u32) << 20)
            | (4 << 13)
    }

    #[test]
    fn walks_mixed_scalar_defaults_to_extract_strings() {
        let pool = type_pool(
            &[
                type_desc(0x03, &[]),
                type_desc(0x21, &[]),
                type_desc(0x30, &[]),
            ],
            &[0, 1, 2],
        );
        let mut data = 42i32.to_be_bytes().to_vec();
        data.push(1);
        data.extend_from_slice(&3u32.to_be_bytes());
        data.extend_from_slice(b"key");
        assert_eq!(
            defaults(
                &pool,
                &type_map(
                    1,
                    &[FLAG_DEFAULT_DATA, FLAG_DEFAULT_DATA, FLAG_DEFAULT_DATA],
                ),
                &data,
                Version {
                    major: 20,
                    minor: 0
                }
            )
            .unwrap(),
            vec![DefaultStringValue {
                type_map_index: 3,
                field_path: Vec::new(),
                labels: vec![Vec::new()],
                bytes: b"key".to_vec()
            }]
        );
    }

    #[test]
    fn walks_cluster_and_array_string_members() {
        let cluster = type_desc(0x50, &[0, 2, 0, 0, 0, 0]);
        let array = type_desc(0x40, &[0, 1, 0, 0, 0, 2, 0, 0]);
        let pool = type_pool(&[type_desc(0x30, &[]), cluster, array], &[1, 2]);
        let mut data = 1u32.to_be_bytes().to_vec();
        data.extend_from_slice(b"a");
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(b"bc");
        let mut array_data = 2u32.to_be_bytes().to_vec();
        for value in [b"x".as_slice(), b"yz".as_slice()] {
            array_data.extend_from_slice(&(value.len() as u32).to_be_bytes());
            array_data.extend_from_slice(value);
        }
        data.extend_from_slice(&array_data);
        let values = defaults(
            &pool,
            &type_map(1, &[FLAG_DEFAULT_DATA, FLAG_DEFAULT_DATA]),
            &data,
            Version {
                major: 20,
                minor: 0,
            },
        )
        .unwrap();
        assert_eq!(
            values,
            vec![
                DefaultStringValue {
                    type_map_index: 1,
                    field_path: vec![0],
                    labels: vec![Vec::new(), Vec::new()],
                    bytes: b"a".to_vec(),
                },
                DefaultStringValue {
                    type_map_index: 1,
                    field_path: vec![1],
                    labels: vec![Vec::new(), Vec::new()],
                    bytes: b"bc".to_vec(),
                },
                DefaultStringValue {
                    type_map_index: 2,
                    field_path: vec![0],
                    labels: vec![Vec::new(), Vec::new()],
                    bytes: b"x".to_vec(),
                },
                DefaultStringValue {
                    type_map_index: 2,
                    field_path: vec![1],
                    labels: vec![Vec::new(), Vec::new()],
                    bytes: b"yz".to_vec(),
                },
            ]
        );
    }

    #[test]
    fn attaches_type_descriptor_labels_along_the_value_path() {
        fn labeled(kind: u8, body: &[u8], label: &[u8]) -> Vec<u8> {
            let mut contents = body.to_vec();
            contents.push(label.len() as u8);
            contents.extend_from_slice(label);
            let mut bytes = type_desc(kind, &contents);
            bytes[2] = TD_FLAG_HAS_LABEL;
            bytes
        }

        let pool = type_pool(
            &[
                labeled(0x30, &[0xff; 4], b"DB Password"),
                type_desc(0x30, &[0xff; 4]),
                labeled(0x50, &[0, 2, 0, 0, 0, 1], b"Settings"),
            ],
            &[2],
        );
        let mut data = Vec::new();
        for value in [b"secret".as_slice(), b"plain".as_slice()] {
            data.extend_from_slice(&(value.len() as u32).to_be_bytes());
            data.extend_from_slice(value);
        }
        let values = defaults(
            &pool,
            &type_map(1, &[FLAG_DEFAULT_DATA]),
            &data,
            Version {
                major: 20,
                minor: 0,
            },
        )
        .unwrap();
        assert_eq!(
            values
                .iter()
                .map(|value| value.labels.clone())
                .collect::<Vec<_>>(),
            vec![
                vec![b"Settings".to_vec(), b"DB Password".to_vec()],
                vec![b"Settings".to_vec(), Vec::new()],
            ]
        );
    }

    #[test]
    fn finds_trailing_labels_like_pylabview() {
        assert_eq!(trailing_label(b"\xff\xff\xff\xff\x04Name"), b"Name");
        assert_eq!(trailing_label(b"\x02a\x01"), b"");
        assert_eq!(trailing_label(b"\x03ab"), b"");
        assert_eq!(trailing_label(b""), b"");
    }

    #[test]
    fn skips_entries_without_saved_data_and_errors_on_unsupported_types() {
        let pool = type_pool(&[type_desc(0x5f, &[])], &[0]);
        assert!(
            defaults(
                &pool,
                &type_map(1, &[1 << 3]),
                &[],
                Version {
                    major: 20,
                    minor: 0
                }
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            defaults(
                &pool,
                &type_map(1, &[FLAG_DEFAULT_DATA]),
                &[],
                Version {
                    major: 20,
                    minor: 0
                }
            )
            .unwrap_err()
            .to_string()
            .contains("unsupported TypeDesc kind")
        );
    }

    #[test]
    fn rejects_truncated_values_and_invalid_client_indices() {
        let string_pool = type_pool(&[type_desc(0x30, &[])], &[0]);
        assert!(
            defaults(
                &string_pool,
                &type_map(1, &[FLAG_DEFAULT_DATA]),
                &[0, 0, 0, 4, b'a'],
                Version {
                    major: 20,
                    minor: 0
                }
            )
            .is_err()
        );
        let bad_cluster = type_pool(&[type_desc(0x50, &[0, 1])], &[0]);
        assert!(
            defaults(
                &bad_cluster,
                &type_map(1, &[FLAG_DEFAULT_DATA]),
                &[],
                Version {
                    major: 20,
                    minor: 0
                }
            )
            .is_err()
        );
    }

    #[test]
    fn reads_zlib_coded_default_data_from_rsrc_sections() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        fn coded(payload: &[u8]) -> Vec<u8> {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(payload).unwrap();
            let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(&encoder.finish().unwrap());
            bytes
        }

        fn record(payload: &[u8]) -> Vec<u8> {
            let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(payload);
            bytes
        }

        let pool = type_pool(&[type_desc(0x30, &[])], &[0]);
        let map = type_map(1, &[FLAG_DEFAULT_DATA]);
        let mut default_data = 2u32.to_be_bytes().to_vec();
        default_data.extend_from_slice(b"ok");
        let records = [
            record(&coded(&default_data)),
            record(&coded(&map)),
            record(&coded(&pool)),
        ];
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for record in records {
            offsets.push(data.len());
            data.extend_from_slice(&record);
        }
        let section_offsets = [40usize, 60, 80];
        let mut table = vec![0; 100];
        table[..4].copy_from_slice(&2u32.to_be_bytes());
        for (index, record_offset) in offsets.iter().copied().enumerate() {
            let section_offset = section_offsets[index];
            table[section_offset + 12..section_offset + 16]
                .copy_from_slice(&(record_offset as u32).to_be_bytes());
        }

        assert_eq!(
            read_default_strings(
                &table,
                40,
                &data,
                (0, section_offsets[0]),
                (0, section_offsets[1]),
                (0, section_offsets[2]),
                VersionInfo {
                    version: Version {
                        major: 20,
                        minor: 0,
                    },
                    word: version_word(Version {
                        major: 20,
                        minor: 0,
                    }),
                }
            )
            .unwrap(),
            vec![DefaultStringValue {
                type_map_index: 1,
                field_path: Vec::new(),
                labels: vec![Vec::new()],
                bytes: b"ok".to_vec(),
            }]
        );
    }

    #[test]
    fn reads_legacy_uncompressed_default_and_type_map_sections() {
        let payload = [1, 2, 3];
        let mut record = (payload.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(&payload);
        let mut table = vec![0; 60];
        table[52..56].copy_from_slice(&0u32.to_be_bytes());

        assert_eq!(
            read_section(
                &table,
                40,
                &record,
                (0, 40),
                b"TM80",
                Version { major: 9, minor: 0 },
            )
            .unwrap(),
            payload
        );
        assert_eq!(
            read_section(
                &table,
                40,
                &record,
                (0, 40),
                b"DFDS",
                Version { major: 7, minor: 1 },
            )
            .unwrap(),
            payload
        );
    }

    #[test]
    fn selects_version_dependent_special_cluster_layouts() {
        assert!(special_cluster_children(&[0, 1, 2], 1 << 2, 0x0900_0000).unwrap() == vec![(2, 2)]);
        assert_eq!(
            special_cluster_children(&[0, 1, 2], 1 << 2, 0x1000_c000).unwrap(),
            vec![(1, 1)]
        );
    }
}
