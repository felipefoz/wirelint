//! Shared bounded decoding of the VCTP type pool.
//!
//! The connector-pane and typed-default readers both use this pool's compressed
//! payload, flat Type Descriptor boundaries, and variable-size indices.

use super::{invalid, rsrc};
use flate2::bufread::ZlibDecoder;
use std::io::{self, Read};

/// Upper bound on the decompressed VCTP pool.
const MAX_VCTP_SIZE: usize = 64 * 1024 * 1024;
pub(super) const MAX_VCTP_ENTRIES: usize = 1_000_000;

/// Reads the sole VCTP section and decompresses its length-prefixed zlib payload.
///
/// Unsupported section tables, malformed ranges or compression, and payloads
/// above the configured size limit return `InvalidData`.
pub(super) fn read_vctp(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    (count_minus_one, section_offset): (usize, usize),
) -> io::Result<Vec<u8>> {
    if count_minus_one != 0 || section_offset < table_size {
        return Err(invalid("unsupported VCTP section table"));
    }
    let section = rsrc::slice(table, section_offset, 20)?;
    if rsrc::number(section, 0)? != 0 {
        return Err(invalid("unsupported VCTP section index"));
    }
    let offset = rsrc::number(section, 12)?;
    let record = rsrc::slice(data, offset, data.len().saturating_sub(offset))?;
    let payload = rsrc::slice(record, 4, rsrc::number(record, 0)?)?;
    if payload.len() < 4 {
        return Err(invalid("truncated VCTP payload"));
    }
    let expected = rsrc::number(payload, 0)?;
    if expected > MAX_VCTP_SIZE {
        return Err(invalid(
            "VCTP consolidated type pool exceeds the size limit",
        ));
    }
    let compressed = &payload[4..];
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decoded = Vec::new();
    decoder
        .by_ref()
        .take((MAX_VCTP_SIZE + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|error| invalid(format!("invalid compressed VCTP data: {error}")))?;
    if decoded.len() != expected || decoder.total_in() as usize != compressed.len() {
        return Err(invalid("inconsistent compressed VCTP length"));
    }
    Ok(decoded)
}

/// Reads VCTP's flat Type Descriptor boundaries and top-level index list.
///
/// Each returned offset identifies one descriptor in `decoded`; malformed
/// lengths, truncated entries, and excessive counts return `InvalidData`.
pub(super) fn parse_vctp_lists(decoded: &[u8]) -> io::Result<(Vec<usize>, Vec<usize>)> {
    let mut cursor = 0;
    let count = rsrc::number(decoded, cursor)?;
    cursor += 4;
    if count > MAX_VCTP_ENTRIES {
        return Err(invalid("VCTP TypeDesc count exceeds the size limit"));
    }
    let mut flat_offsets = Vec::new();
    for _ in 0..count {
        let entry_start = cursor;
        flat_offsets.push(entry_start);
        let (_type, _flags, obj_len) = read_td_header(decoded, &mut cursor)?;
        cursor = entry_start
            .checked_add(obj_len)
            .ok_or_else(|| invalid("VCTP TypeDesc entry length overflow"))?;
        if cursor > decoded.len() {
            return Err(invalid("VCTP TypeDesc entry exceeds the section"));
        }
    }
    let top_count = read_variable(decoded, &mut cursor)?;
    if top_count > MAX_VCTP_ENTRIES {
        return Err(invalid("VCTP top-level type count exceeds the size limit"));
    }
    let mut top_level = Vec::new();
    for _ in 0..top_count {
        top_level.push(read_variable(decoded, &mut cursor)?);
    }
    Ok((flat_offsets, top_level))
}

/// Reads a Type Descriptor's `(type, flags, whole-entry length)` header.
///
/// `cursor` must point to the descriptor's encoded length and advances past
/// that length and the two-byte type/flags word.
pub(super) fn read_td_header(decoded: &[u8], cursor: &mut usize) -> io::Result<(u8, u8, usize)> {
    let obj_len = read_variable(decoded, cursor)?;
    let rest = rsrc::slice(decoded, *cursor, 2)?;
    let obj_flags = rest[0];
    let obj_type = rest[1];
    *cursor += 2;
    if obj_len < 4 {
        return Err(invalid("TypeDesc entry is smaller than its own header"));
    }
    Ok((obj_type, obj_flags, obj_len))
}

/// Reads LabVIEW's 16-or-32-bit variable-size field.
///
/// Values with the first word's high bit set consume a second word; truncated
/// input returns `InvalidData` without substituting a value.
pub(super) fn read_variable(decoded: &[u8], cursor: &mut usize) -> io::Result<usize> {
    let high = rsrc::slice(decoded, *cursor, 2)?;
    let mut value = u16::from_be_bytes([high[0], high[1]]) as usize;
    *cursor += 2;
    if value & 0x8000 != 0 {
        let low = rsrc::slice(decoded, *cursor, 2)?;
        *cursor += 2;
        value = ((value & 0x7fff) << 16) | u16::from_be_bytes([low[0], low[1]]) as usize;
    }
    Ok(value)
}
