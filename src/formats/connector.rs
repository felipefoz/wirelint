//! Bounded decoding of a VI's connector pane pattern.
//!
//! The pattern selects one of LabVIEW's 36 fixed terminal layouts for the
//! connector pane editor. It is read from the `pattern` field of the
//! "Function" Type Descriptor that the VI's `CONP` block points at, inside
//! the `VCTP` consolidated type pool. Offsets and structures were researched
//! using pylabview; the `CONP`-to-`VCTP`-to-pattern chain and the mapping
//! from raw pattern codes to named layouts came from labview-mcp's harvested
//! connector-pane tables. See THIRD_PARTY_NOTICES.md.

use super::vctp::{self, read_td_header, read_variable};
use super::{invalid, rsrc};
use std::io;

/// `TD_FULL_TYPE.Function`: the Type Descriptor kind describing a connector pane.
const FUNCTION_TYPE: u8 = 0xF0;
const POLY_VI_TYPE: u8 = 0xF2;
const CLUSTER_TYPE: u8 = 0x50;
/// Number of fixed connector pane patterns LabVIEW currently offers.
const PATTERN_COUNT: u16 = 36;

/// Reads the VI's connector pane pattern index (0-35), or `None` for a
/// polymorphic or global VI, which has no connector pane.
///
/// `conp` and `type_pool` are each a block's `(section_count_minus_one,
/// section_offset)` pair, as found in the RSRC block table. Malformed or
/// out-of-range structures, and pattern codes outside the 36 known layouts,
/// are errors; this never guesses a layout.
pub(super) fn read_pattern(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    conp: (usize, usize),
    type_pool: (usize, usize),
) -> io::Result<Option<u8>> {
    let conp_type_id = read_conp(table, table_size, data, conp)?;
    let decoded = vctp::read_vctp(table, table_size, data, type_pool)?;
    let (flat_offsets, top_level) = vctp::parse_vctp_lists(&decoded)?;
    let flat_type_id = *conp_type_id
        .checked_sub(1)
        .and_then(|index| top_level.get(index))
        .ok_or_else(|| invalid("connector pane TypeDesc index is out of range"))?;
    let offset = *flat_offsets
        .get(flat_type_id)
        .ok_or_else(|| invalid("connector pane FlatTypeID is out of range"))?;
    let mut cursor = offset;
    let (obj_type, _, _) = read_td_header(&decoded, &mut cursor)?;
    if matches!(obj_type, POLY_VI_TYPE | CLUSTER_TYPE) {
        return Ok(None);
    }
    let pattern = read_function_pattern(&decoded, offset)?;
    let pattern_index = pattern >> 3;
    if pattern_index >= PATTERN_COUNT {
        return Err(invalid(
            "connector pane pattern code does not match any known pattern",
        ));
    }
    Ok(Some(pattern_index as u8))
}

/// Reads the single big-endian type index stored in an uncompressed `CONP` block.
fn read_conp(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    (count_minus_one, section_offset): (usize, usize),
) -> io::Result<usize> {
    if count_minus_one != 0 || section_offset < table_size {
        return Err(invalid("unsupported CONP section table"));
    }
    let section = rsrc::slice(table, section_offset, 20)?;
    if rsrc::number(section, 0)? != 0 {
        return Err(invalid("unsupported CONP section index"));
    }
    let offset = rsrc::number(section, 12)?;
    let record = rsrc::slice(data, offset, data.len().saturating_sub(offset))?;
    let payload = rsrc::slice(record, 4, rsrc::number(record, 0)?)?;
    if payload.len() != 2 {
        return Err(invalid("unsupported CONP payload size"));
    }
    Ok(u16::from_be_bytes([payload[0], payload[1]]) as usize)
}

/// Reads the Function Type Descriptor at `offset` and returns its raw,
/// undivided 16-bit `pattern` field.
fn read_function_pattern(decoded: &[u8], offset: usize) -> io::Result<u16> {
    let mut cursor = offset;
    let (obj_type, _obj_flags, _obj_len) = read_td_header(decoded, &mut cursor)?;
    if obj_type != FUNCTION_TYPE {
        return Err(invalid("connector pane TypeDesc is not a Function type"));
    }
    let client_count = read_variable(decoded, &mut cursor)?;
    for _ in 0..client_count {
        read_variable(decoded, &mut cursor)?;
    }
    let rest = rsrc::slice(decoded, cursor, 4)?;
    Ok(u16::from_be_bytes([rest[2], rest[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    /// Builds one flat Type Descriptor entry: `[len:u16][flags:u8][type:u8][body]`.
    fn td_entry(obj_type: u8, body: &[u8]) -> Vec<u8> {
        let obj_len = 4 + body.len();
        let mut entry = (obj_len as u16).to_be_bytes().to_vec();
        entry.push(0); // flags
        entry.push(obj_type);
        entry.extend_from_slice(body);
        entry
    }

    /// Builds a Function TypeDesc body: client count, client indices (each
    /// 2 bytes here), `fflags`, `pattern`, and trailing padding we never read.
    fn function_body(clients: &[u16], pattern: u16) -> Vec<u8> {
        let mut body = (clients.len() as u16).to_be_bytes().to_vec();
        for client in clients {
            body.extend_from_slice(&client.to_be_bytes());
        }
        body.extend_from_slice(&0u16.to_be_bytes()); // fflags
        body.extend_from_slice(&pattern.to_be_bytes());
        body.extend_from_slice(&[0xaa, 0xbb]);
        body
    }

    /// Assembles a VCTP decoded payload: flat TD list, then the top-level list.
    fn vctp_payload(entries: &[Vec<u8>], top_level: &[u16]) -> Vec<u8> {
        let mut payload = (entries.len() as u32).to_be_bytes().to_vec();
        for entry in entries {
            payload.extend_from_slice(entry);
        }
        payload.extend_from_slice(&(top_level.len() as u16).to_be_bytes());
        for value in top_level {
            payload.extend_from_slice(&value.to_be_bytes());
        }
        payload
    }

    /// Codes a payload the way `BLOCK_CODING.ZLIB` sections are stored: a
    /// 4-byte decompressed length, then a raw zlib stream.
    fn zlib_coded(payload: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut coded = (payload.len() as u32).to_be_bytes().to_vec();
        coded.extend_from_slice(&compressed);
        coded
    }

    /// Builds a length-prefixed record: `[len:u32][payload]`.
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut record = (payload.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(payload);
        record
    }

    /// Builds a 20-byte section descriptor: section index 0, record at `offset`.
    fn section_descriptor(offset: usize) -> [u8; 20] {
        let mut section = [0u8; 20];
        section[12..16].copy_from_slice(&(offset as u32).to_be_bytes());
        section
    }

    /// Assembles a `(table, data)` pair with one CONP section descriptor at
    /// table offset 0 and one VCTP section descriptor at table offset 20, so
    /// tests can call `read_pattern(&table, 0, &data, (0, 0), (0, 20))`.
    fn fixture(conp_type_id: u16, vctp_payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let conp_record = record(&conp_type_id.to_be_bytes());
        let vctp_record = record(&zlib_coded(vctp_payload));

        let mut data = Vec::new();
        let conp_offset = data.len();
        data.extend_from_slice(&conp_record);
        let vctp_offset = data.len();
        data.extend_from_slice(&vctp_record);

        let mut table = Vec::new();
        table.extend_from_slice(&section_descriptor(conp_offset));
        table.extend_from_slice(&section_descriptor(vctp_offset));

        (table, data)
    }

    #[test]
    fn decodes_a_known_pattern_from_the_real_encoding_relation() {
        // conId 4815 (pattern index 15) carries raw pattern code 0x78 in the
        // harvested table; conId 4833 (index 33) carries 0x108.
        for (pattern_code, expected_index) in [(0x78u16, 15u8), (0x108, 33)] {
            let entries = vec![td_entry(FUNCTION_TYPE, &function_body(&[], pattern_code))];
            let payload = vctp_payload(&entries, &[0]);
            let (table, data) = fixture(1, &payload);
            let pattern = read_pattern(&table, 0, &data, (0, 0), (0, 20)).unwrap();
            assert_eq!(pattern, Some(expected_index), "{pattern_code:#x}");
        }
    }

    #[test]
    fn skips_preceding_flat_entries_to_reach_the_right_one() {
        let entries = vec![
            td_entry(0x01, &[0xde, 0xad, 0xbe, 0xef]),
            td_entry(0x05, &[]),
            td_entry(FUNCTION_TYPE, &function_body(&[7, 9], 0x60)),
        ];
        let payload = vctp_payload(&entries, &[2]);
        let (table, data) = fixture(1, &payload);
        let pattern = read_pattern(&table, 0, &data, (0, 0), (0, 20)).unwrap();
        assert_eq!(pattern, Some((0x60u16 >> 3) as u8));
    }

    #[test]
    fn skips_known_pane_less_type_descriptors() {
        for obj_type in [POLY_VI_TYPE, CLUSTER_TYPE] {
            let payload = vctp_payload(&[td_entry(obj_type, &[])], &[0]);
            let (table, data) = fixture(1, &payload);
            assert_eq!(
                read_pattern(&table, 0, &data, (0, 0), (0, 20)).unwrap(),
                None
            );
        }
    }

    #[test]
    fn rejects_out_of_range_or_zero_conp_type_id() {
        let entries = vec![td_entry(FUNCTION_TYPE, &function_body(&[], 0x08))];
        let payload = vctp_payload(&entries, &[0]);
        for conp_type_id in [0u16, 2] {
            let (table, data) = fixture(conp_type_id, &payload);
            assert!(read_pattern(&table, 0, &data, (0, 0), (0, 20)).is_err());
        }
    }

    #[test]
    fn rejects_a_typedesc_that_is_not_a_function_type() {
        let entries = vec![td_entry(0x01, &[0, 0, 0, 0])];
        let payload = vctp_payload(&entries, &[0]);
        let (table, data) = fixture(1, &payload);
        assert!(read_pattern(&table, 0, &data, (0, 0), (0, 20)).is_err());
    }

    #[test]
    fn rejects_a_pattern_code_outside_the_36_known_patterns() {
        let entries = vec![td_entry(FUNCTION_TYPE, &function_body(&[], 36 * 8))];
        let payload = vctp_payload(&entries, &[0]);
        let (table, data) = fixture(1, &payload);
        assert!(read_pattern(&table, 0, &data, (0, 0), (0, 20)).is_err());
    }

    #[test]
    fn rejects_inconsistent_or_truncated_compressed_data() {
        let entries = vec![td_entry(FUNCTION_TYPE, &function_body(&[], 0x08))];
        let payload = vctp_payload(&entries, &[0]);
        let (table, mut data) = fixture(1, &payload);
        let last = data.len() - 1;
        data[last] ^= 0xff;
        assert!(read_pattern(&table, 0, &data, (0, 0), (0, 20)).is_err());
    }
}
