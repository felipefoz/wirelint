//! Minimal bounded RSRC format-3 reader for VI settings and analysis facts.
//!
//! Offsets and bit semantics were researched using pylabview; see
//! THIRD_PARTY_NOTICES.md. No compiled-code blocks are interpreted or executed.

use super::{FileFacts, Version, invalid};
use std::io;
use std::path::PathBuf;

#[cfg(test)]
pub(super) fn read_facts(
    bytes: &[u8],
    read_version: bool,
    read_description: bool,
) -> io::Result<FileFacts> {
    read_facts_with_password(bytes, read_version, read_description, false)
}

/// Extracts VI settings and requested description/password facts.
///
/// Only format 3, LBVW-created VI/control resources with one LVSR section are
/// supported. Missing, ambiguous, or out-of-bounds requested records return
/// an error.
#[cfg(test)]
pub(super) fn read_facts_with_password(
    bytes: &[u8],
    read_version: bool,
    read_description: bool,
    read_password: bool,
) -> io::Result<FileFacts> {
    read_facts_with_orphaned_vi(
        bytes,
        read_version,
        read_description,
        read_password,
        false,
        false,
        false,
    )
    .map(|(facts, _)| facts)
}

#[cfg(test)]
pub(super) fn read_facts_with_connector_pane_pattern(
    bytes: &[u8],
    read_connector_pane_pattern: bool,
) -> io::Result<FileFacts> {
    read_facts_with_orphaned_vi(
        bytes,
        false,
        false,
        false,
        false,
        read_connector_pane_pattern,
        false,
    )
    .map(|(facts, _)| facts)
}

/// Extracts an owning-library path when orphaned-VI analysis is requested.
pub(super) fn read_facts_with_orphaned_vi(
    bytes: &[u8],
    read_version: bool,
    read_description: bool,
    read_password: bool,
    read_orphaned_vi: bool,
    read_connector_pane_pattern: bool,
    read_default_strings: bool,
) -> io::Result<(FileFacts, Vec<Vec<u8>>)> {
    let first_header = slice(bytes, 0, 32)?;
    let mut header_offset = 0;
    let header = loop {
        let header = slice(bytes, header_offset, 32)?;
        if &header[..6] != b"RSRC\r\n"
            || &header[6..8] != b"\0\x03"
            || &header[12..16] != b"LBVW"
            || !matches!(&header[8..12], b"LVIN" | b"LVCC" | b"sVIN" | b"sVCC")
        {
            return Err(invalid("unsupported RSRC signature, version, or file type"));
        }
        if header[..16] != first_header[..16] || header[20..] != first_header[20..] {
            return Err(invalid("inconsistent RSRC headers"));
        }
        let next = number(header, 16)?;
        if next == header_offset {
            break header;
        }
        if next < header_offset + 32 {
            return Err(invalid("invalid RSRC header chain"));
        }
        header_offset = next;
    };

    let info = slice(bytes, header_offset, number(header, 20)?)?;
    let data_offset = number(header, 24)?;
    if data_offset < 32 {
        return Err(invalid("RSRC data overlaps the file header"));
    }
    let data = slice(bytes, data_offset, number(header, 28)?)?;
    if data_offset + data.len() > header_offset {
        return Err(invalid("RSRC data overlaps resource metadata"));
    }
    let list_header = slice(info, 32, 20)?;
    if number(list_header, 8)? != 32 {
        return Err(invalid("unsupported RSRC block-info header size"));
    }
    let table_offset = number(list_header, 12)?;
    if table_offset < 52 {
        return Err(invalid("invalid RSRC block table offset"));
    }
    let table = slice(info, table_offset, info.len().saturating_sub(table_offset))?;
    let count = number(table, 0)?
        .checked_add(1)
        .ok_or_else(|| invalid("RSRC block count overflow"))?;
    let table_size = count
        .checked_mul(12)
        .and_then(|size| size.checked_add(4))
        .ok_or_else(|| invalid("RSRC block table size overflow"))?;
    slice(table, 0, table_size)?;

    let mut separate_compiled_code = None;
    let mut file_version = None;
    let mut saved_version = None;
    let mut debugging_enabled = None;
    let mut has_breakpoints = None;
    let mut auto_error_handling = None;
    let is_vi = matches!(&header[8..12], b"LVIN" | b"sVIN");
    let mut has_password = (read_password && is_vi).then_some(false);
    let mut bdpw_seen = false;
    let mut strg = None;
    let mut li_vi_seen = false;
    let mut linked_library = None;
    let mut bookmarks = Vec::new();
    let mut diagram_string_values = Vec::new();
    let mut diagram_seen = false;
    let mut terminal_icon_styles = is_vi.then(Vec::new);
    let mut conp_seen = false;
    let mut conp_section = None;
    let mut vctp_seen = false;
    let mut vctp_section = None;
    let mut fphb_seen = false;
    let mut control_defaults = None;
    let mut dthp_seen = false;
    let mut dthp_section = None;
    for block in table[4..table_size].as_chunks::<12>().0 {
        if &block[..4] == b"LVSR" {
            if separate_compiled_code.is_some() || number(block, 4)? != 0 {
                return Err(invalid("expected exactly one LVSR block and section"));
            }
            let section_offset = number(block, 8)?;
            if section_offset < table_size {
                return Err(invalid("LVSR section overlaps the block table"));
            }
            let section = slice(table, section_offset, 20)?;
            if number(section, 0)? != 0 {
                return Err(invalid("unsupported LVSR section index"));
            }
            let payload_offset = number(section, 12)?;
            let record = slice(
                data,
                payload_offset,
                data.len().saturating_sub(payload_offset),
            )?;
            let payload = slice(record, 4, number(record, 0)?)?;
            if payload.len() < 68 {
                return Err(invalid("truncated LVSR save record"));
            }
            let vi_flags2 = number(payload, 8)?;
            separate_compiled_code = Some(vi_flags2 & (1 << 10) != 0);
            if is_vi {
                let instrument_state = number(payload, 24)?;
                debugging_enabled = Some(instrument_state & (1 << 9) != 0);
                has_breakpoints = Some(instrument_state & 0x2000_0000 != 0);
                auto_error_handling = Some(vi_flags2 & 0x2000_0000 != 0);
            }
            if read_version || read_description || read_default_strings {
                let word = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let version = Version::from_word(word)?;
                file_version = Some(version);
                if read_version {
                    saved_version = Some(version);
                }
            }
        } else if is_vi && &block[..4] == b"BDHb" {
            if diagram_seen {
                return Err(invalid("duplicate BDHb block diagram"));
            }
            diagram_seen = true;
            let diagram = super::heap::read_bdhb(
                table,
                table_size,
                data,
                number(block, 4)?,
                number(block, 8)?,
                read_default_strings,
            )?;
            bookmarks = diagram.bookmarks;
            terminal_icon_styles = Some(diagram.terminal_icon_styles);
            diagram_string_values = diagram.string_constants;
        } else if is_vi && matches!(&block[..4], b"BDHP" | b"BDHc") {
            return Err(invalid(
                "unsupported block diagram heap format for bookmark extraction",
            ));
        } else if read_password && is_vi && &block[..4] == b"BDPW" {
            if bdpw_seen {
                return Err(invalid("duplicate BDPW password block"));
            }
            bdpw_seen = true;
            has_password = Some(read_bdpw_password(
                table,
                table_size,
                data,
                number(block, 4)?,
                number(block, 8)?,
            )?);
        } else if read_description && &block[..4] == b"STRG" {
            if strg.is_some() {
                return Err(invalid("duplicate STRG description block"));
            }
            strg = Some((number(block, 4)?, number(block, 8)?));
        } else if read_orphaned_vi && is_vi && &block[..4] == b"LIvi" {
            if li_vi_seen {
                return Err(invalid("duplicate LIvi library-link block"));
            }
            li_vi_seen = true;
            linked_library = read_vi_library_link(
                table,
                table_size,
                data,
                number(block, 4)?,
                number(block, 8)?,
            )?;
        } else if read_connector_pane_pattern && is_vi && &block[..4] == b"CONP" {
            if conp_seen {
                return Err(invalid("duplicate CONP connector pane block"));
            }
            conp_seen = true;
            conp_section = Some((number(block, 4)?, number(block, 8)?));
        } else if (read_connector_pane_pattern || read_default_strings)
            && is_vi
            && &block[..4] == b"VCTP"
        {
            if vctp_seen {
                return Err(invalid("duplicate VCTP consolidated type pool block"));
            }
            vctp_seen = true;
            vctp_section = Some((number(block, 4)?, number(block, 8)?));
        } else if read_default_strings && is_vi && &block[..4] == b"FPHb" {
            if fphb_seen {
                return Err(invalid("duplicate FPHb front-panel heap"));
            }
            fphb_seen = true;
            control_defaults = Some(super::heap::read_fphb(
                table,
                table_size,
                data,
                number(block, 4)?,
                number(block, 8)?,
            )?);
        } else if read_default_strings && is_vi && matches!(&block[..4], b"FPHP" | b"FPHc") {
            return Err(invalid(
                "unsupported front-panel heap format for default-value extraction",
            ));
        } else if read_default_strings && is_vi && &block[..4] == b"DTHP" {
            if dthp_seen {
                return Err(invalid("duplicate DTHP heap type slice"));
            }
            dthp_seen = true;
            dthp_section = Some((number(block, 4)?, number(block, 8)?));
        }
    }
    let separate_compiled_code =
        separate_compiled_code.ok_or_else(|| invalid("missing LVSR save record"))?;
    let has_description = if read_description {
        Some(match strg {
            Some((section_count_minus_one, section_offset)) => read_strg_description(
                table,
                table_size,
                data,
                section_count_minus_one,
                section_offset,
                file_version.ok_or_else(|| invalid("missing LVSR version for STRG description"))?,
            )?,
            None => false,
        })
    } else {
        None
    };
    let connector_pane_pattern = if read_connector_pane_pattern && is_vi {
        let conp = conp_section.ok_or_else(|| invalid("missing CONP connector pane block"))?;
        let vctp =
            vctp_section.ok_or_else(|| invalid("missing VCTP consolidated type pool block"))?;
        super::connector::read_pattern(table, table_size, data, conp, vctp)?
    } else {
        None
    };
    let default_string_values = if read_default_strings && is_vi {
        let controls = control_defaults.ok_or_else(|| invalid("missing FPHb front-panel heap"))?;
        if controls.is_empty() {
            Some(Vec::new())
        } else {
            let version = file_version
                .ok_or_else(|| invalid("missing LVSR version for default-value decoding"))?;
            let dthp = super::typed_data::read_dthp(
                table,
                table_size,
                data,
                dthp_section.ok_or_else(|| invalid("missing DTHP heap type slice"))?,
            )?;
            let vctp =
                vctp_section.ok_or_else(|| invalid("missing VCTP consolidated type pool"))?;
            let types = super::connector::read_vctp(table, table_size, data, vctp)
                .map_err(|error| invalid(format!("VCTP type pool: {error}")))?;
            Some(super::typed_data::read_default_strings(
                &types, dthp, &controls, version,
            )?)
        }
    } else {
        None
    };
    Ok((
        FileFacts {
            separate_compiled_code,
            has_description,
            saved_version,
            debugging_enabled,
            has_breakpoints,
            auto_error_handling,
            has_password,
            linked_library,
            library_members: None,
            orphaned_vi: None,
            has_mutation_history: None,
            terminal_icon_styles,
            connector_pane_pattern,
            default_string_values,
            diagram_string_values: (read_default_strings && is_vi).then_some(diagram_string_values),
        },
        bookmarks,
    ))
}

/// Reads the owning `.lvlib` path from the VI's `VILB` entry in its `LIvi` table.
fn read_vi_library_link(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    section_count_minus_one: usize,
    section_offset: usize,
) -> io::Result<Option<PathBuf>> {
    let section_count = section_count_minus_one
        .checked_add(1)
        .ok_or_else(|| invalid("LIvi section count overflow"))?;
    let section_table_size = section_count
        .checked_mul(20)
        .ok_or_else(|| invalid("LIvi section table size overflow"))?;
    if section_offset < table_size {
        return Err(invalid("LIvi section overlaps the block table"));
    }
    let sections = slice(table, section_offset, section_table_size)?;
    let mut library_path = None;
    let mut section_zero_seen = false;
    for section in sections.as_chunks::<20>().0 {
        if number(section, 0)? != 0 {
            continue;
        }
        if section_zero_seen {
            return Err(invalid("duplicate LIvi section 0"));
        }
        section_zero_seen = true;
        let record_offset = number(section, 12)?;
        let record = slice(
            data,
            record_offset,
            data.len().saturating_sub(record_offset),
        )?;
        let payload = slice(record, 4, number(record, 0)?)?;
        if let Some(path) = read_vilb_path(payload)?
            && library_path.replace(path).is_some()
        {
            return Err(invalid("multiple owning-library paths in LIvi"));
        }
    }
    if !section_zero_seen {
        return Err(invalid("missing LIvi section 0"));
    }
    Ok(library_path)
}

/// Finds the VI-relative PTH0 owner path, translating empty components to `..`.
fn read_vilb_path(payload: &[u8]) -> io::Result<Option<PathBuf>> {
    let mut vilb = None;
    for (offset, tag) in payload.windows(4).enumerate() {
        if tag == b"VILB" && vilb.replace(offset).is_some() {
            return Err(invalid("multiple VILB entries in LIvi"));
        }
    }
    let Some(vilb) = vilb else {
        return Ok(None);
    };
    let path_tag = payload[vilb + 4..]
        .windows(4)
        .position(|tag| tag == b"PTH0")
        .map(|offset| vilb + 4 + offset)
        .ok_or_else(|| invalid("VILB entry is missing its PTH0 path"))?;
    let (path_type, components) = read_pth0(payload, path_tag)?;
    if path_type != 1 || components.is_empty() {
        return Ok(None);
    }
    let mut path = PathBuf::new();
    for component in components {
        path.push(if component.is_empty() {
            ".."
        } else {
            &component
        });
    }
    Ok(Some(path))
}

/// Decodes a bounded PTH0 record without interpreting absolute/token paths.
fn read_pth0(payload: &[u8], offset: usize) -> io::Result<(u16, Vec<String>)> {
    if slice(payload, offset, 4)? != b"PTH0" {
        return Err(invalid("expected PTH0 path record"));
    }
    let length = number(payload, offset + 4)?;
    if length < 4 {
        return Err(invalid("invalid PTH0 path length"));
    }
    let record_end = offset
        .checked_add(8)
        .and_then(|start| start.checked_add(length))
        .ok_or_else(|| invalid("PTH0 path range overflow"))?;
    slice(payload, offset, record_end - offset)?;
    let header = slice(payload, offset + 8, 4)?;
    let path_type = u16::from_be_bytes([header[0], header[1]]);
    let component_count = u16::from_be_bytes([header[2], header[3]]) as usize;
    if component_count > 128 {
        return Err(invalid("too many PTH0 path components"));
    }
    let mut cursor = offset + 12;
    let mut components = Vec::with_capacity(component_count);
    for _ in 0..component_count {
        let component_length = slice(payload, cursor, 1)?[0] as usize;
        cursor += 1;
        let component = slice(payload, cursor, component_length)?;
        cursor += component_length;
        let text = std::str::from_utf8(component)
            .map(str::to_owned)
            .unwrap_or_else(|_| component.iter().map(|byte| char::from(*byte)).collect());
        components.push(text);
    }
    if cursor != record_end {
        return Err(invalid("inconsistent PTH0 path length"));
    }
    Ok((path_type, components))
}

/// Reads the BDPW hash list without retaining or exposing password material.
fn read_bdpw_password(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    section_count_minus_one: usize,
    section_offset: usize,
) -> io::Result<bool> {
    let section_count = section_count_minus_one
        .checked_add(1)
        .ok_or_else(|| invalid("BDPW section count overflow"))?;
    if section_count != 1 {
        return Err(invalid("unsupported BDPW section count"));
    }
    if section_offset < table_size {
        return Err(invalid("BDPW section overlaps the block table"));
    }
    let section = slice(table, section_offset, 20)?;
    if number(section, 0)? != 0 {
        return Err(invalid("unsupported BDPW section index"));
    }
    let record_offset = number(section, 12)?;
    let record = slice(
        data,
        record_offset,
        data.len().saturating_sub(record_offset),
    )?;
    let hashes = slice(record, 4, number(record, 0)?)?;
    if hashes.len() < 16 || hashes.len() % 16 != 0 {
        return Err(invalid("invalid BDPW password hash list"));
    }

    const EMPTY_PASSWORD_HASH: [u8; 16] = [
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42,
        0x7e,
    ];
    Ok(hashes[..16] != EMPTY_PASSWORD_HASH)
}

/// Reads the first STRG string, which stores the owning VI's description.
fn read_strg_description(
    table: &[u8],
    table_size: usize,
    data: &[u8],
    section_count_minus_one: usize,
    section_offset: usize,
    version: Version,
) -> io::Result<bool> {
    let section_count = section_count_minus_one
        .checked_add(1)
        .ok_or_else(|| invalid("STRG section count overflow"))?;
    let section_table_size = section_count
        .checked_mul(20)
        .ok_or_else(|| invalid("STRG section table size overflow"))?;
    if section_offset < table_size {
        return Err(invalid("STRG section overlaps the block table"));
    }
    let sections = slice(table, section_offset, section_table_size)?;
    let mut description_section = None;
    for section in sections.as_chunks::<20>().0 {
        if number(section, 0)? == 0 {
            if description_section.is_some() {
                return Err(invalid("duplicate STRG description section"));
            }
            description_section = Some(section);
        }
    }
    let section = description_section.ok_or_else(|| invalid("missing STRG section 0"))?;
    let record_offset = number(section, 12)?;
    let record = slice(
        data,
        record_offset,
        data.len().saturating_sub(record_offset),
    )?;
    let payload = slice(record, 4, number(record, 0)?)?;

    let (count_size, length_size) = if version.major >= 4 { (0, 4) } else { (4, 1) };
    let string_count = if count_size == 0 {
        1
    } else {
        number(payload, 0)?
    };
    if string_count == 0 {
        return Ok(false);
    }
    if string_count > payload.len().saturating_sub(count_size) / length_size {
        return Err(invalid("truncated STRG string list"));
    }
    let description_length = if length_size == 4 {
        number(payload, count_size)?
    } else {
        slice(payload, count_size, length_size)?[0] as usize
    };
    let description_offset = count_size + length_size;
    let description = slice(payload, description_offset, description_length)?;
    Ok(description
        .iter()
        .any(|byte| !byte.is_ascii_whitespace() && *byte != 0xca))
}

/// Returns a bounded byte range, rejecting overflow and truncated resources.
pub(super) fn slice(bytes: &[u8], offset: usize, length: usize) -> io::Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("RSRC range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("RSRC range is outside its containing region"))
}

/// Reads one big-endian unsigned word as a checked host offset.
pub(super) fn number(bytes: &[u8], offset: usize) -> io::Result<usize> {
    let word = slice(bytes, offset, 4)?;
    usize::try_from(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
        .map_err(|_| invalid("RSRC offset is too large for this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic two-block RSRC with an unrelated block before LVSR.
    fn fixture(flags: u32) -> Vec<u8> {
        let data_size = 72;
        let info_offset = 32 + data_size;
        let info_size = 52 + 4 + 24 + 40;
        let mut bytes = vec![0; info_offset + info_size];
        for base in [0, info_offset] {
            bytes[base..base + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
            put(&mut bytes, base + 16, info_offset as u32);
            put(&mut bytes, base + 20, info_size as u32);
            put(&mut bytes, base + 24, 32);
            put(&mut bytes, base + 28, data_size as u32);
        }
        put(&mut bytes, 32, 68);
        put(&mut bytes, 36, 0x15008000);
        put(&mut bytes, 44, flags);
        put(&mut bytes, info_offset + 40, 32);
        put(&mut bytes, info_offset + 44, 52);
        put(&mut bytes, info_offset + 48, info_size as u32);
        let table = info_offset + 52;
        put(&mut bytes, table, 1);
        bytes[table + 4..table + 8].copy_from_slice(b"TEST");
        put(&mut bytes, table + 12, 28);
        bytes[table + 16..table + 20].copy_from_slice(b"LVSR");
        put(&mut bytes, table + 24, 48);
        put(&mut bytes, table + 48 + 4, u32::MAX);
        bytes
    }

    fn fixture_with_bdpw(hashes: &[u8]) -> Vec<u8> {
        let data_size = 72 + 4 + hashes.len();
        let info_offset = 32 + data_size;
        let info_size = 52 + 4 + 24 + 40;
        let mut bytes = vec![0; info_offset + info_size];
        for base in [0, info_offset] {
            bytes[base..base + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
            put(&mut bytes, base + 16, info_offset as u32);
            put(&mut bytes, base + 20, info_size as u32);
            put(&mut bytes, base + 24, 32);
            put(&mut bytes, base + 28, data_size as u32);
        }
        put(&mut bytes, 32, 68);
        put(&mut bytes, 36, 0x15008000);
        put(&mut bytes, 44, 1 << 10);
        let bdpw_record = 32 + 72;
        put(&mut bytes, bdpw_record, hashes.len() as u32);
        bytes[bdpw_record + 4..bdpw_record + 4 + hashes.len()].copy_from_slice(hashes);

        put(&mut bytes, info_offset + 40, 32);
        put(&mut bytes, info_offset + 44, 52);
        put(&mut bytes, info_offset + 48, info_size as u32);
        let table = info_offset + 52;
        put(&mut bytes, table, 1);
        bytes[table + 4..table + 8].copy_from_slice(b"LVSR");
        put(&mut bytes, table + 12, 28);
        bytes[table + 16..table + 20].copy_from_slice(b"BDPW");
        put(&mut bytes, table + 24, 48);
        put(&mut bytes, table + 40 + 4, u32::MAX);
        put(&mut bytes, table + 48 + 4, u32::MAX);
        put(&mut bytes, table + 48 + 12, 72);
        bytes
    }

    /// Adds a format-4+ STRG section containing its first string.
    fn fixture_with_strg(flags: u32, description: &[u8]) -> Vec<u8> {
        let strg_payload_size = 4 + description.len();
        let data_size = 72 + 4 + strg_payload_size;
        let info_size = 52 + 4 + 36 + 60;
        let info_offset = 32 + data_size;
        let mut bytes = vec![0; info_offset + info_size];
        for base in [0, info_offset] {
            bytes[base..base + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
            put(&mut bytes, base + 16, info_offset as u32);
            put(&mut bytes, base + 20, info_size as u32);
            put(&mut bytes, base + 24, 32);
            put(&mut bytes, base + 28, data_size as u32);
        }
        put(&mut bytes, 32, 68);
        put(&mut bytes, 36, 0x20008000);
        put(&mut bytes, 44, flags);
        let strg_record = 32 + 72;
        put(&mut bytes, strg_record, strg_payload_size as u32);
        put(&mut bytes, strg_record + 4, description.len() as u32);
        bytes[strg_record + 8..strg_record + 8 + description.len()].copy_from_slice(description);

        put(&mut bytes, info_offset + 40, 32);
        put(&mut bytes, info_offset + 44, 52);
        put(&mut bytes, info_offset + 48, info_size as u32);
        let table = info_offset + 52;
        put(&mut bytes, table, 2);
        bytes[table + 4..table + 8].copy_from_slice(b"TEST");
        put(&mut bytes, table + 12, 40);
        bytes[table + 16..table + 20].copy_from_slice(b"LVSR");
        put(&mut bytes, table + 24, 60);
        bytes[table + 28..table + 32].copy_from_slice(b"STRG");
        put(&mut bytes, table + 36, 80);
        for section in [table + 40, table + 60, table + 80] {
            put(&mut bytes, section + 4, u32::MAX);
        }
        put(&mut bytes, table + 92, 72);
        bytes
    }

    fn fixture_with_default_strings(diagram_value: Option<&[u8]>) -> Vec<u8> {
        fn node(heap: &mut Vec<u8>, tag: i32, scope: u8, class: Option<i16>, content: &[u8]) {
            let tag = (tag + 31) as u16;
            let size = if content.is_empty() { 0 } else { 6 };
            heap.push(
                (size << 5) | (u8::from(class.is_some()) << 4) | (scope << 2) | (tag >> 8) as u8,
            );
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
        let mut vi_payload = vec![0; 68];
        vi_payload[..4].copy_from_slice(&0x1400_8000u32.to_be_bytes());
        let vctp_payload = {
            let mut payload = 1u32.to_be_bytes().to_vec();
            payload.extend_from_slice(&[0, 8, 0, 0x30, 0xff, 0xff, 0xff, 0xff]);
            payload.extend_from_slice(&[0, 1, 0, 0]);
            payload
        };
        let mut heap = Vec::new();
        node(&mut heap, -6, 0, Some(18), &[]);
        node(&mut heap, 283, 1, None, &[1]);
        node(&mut heap, 52, 0, Some(81), &[]);
        node(&mut heap, 194, 0, None, &[]);
        node(&mut heap, -6, 0, Some(10), &[]);
        node(&mut heap, 192, 1, None, &[16]);
        node(&mut heap, 270, 0, Some(1), &[]);
        node(&mut heap, 3, 1, None, b"Password");
        node(&mut heap, 270, 2, None, &[]);
        node(&mut heap, -6, 2, None, &[]);
        node(&mut heap, 194, 2, None, &[]);
        node(&mut heap, 52, 2, None, &[]);
        node(&mut heap, 571, 1, None, b"\0\0\0\x08hunter22");
        node(&mut heap, -6, 2, None, &[]);
        let mut fphb_payload = (heap.len() as u32).to_be_bytes().to_vec();
        fphb_payload.extend_from_slice(&heap);
        let mut heap = Vec::new();
        node(&mut heap, -7, 0, Some(27), &[]);
        node(&mut heap, 48, 0, Some(19), &[]);
        node(&mut heap, 52, 0, Some(81), &[]);
        node(&mut heap, 194, 0, None, &[]);
        node(&mut heap, -6, 0, Some(10), &[]);
        node(&mut heap, 192, 1, None, &[16]);
        node(&mut heap, 270, 0, Some(1), &[]);
        node(&mut heap, 3, 1, None, b"API Key");
        node(&mut heap, 270, 2, None, &[]);
        node(&mut heap, -6, 2, None, &[]);
        node(&mut heap, 194, 2, None, &[]);
        node(&mut heap, 52, 2, None, &[]);
        if let Some(value) = diagram_value {
            node(&mut heap, 589, 1, None, value);
        }
        node(&mut heap, 48, 2, None, &[]);
        node(&mut heap, -7, 2, None, &[]);
        let mut bdhb_payload = (heap.len() as u32).to_be_bytes().to_vec();
        bdhb_payload.extend_from_slice(&heap);
        let mut dthp_payload = vec![0, 1, 0, 1];
        let records = [
            {
                let mut record = (vi_payload.len() as u32).to_be_bytes().to_vec();
                record.append(&mut vi_payload);
                record
            },
            {
                let coded = zlib_coded(&fphb_payload);
                let mut record = (coded.len() as u32).to_be_bytes().to_vec();
                record.extend_from_slice(&coded);
                record
            },
            {
                let mut record = (dthp_payload.len() as u32).to_be_bytes().to_vec();
                record.append(&mut dthp_payload);
                record
            },
            {
                let coded = zlib_coded(&vctp_payload);
                let mut record = (coded.len() as u32).to_be_bytes().to_vec();
                record.extend_from_slice(&coded);
                record
            },
            {
                let coded = zlib_coded(&bdhb_payload);
                let mut record = (coded.len() as u32).to_be_bytes().to_vec();
                record.extend_from_slice(&coded);
                record
            },
        ];
        let mut data = Vec::new();
        let mut data_offsets = Vec::new();
        for record in records {
            data_offsets.push(data.len());
            data.extend_from_slice(&record);
        }

        let table_header_size = 52;
        let block_count = 5;
        let table_size = 4 + 12 * block_count + 20 * block_count;
        let info_size = table_header_size + table_size;
        let info_offset = 32 + data.len();
        let mut bytes = vec![0; info_offset + info_size];
        for base in [0, info_offset] {
            bytes[base..base + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
            put(&mut bytes, base + 16, info_offset as u32);
            put(&mut bytes, base + 20, info_size as u32);
            put(&mut bytes, base + 24, 32);
            put(&mut bytes, base + 28, data.len() as u32);
        }
        bytes[32..32 + data.len()].copy_from_slice(&data);
        put(&mut bytes, info_offset + 40, 32);
        put(&mut bytes, info_offset + 44, table_header_size as u32);
        put(&mut bytes, info_offset + 48, info_size as u32);
        let table = info_offset + table_header_size;
        put(&mut bytes, table, (block_count - 1) as u32);
        let names = [b"LVSR", b"FPHb", b"DTHP", b"VCTP", b"BDHb"];
        for index in 0..block_count {
            let block = table + 4 + 12 * index;
            bytes[block..block + 4].copy_from_slice(names[index]);
            put(
                &mut bytes,
                block + 8,
                (4 + 12 * block_count + 20 * index) as u32,
            );
            let section = table + 4 + 12 * block_count + 20 * index;
            put(&mut bytes, section + 12, data_offsets[index] as u32);
        }
        bytes
    }

    /// Zlib-codes a payload the way `BLOCK_CODING.ZLIB` sections are stored:
    /// a 4-byte decompressed length, then a raw zlib stream.
    fn zlib_coded(payload: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut coded = (payload.len() as u32).to_be_bytes().to_vec();
        coded.extend_from_slice(&compressed);
        coded
    }

    /// Builds a one-entry VCTP payload (flat `Function` TypeDesc, then a
    /// one-entry top-level list) carrying the given raw connector pane pattern.
    fn connector_pane_vctp_payload(pattern: u16) -> Vec<u8> {
        let mut function_body = 0u16.to_be_bytes().to_vec(); // zero clients
        function_body.extend_from_slice(&0u16.to_be_bytes()); // fflags
        function_body.extend_from_slice(&pattern.to_be_bytes());

        let mut entry = ((4 + function_body.len()) as u16).to_be_bytes().to_vec();
        entry.push(0); // flags
        entry.push(0xF0); // TD_FULL_TYPE::Function
        entry.extend_from_slice(&function_body);

        let mut payload = 1u32.to_be_bytes().to_vec(); // one flat TypeDesc
        payload.extend_from_slice(&entry);
        payload.extend_from_slice(&1u16.to_be_bytes()); // one top-level entry
        payload.extend_from_slice(&0u16.to_be_bytes()); // -> FlatTypeID 0
        payload
    }

    /// Builds a VI/control RSRC with an `LVSR` block and, after it, `CONP`
    /// (pointing at type index 1) and `VCTP` blocks describing one connector
    /// pane pattern.
    fn fixture_with_connector_pane(pattern: u16) -> Vec<u8> {
        let conp_payload = 1u16.to_be_bytes();
        let vctp_coded = zlib_coded(&connector_pane_vctp_payload(pattern));

        let conp_data_offset = 72;
        let vctp_data_offset = conp_data_offset + 4 + conp_payload.len();
        let data_size = vctp_data_offset + 4 + vctp_coded.len();
        let info_size = 52 + 4 + 36 + 60;
        let info_offset = 32 + data_size;
        let mut bytes = vec![0; info_offset + info_size];
        for base in [0, info_offset] {
            bytes[base..base + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
            put(&mut bytes, base + 16, info_offset as u32);
            put(&mut bytes, base + 20, info_size as u32);
            put(&mut bytes, base + 24, 32);
            put(&mut bytes, base + 28, data_size as u32);
        }
        put(&mut bytes, 32, 68);
        put(&mut bytes, 36, 0x20008000);

        let conp_abs = 32 + conp_data_offset;
        put(&mut bytes, conp_abs, conp_payload.len() as u32);
        bytes[conp_abs + 4..conp_abs + 4 + conp_payload.len()].copy_from_slice(&conp_payload);

        let vctp_abs = 32 + vctp_data_offset;
        put(&mut bytes, vctp_abs, vctp_coded.len() as u32);
        bytes[vctp_abs + 4..vctp_abs + 4 + vctp_coded.len()].copy_from_slice(&vctp_coded);

        put(&mut bytes, info_offset + 40, 32);
        put(&mut bytes, info_offset + 44, 52);
        put(&mut bytes, info_offset + 48, info_size as u32);
        let table = info_offset + 52;
        put(&mut bytes, table, 2);
        bytes[table + 4..table + 8].copy_from_slice(b"LVSR");
        put(&mut bytes, table + 12, 40);
        bytes[table + 16..table + 20].copy_from_slice(b"CONP");
        put(&mut bytes, table + 24, 60);
        bytes[table + 28..table + 32].copy_from_slice(b"VCTP");
        put(&mut bytes, table + 36, 80);
        put(&mut bytes, table + 60 + 12, conp_data_offset as u32);
        put(&mut bytes, table + 80 + 12, vctp_data_offset as u32);
        bytes
    }

    fn put(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn reads_the_flag_not_the_presence_of_compiled_blocks() {
        for flags in [0, 1 << 9, 1 << 10, u32::MAX] {
            assert_eq!(
                read_facts(&fixture(flags), true, false)
                    .unwrap()
                    .separate_compiled_code,
                flags & (1 << 10) != 0
            );
        }
        for extension in ["vi", "VIT", "vim", "ctl"] {
            assert!(
                super::super::read_facts(
                    std::path::Path::new(&format!("file.{extension}")),
                    &fixture(1 << 10),
                    true,
                    false,
                    false,
                )
                .unwrap()
                .separate_compiled_code
            );
        }
    }

    #[test]
    fn reads_vi_control_and_template_resource_types() {
        for kind in [b"LVIN", b"LVCC", b"sVIN", b"sVCC"] {
            let mut bytes = fixture(1 << 10);
            for offset in [8, 104 + 8] {
                bytes[offset..offset + 4].copy_from_slice(kind);
            }
            assert!(
                read_facts(&bytes, true, false)
                    .unwrap()
                    .separate_compiled_code
            );
        }
    }

    #[test]
    fn reads_debug_capable_bit_without_conflating_other_instrument_state_bits() {
        for (state, expected) in [
            (0, false),
            (1 << 9, true),
            (1 << 30, false),
            (0x40000200, true),
            (!(1 << 9), false),
        ] {
            for kind in [b"LVIN", b"sVIN", b"LVCC", b"sVCC"] {
                let mut bytes = fixture(1 << 10);
                put(&mut bytes, 36 + 24, state);
                for offset in [8, 104 + 8] {
                    bytes[offset..offset + 4].copy_from_slice(kind);
                }
                assert_eq!(
                    read_facts(&bytes, false, false).unwrap().debugging_enabled,
                    matches!(kind, b"LVIN" | b"sVIN").then_some(expected),
                    "{kind:?}, {state:#x}"
                );
            }
        }
    }

    #[test]
    fn reads_breakpoints_set_flag_without_conflating_other_instrument_state_bits() {
        for (state, expected) in [
            (0, false),
            (1 << 9, false),
            (0x2000_0000, true),
            (0x4000_0000, false),
        ] {
            for kind in [b"LVIN", b"sVIN", b"LVCC", b"sVCC"] {
                let mut bytes = fixture(1 << 10);
                put(&mut bytes, 36 + 24, state);
                for offset in [8, 104 + 8] {
                    bytes[offset..offset + 4].copy_from_slice(kind);
                }
                assert_eq!(
                    read_facts(&bytes, false, false).unwrap().has_breakpoints,
                    matches!(kind, b"LVIN" | b"sVIN").then_some(expected),
                    "{kind:?}, {state:#x}"
                );
            }
        }
    }

    #[test]
    fn reads_auto_error_handling_flag_only_for_vi_resources() {
        for (flags, expected) in [(0, false), (1 << 10, false), (0x2000_0000, true)] {
            for kind in [b"LVIN", b"sVIN", b"LVCC", b"sVCC"] {
                let mut bytes = fixture(flags);
                for offset in [8, 104 + 8] {
                    bytes[offset..offset + 4].copy_from_slice(kind);
                }
                assert_eq!(
                    read_facts(&bytes, false, false)
                        .unwrap()
                        .auto_error_handling,
                    matches!(kind, b"LVIN" | b"sVIN").then_some(expected),
                    "{kind:?}, {flags:#x}"
                );
            }
        }
    }

    #[test]
    fn reads_password_presence_from_bdpw_hashes_only_for_vi_resources() {
        let empty_password_hash = [
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        let password_hash = [0x01; 16];
        assert_eq!(
            read_facts_with_password(&fixture(0), false, false, true)
                .unwrap()
                .has_password,
            Some(false)
        );
        assert_eq!(
            read_facts_with_password(&fixture_with_bdpw(&empty_password_hash), false, false, true)
                .unwrap()
                .has_password,
            Some(false)
        );
        assert_eq!(
            read_facts_with_password(&fixture_with_bdpw(&password_hash), false, false, true)
                .unwrap()
                .has_password,
            Some(true)
        );

        for kind in [b"LVIN", b"sVIN", b"LVCC", b"sVCC"] {
            let mut bytes = fixture_with_bdpw(&password_hash);
            for offset in [8, 124 + 8] {
                bytes[offset..offset + 4].copy_from_slice(kind);
            }
            assert_eq!(
                read_facts_with_password(&bytes, false, false, true)
                    .unwrap()
                    .has_password,
                matches!(kind, b"LVIN" | b"sVIN").then_some(true),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn rejects_malformed_bdpw_only_when_password_check_is_requested() {
        let malformed = fixture_with_bdpw(&[0x01; 15]);
        assert!(read_facts_with_password(&malformed, false, false, true).is_err());
        assert!(read_facts_with_password(&malformed, false, false, false).is_ok());
    }

    #[test]
    fn rejects_every_truncated_prefix_without_panicking() {
        let bytes = fixture(1 << 10);
        for length in 0..bytes.len() {
            assert!(read_facts(&bytes[..length], true, false).is_err());
        }
    }

    #[test]
    fn rejects_missing_ambiguous_and_invalid_resource_records() {
        let original = fixture(1 << 10);
        let table = 104 + 52;
        for (offset, value) in [
            (16, u32::MAX),
            (20, 1),
            (24, 0),
            (28, u32::MAX),
            (104 + 16, 0),
            (104 + 44, u32::MAX),
            (table, u32::MAX),
            (table + 16, u32::from_be_bytes(*b"NONE")),
            (table + 4, u32::from_be_bytes(*b"LVSR")),
            (table + 20, 1),
            (table + 24, 0),
            (table + 48, 1),
            (table + 60, u32::MAX),
            (32, 11),
            (32, u32::MAX),
        ] {
            let mut bytes = original.clone();
            put(&mut bytes, offset, value);
            assert!(read_facts(&bytes, true, false).is_err(), "offset {offset}");
        }
        let mut unsupported = original;
        unsupported[7] = 2;
        assert!(read_facts(&unsupported, true, false).is_err());
    }

    #[test]
    fn reads_version_digits_from_the_save_record() {
        for (word, expected) in [
            (
                0x19008000,
                Version {
                    major: 19,
                    minor: 0,
                },
            ),
            (
                0x20008000,
                Version {
                    major: 20,
                    minor: 0,
                },
            ),
            (
                0x21318000,
                Version {
                    major: 21,
                    minor: 3,
                },
            ),
        ] {
            let mut bytes = fixture(0);
            put(&mut bytes, 36, word);
            assert_eq!(
                read_facts(&bytes, true, false).unwrap().saved_version,
                Some(expected)
            );
        }
        let mut bytes = fixture(0);
        put(&mut bytes, 36, 0x2a008000);
        assert!(read_facts(&bytes, true, false).is_err());
        assert!(read_facts(&bytes, false, false).is_ok());
    }

    #[test]
    fn reads_vi_description_from_the_first_strg_string() {
        assert_eq!(
            read_facts(&fixture_with_strg(0, b"VI description"), false, true)
                .unwrap()
                .has_description,
            Some(true)
        );
        for description in [b"".as_slice(), b" \t\r\n", b"\xca"] {
            assert_eq!(
                read_facts(&fixture_with_strg(0, description), false, true)
                    .unwrap()
                    .has_description,
                Some(false)
            );
        }
        assert_eq!(
            read_facts(&fixture(0), false, true)
                .unwrap()
                .has_description,
            Some(false)
        );
    }

    #[test]
    fn rejects_malformed_strg_but_skips_it_when_the_rule_is_inactive() {
        let mut bytes = fixture_with_strg(0, b"description");
        let description_length = 32 + 72 + 4;
        put(&mut bytes, description_length, u32::MAX);
        assert!(read_facts(&bytes, false, true).is_err());
        assert_eq!(
            read_facts(&bytes, false, false).unwrap().has_description,
            None
        );
    }

    #[test]
    fn reads_relative_owning_library_from_the_vi_link_table() {
        let facts = super::super::read_facts_with_orphaned_vi(
            std::path::Path::new("orphan-vi.vi"),
            &crate::test_support::vi_with_library_link("orphaned-example.lvlib"),
            false,
            false,
            false,
            true,
            false,
            false,
        )
        .unwrap();
        assert_eq!(
            facts.0.linked_library,
            Some(PathBuf::from("..").join("orphaned-example.lvlib"))
        );
        assert_eq!(
            super::super::read_facts_with_orphaned_vi(
                std::path::Path::new("ordinary.vi"),
                &fixture(1 << 10),
                false,
                false,
                false,
                true,
                false,
                false,
            )
            .unwrap()
            .0
            .linked_library,
            None
        );
    }

    #[test]
    fn reads_connector_pane_pattern_only_when_requested_and_only_for_vi_resources() {
        let bytes = fixture_with_connector_pane(0x78); // conId 4815, pattern index 15
        assert_eq!(
            read_facts_with_connector_pane_pattern(&bytes, true)
                .unwrap()
                .connector_pane_pattern,
            Some(15)
        );
        assert_eq!(
            read_facts_with_connector_pane_pattern(&bytes, false)
                .unwrap()
                .connector_pane_pattern,
            None
        );
        let mut control_bytes = bytes;
        let info_offset = u32::from_be_bytes(control_bytes[16..20].try_into().unwrap()) as usize;
        for offset in [8, info_offset + 8] {
            control_bytes[offset..offset + 4].copy_from_slice(b"LVCC");
        }
        assert_eq!(
            read_facts_with_connector_pane_pattern(&control_bytes, true)
                .unwrap()
                .connector_pane_pattern,
            None
        );
    }

    #[test]
    fn rejects_missing_connector_pane_blocks_only_when_requested() {
        let bytes = fixture(1 << 10);
        assert!(read_facts_with_connector_pane_pattern(&bytes, true).is_err());
        assert!(read_facts_with_connector_pane_pattern(&bytes, false).is_ok());
    }

    #[test]
    fn rejects_duplicate_connector_pane_blocks() {
        let mut bytes = fixture_with_connector_pane(0x08);
        let info_offset = u32::from_be_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let table = info_offset + 52;
        bytes[table + 28..table + 32].copy_from_slice(b"CONP");
        assert!(read_facts_with_connector_pane_pattern(&bytes, true).is_err());
    }

    #[test]
    fn reads_default_strings_only_when_requested() {
        let bytes = fixture_with_default_strings(Some(b"\0\0\0\x08abc12345"));
        assert!(
            super::super::read_facts_with_orphaned_vi(
                std::path::Path::new("ordinary.vi"),
                &bytes,
                false,
                false,
                false,
                false,
                false,
                false,
            )
            .is_ok()
        );
        let facts = super::super::read_facts_with_orphaned_vi(
            std::path::Path::new("defaults.vi"),
            &bytes,
            false,
            false,
            false,
            false,
            false,
            true,
        )
        .unwrap()
        .0;
        assert_eq!(
            facts.default_string_values,
            Some(vec![super::super::DefaultStringValue {
                type_index: 1,
                field_path: Vec::new(),
                labels: vec![b"Password".to_vec()],
                bytes: b"hunter22".to_vec(),
            }])
        );
        assert_eq!(
            facts.diagram_string_values,
            Some(vec![super::super::DiagramStringConstant {
                label: Some(b"API Key".to_vec()),
                bytes: b"abc12345".to_vec(),
            }])
        );
        let finding = crate::rules::sast::BUILT_INS[0]
            .check(&facts, None)
            .unwrap();
        assert!(finding.contains("\"Password\" (credential-named control)"));
        assert!(finding.contains("and 1 other value"));
        assert!(!finding.contains("hunter22"));
        assert!(!finding.contains("abc12345"));
        assert!(
            super::super::read_facts_with_orphaned_vi(
                std::path::Path::new("ordinary.vi"),
                &fixture(0),
                false,
                false,
                false,
                false,
                false,
                false,
            )
            .unwrap()
            .0
            .default_string_values
            .is_none()
        );
    }

    #[test]
    fn invalid_diagram_constant_is_an_error_only_when_requested() {
        let bytes = fixture_with_default_strings(None);
        let read = |requested| {
            super::super::read_facts_with_orphaned_vi(
                std::path::Path::new("defaults.vi"),
                &bytes,
                false,
                false,
                false,
                false,
                false,
                requested,
            )
        };
        assert!(read(false).is_ok());
        let error = read(true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("string constant has no ConstValue")
        );
    }
}
