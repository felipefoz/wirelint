//! Synthetic RSRC fixtures shared by parser and command-line tests.

use std::io::Write;

/// Builds the supported VI subset with LVSR settings and a relative LIvi owner.
///
/// `library` is a sibling library name of at most 255 UTF-8 bytes.
pub fn vi_with_library_link(library: &str) -> Vec<u8> {
    vi_with_library_path(&["", library])
}

/// Builds a VI with the supplied relative PTH0 owner path components.
///
/// Empty components ascend one level from the VI file. Each component must
/// fit in one byte of length; no LabVIEW installation is needed.
pub fn vi_with_library_path(components: &[&str]) -> Vec<u8> {
    let mut link = b"VILBPTH0".to_vec();
    let path_size: usize = components.iter().map(|component| 1 + component.len()).sum();
    link.extend_from_slice(&u32::try_from(4 + path_size).unwrap().to_be_bytes());
    link.extend_from_slice(&1u16.to_be_bytes());
    link.extend_from_slice(&u16::try_from(components.len()).unwrap().to_be_bytes());
    for component in components {
        link.push(u8::try_from(component.len()).expect("fixture path component is too long"));
        link.extend_from_slice(component.as_bytes());
    }

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&[0, 0, 0, 0]).unwrap();
    let mut panel = 4u32.to_be_bytes().to_vec();
    panel.extend(encoder.finish().unwrap());
    let panel_offset = 72 + 4 + link.len();
    let data_size = panel_offset + 4 + panel.len();
    let table_size = 4 + 3 * 12;
    let info_size = 52 + table_size + 3 * 20;
    let info_offset = 32 + data_size;
    let mut bytes = vec![0; info_offset + info_size];
    for header in [0, info_offset] {
        bytes[header..header + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
        put(&mut bytes, header + 16, info_offset as u32);
        put(&mut bytes, header + 20, info_size as u32);
        put(&mut bytes, header + 24, 32);
        put(&mut bytes, header + 28, data_size as u32);
    }

    put(&mut bytes, 32, 68);
    put(&mut bytes, 36, 0x20008000);
    put(&mut bytes, 44, 1 << 10);
    put(&mut bytes, 104, link.len() as u32);
    bytes[108..108 + link.len()].copy_from_slice(&link);
    put(&mut bytes, 32 + panel_offset, panel.len() as u32);
    bytes[36 + panel_offset..36 + panel_offset + panel.len()].copy_from_slice(&panel);

    put(&mut bytes, info_offset + 40, 32);
    put(&mut bytes, info_offset + 44, 52);
    put(&mut bytes, info_offset + 48, info_size as u32);
    let table = info_offset + 52;
    put(&mut bytes, table, 2);
    for (index, (id, offset)) in [(b"LVSR", 0), (b"LIvi", 72), (b"FPHb", panel_offset)]
        .iter()
        .enumerate()
    {
        let entry = table + 4 + index * 12;
        let section = table + table_size + index * 20;
        bytes[entry..entry + 4].copy_from_slice(*id);
        put(&mut bytes, entry + 8, (table_size + index * 20) as u32);
        put(&mut bytes, section + 4, u32::MAX);
        put(&mut bytes, section + 12, *offset as u32);
    }
    bytes
}

/// Writes a big-endian word at a fixture-owned offset.
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
