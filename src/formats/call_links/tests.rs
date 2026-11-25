//! Independent link encodings exercise alignment, limits and truncation.

use super::*;

fn path(bytes: &mut Vec<u8>, parts: &[&str]) {
    bytes.extend_from_slice(b"PTH0");
    let length = 4 + parts.iter().map(|part| 1 + part.len()).sum::<usize>();
    bytes.extend_from_slice(&(length as u32).to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&(parts.len() as u16).to_be_bytes());
    for part in parts {
        bytes.push(part.len() as u8);
        bytes.extend_from_slice(part.as_bytes());
    }
}

fn encoded_link(expanded: bool) -> Vec<u8> {
    let mut bytes = b"\0\x01BDHP\0\0\0\x01\0\x02IUVI".to_vec();
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(14);
    bytes.extend_from_slice(b"System Exec.vi");
    bytes.push(0);
    path(
        &mut bytes,
        &["<vilib>", "Platform", "system.llb", "System Exec.vi"],
    );
    bytes.extend_from_slice(&0u32.to_be_bytes());
    if expanded {
        bytes.extend_from_slice(&[0x80, 0x01, 0x00, 0x02, 0xff]);
        bytes.extend_from_slice(&[0; 24]);
    } else {
        bytes.extend_from_slice(&[0, 5, 0]);
    }
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&43i32.to_be_bytes());
    bytes.extend_from_slice(&70_000i32.to_be_bytes());
    path(&mut bytes, &[]);
    bytes.extend_from_slice(&[0, 0, 0, 3]);
    bytes
}

#[test]
fn reads_static_call_identities_and_wide_or_compact_reference_metadata() {
    for expanded in [false, true] {
        let links = parse(&encoded_link(expanded)).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].name, [b"System Exec.vi".to_vec()]);
        assert_eq!(
            links[0].path,
            ["<vilib>", "Platform", "system.llb", "System Exec.vi"]
        );
        assert_eq!(links[0].nodes, [43, 70_000]);
    }
    assert!(parse(b"\0\x01BDHP\0\0\0\0\0\x03").unwrap().is_empty());
}

#[test]
fn rejects_unknown_link_records_truncation_and_unbounded_counts() {
    let original = encoded_link(false);
    for end in 0..original.len() {
        assert!(parse(&original[..end]).is_err(), "length {end}");
    }
    let mut unknown = original.clone();
    unknown[12..16].copy_from_slice(b"TCPI");
    assert!(parse(&unknown).unwrap_err().to_string().contains("TCPI"));
    let mut oversized = original.clone();
    oversized[6..10].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse(&oversized).is_err());
    let mut trailing = original;
    trailing.push(0);
    assert!(parse(&trailing).is_err());
}
