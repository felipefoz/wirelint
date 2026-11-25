//! Decoding of flattened LabVIEW path values from source heaps.
//!
//! Components remain bytes: older path encodings are not necessarily UTF-8.
//! Malformed records are analysis errors, not guessed path values.

use super::{invalid, rsrc};
use std::io;

/// One scalar path value and the source object that owns it.
#[derive(Clone, Debug)]
pub struct PathUsage {
    pub label: Option<Vec<u8>>,
    pub constant: bool,
    pub kind: PathKind,
    pub components: Vec<Vec<u8>>,
}

/// LabVIEW's stored path categories, independent of the scanning host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    Absolute,
    Relative,
    NotAPath,
    Unc,
}

/// Parses a single complete flattened PTH0, PTH1, or PTH2 value.
pub(super) fn decode(data: &[u8], label: Option<Vec<u8>>, constant: bool) -> io::Result<PathUsage> {
    let ident = rsrc::slice(data, 0, 4)?;
    let length = rsrc::number(data, 4)?;
    let body_length = if ident == b"PTH0" && length == 0 {
        4
    } else {
        length
    };
    let body = rsrc::slice(data, 8, body_length)?;
    if data.len() != 8 + body_length || body.len() < 4 {
        return Err(invalid("invalid flattened path length"));
    }

    let (kind, count, width) = if ident == b"PTH0" {
        let kind = match u16::from_be_bytes([body[0], body[1]]) {
            0 => PathKind::Absolute,
            1 => PathKind::Relative,
            2 => PathKind::NotAPath,
            3 => PathKind::Unc,
            _ => return Err(invalid("unknown PTH0 path kind")),
        };
        (
            kind,
            Some(u16::from_be_bytes([body[2], body[3]]) as usize),
            1,
        )
    } else if ident == b"PTH1" || ident == b"PTH2" {
        let kind = match &body[..4] {
            b"abs " => PathKind::Absolute,
            b"rel " => PathKind::Relative,
            b"!pth" => PathKind::NotAPath,
            b"unc " => PathKind::Unc,
            _ => return Err(invalid("unknown path kind")),
        };
        (kind, None, 2)
    } else {
        return Err(invalid("unknown flattened path format"));
    };
    let mut cursor = 4;
    let mut components = Vec::new();
    while cursor < body.len() {
        let size = rsrc::slice(body, cursor, width)?;
        let component_length = if width == 1 {
            usize::from(size[0])
        } else {
            usize::from(u16::from_be_bytes([size[0], size[1]]))
        };
        cursor += width;
        components.push(rsrc::slice(body, cursor, component_length)?.to_vec());
        cursor += component_length;
    }
    if count.is_some_and(|count| count != components.len())
        || (kind == PathKind::NotAPath && !components.is_empty())
        || (length == 0 && (kind != PathKind::Absolute || !components.is_empty()))
    {
        return Err(invalid("inconsistent flattened path components"));
    }
    Ok(PathUsage {
        label,
        constant,
        kind,
        components,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_path_kinds_and_rejects_malformed_records() {
        let empty = b"PTH0\0\0\0\x04\0\0\0\0";
        assert_eq!(decode(empty, None, true).unwrap().kind, PathKind::Absolute);
        let not_a_path = b"PTH0\0\0\0\x04\0\x02\0\0";
        assert_eq!(
            decode(not_a_path, None, true).unwrap().kind,
            PathKind::NotAPath
        );
        let relative = b"PTH0\0\0\0\x08\0\x01\0\x01\x03abc";
        assert_eq!(
            decode(relative, None, true).unwrap().components,
            [b"abc".to_vec()]
        );
        let utf8 = b"PTH2\0\0\0\x09rel \0\x03abc";
        assert_eq!(decode(utf8, None, true).unwrap().kind, PathKind::Relative);
        for bad in [
            b"PTH0\0\0\0\x04\0\x01\0\x01".as_slice(),
            b"PTH0\0\0\0\x08\0\x01\0\x01\x05abc",
            b"PTH0\0\0\0\x04\0\x09\0\0",
            b"PTH9\0\0\0\x04\0\0\0\0",
        ] {
            assert!(decode(bad, None, true).is_err());
        }
    }
}
