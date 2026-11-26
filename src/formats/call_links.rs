//! Bounded decoding of modern `LIbd/BDHP/IUVI` static subVI links.
//!
//! Records have no independent length, so unknown record kinds are errors:
//! searching arbitrary bytes for a VI name cannot establish a call identity.

use super::{invalid, rsrc};
use std::io;

const MAX_LINKS: usize = 100_000;

/// A saved static callee and the diagram node UIDs that reference it.
#[derive(Debug)]
pub(crate) struct CallLink {
    pub name: Vec<Vec<u8>>,
    pub path: Vec<String>,
    pub nodes: Vec<i32>,
}

/// Reads the version-14-and-newer list layout, rejecting unsupported records.
pub(super) fn parse(bytes: &[u8]) -> io::Result<Vec<CallLink>> {
    let mut reader = Reader { bytes, position: 0 };
    if reader.u16()? != 1 || reader.take(4)? != b"BDHP" {
        return Err(invalid("unsupported LIbd root list"));
    }
    let count = reader.count()?;
    let mut links = Vec::new();
    let mut total_nodes = 0;
    for _ in 0..count {
        if reader.u16()? != 2 {
            return Err(invalid("invalid LIbd list continuation"));
        }
        let kind = reader.take(4)?;
        if kind != b"IUVI" {
            return Err(invalid(format!(
                "unsupported LIbd link kind {:?}",
                String::from_utf8_lossy(kind)
            )));
        }
        reader.align(4)?;
        let parts = reader.count()?;
        if parts > 128 {
            return Err(invalid("too many callee name components"));
        }
        let mut name = Vec::new();
        for _ in 0..parts {
            name.push(reader.string()?.to_vec());
        }
        reader.align(2)?;
        let path = reader.path()?;
        reader.take(4)?; // BasicLinkSaveInfo flags.
        let type_index = reader.u16()?;
        if type_index & 0x8000 != 0 {
            reader.take(2)?;
        }
        if reader.take(1)? == [0xff] {
            reader.take(24)?;
        }
        reader.take(4)?; // TypedLinkSaveInfo flags.
        let node_count = reader.count()?;
        total_nodes += node_count;
        if total_nodes > MAX_LINKS {
            return Err(invalid("LIbd exceeds the total call-node limit"));
        }
        let mut nodes = Vec::new();
        for _ in 0..node_count {
            nodes.push(i32::from_be_bytes(reader.take(4)?.try_into().unwrap()));
        }
        reader.path()?; // Saved VI link-search path.
        let length = reader.string()?.len();
        if (length + 1) % 2 != 0 {
            reader.take(1)?;
        }
        links.push(CallLink { name, path, nodes });
    }
    if reader.u16()? != 3 || reader.position != bytes.len() {
        return Err(invalid("inconsistent LIbd list termination or length"));
    }
    Ok(links)
}

/// A checked cursor; every variable-length allocation is bounded before use.
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let bytes = rsrc::slice(self.bytes, self.position, length)?;
        self.position += length;
        Ok(bytes)
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn count(&mut self) -> io::Result<usize> {
        let value = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        if value > MAX_LINKS {
            return Err(invalid("LIbd collection exceeds the size limit"));
        }
        Ok(value)
    }

    fn string(&mut self) -> io::Result<&'a [u8]> {
        let length = self.take(1)?[0] as usize;
        self.take(length)
    }

    fn align(&mut self, alignment: usize) -> io::Result<()> {
        let padding = (alignment - self.position % alignment) % alignment;
        self.take(padding).map(|_| ())
    }

    fn path(&mut self) -> io::Result<Vec<String>> {
        let start = self.position;
        if self.take(4)? != b"PTH0" {
            return Err(invalid("unsupported LIbd path encoding"));
        }
        let length = rsrc::number(self.bytes, self.position)?;
        self.take(4)?;
        if length == 0 {
            if self.take(4)? != [0; 4] {
                return Err(invalid("invalid empty LIbd PTH0 path"));
            }
            return Ok(Vec::new());
        }
        self.take(length)?;
        let (_, components) = rsrc::read_pth0(self.bytes, start)?;
        Ok(components)
    }
}

#[cfg(test)]
mod tests;
