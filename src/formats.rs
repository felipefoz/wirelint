//! Shared facts and dispatch for native VI/RSRC and XML LabVIEW formats.

mod connector;
mod heap;
mod rsrc;
mod typed_data;
mod xml;

pub use typed_data::DefaultStringValue;

use std::io;
use std::path::{Path, PathBuf};

/// LabVIEW major and minor release numbers, ordered numerically.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    /// Parses a major.minor configuration value with representable components.
    pub fn parse(text: &str) -> Option<Self> {
        let (major, minor) = text.split_once('.')?;
        if major.is_empty()
            || minor.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let major = major.parse().ok()?;
        let minor = minor.parse().ok()?;
        (major <= 99 && minor <= 9).then_some(Self { major, minor })
    }

    /// Decodes the major and minor BCD digits of a LabVIEW version word.
    fn from_word(word: u32) -> io::Result<Self> {
        let tens = ((word >> 28) & 0xf) as u8;
        let ones = ((word >> 24) & 0xf) as u8;
        let minor = ((word >> 20) & 0xf) as u8;
        if tens > 9 || ones > 9 || minor > 9 {
            return Err(invalid("invalid LabVIEW version digits"));
        }
        Ok(Self {
            major: tens * 10 + ones,
            minor,
        })
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}", self.major, self.minor)
    }
}

/// Facts shared by all rules; extracted once for each analyzed file.
#[derive(Debug)]
pub struct FileFacts {
    pub separate_compiled_code: bool,
    pub has_description: Option<bool>,
    pub saved_version: Option<Version>,
    /// Stored DebugCapable flag; absent for controls and XML containers.
    pub debugging_enabled: Option<bool>,
    /// Stored breakpoints-set flag; absent for controls and XML containers.
    pub has_breakpoints: Option<bool>,
    /// Stored automatic error handling flag; absent for controls and XML containers.
    pub auto_error_handling: Option<bool>,
    /// Whether a password is set; absent for controls and XML containers.
    pub has_password: Option<bool>,
    /// Relative path to the owning library, when present in the VI link table.
    pub linked_library: Option<PathBuf>,
    /// VI member URLs listed by an `.lvlib`, when requested.
    pub library_members: Option<Vec<String>>,
    /// Whether a scanned owning library omits this VI from its member list.
    pub orphaned_vi: Option<bool>,
    /// Whether an `.lvclass` has nonempty content in its root geneology property.
    pub has_mutation_history: Option<bool>,
    /// Each front-panel terminal's icon-style flag, in heap order; absent for
    /// controls and XML containers.
    pub terminal_icon_styles: Option<Vec<bool>>,
    /// Index (0-35) of the VI's connector pane pattern among LabVIEW's 36
    /// fixed terminal layouts; absent for controls and XML containers.
    pub connector_pane_pattern: Option<u8>,
    /// String defaults of a VI's front-panel controls, from `FPHb`, when requested.
    pub default_string_values: Option<Vec<DefaultStringValue>>,
}

/// Reads a VI-family RSRC file or an XML project/library/class document.
///
/// Missing XML source-only or description properties mean false. When
/// `read_version` is true, missing or malformed version metadata is an error.
/// When `read_password` is true, malformed BDPW metadata is an error.
/// XML owner descriptions are always validated to extract suppression directives.
/// Malformed documents and unsupported binary layouts return `InvalidData`,
/// never an assumed value.
#[cfg(test)]
pub fn read_facts(
    path: &Path,
    bytes: &[u8],
    read_version: bool,
    read_description: bool,
    read_password: bool,
) -> io::Result<FileFacts> {
    read_facts_with_orphaned_vi(
        path,
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

/// Reads facts and suppression directives, optionally extracting library links.
#[allow(clippy::too_many_arguments)]
pub fn read_facts_with_orphaned_vi(
    path: &Path,
    bytes: &[u8],
    read_version: bool,
    read_description: bool,
    read_password: bool,
    read_orphaned_vi: bool,
    read_connector_pane_pattern: bool,
    read_default_strings: bool,
) -> io::Result<(FileFacts, Vec<Vec<u8>>)> {
    let xml = path.extension().and_then(|value| value.to_str());
    match xml {
        Some(extension) if extension.eq_ignore_ascii_case("lvproj") => {
            xml::read_facts_with_members(bytes, "Project", read_version, read_description, false)
        }
        Some(extension) if extension.eq_ignore_ascii_case("lvlib") => xml::read_facts_with_members(
            bytes,
            "Library",
            read_version,
            read_description,
            read_orphaned_vi,
        ),
        Some(extension) if extension.eq_ignore_ascii_case("lvclass") => {
            xml::read_facts_with_members(bytes, "LVClass", read_version, read_description, false)
        }
        _ => rsrc::read_facts_with_orphaned_vi(
            bytes,
            read_version,
            read_description,
            read_password,
            read_orphaned_vi,
            read_connector_pane_pattern,
            read_default_strings,
        ),
    }
}

/// Extracts the rule ID from an exact, case-sensitive two-token directive.
///
/// The `#` must be the first byte. Only ASCII whitespace separates tokens.
pub fn directive_rule(text: &[u8]) -> Option<&[u8]> {
    if !text.starts_with(b"#") {
        return None;
    }
    let mut tokens = text
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|part| !part.is_empty());
    if tokens.next()? != b"#wirelint" {
        return None;
    }
    let rule = tokens.next()?;
    tokens.next().is_none().then_some(rule)
}

/// Creates a contextual format error without substituting a setting value.
fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_owner_xml_properties_for_all_xml_extensions() {
        for (extension, root) in [
            ("lvproj", "Project"),
            ("lvlib", "Library"),
            ("LVCLASS", "LVClass"),
        ] {
            for (property, expected) in [
                ("", false),
                (
                    r#"<Property Name="NI.LV.All.SourceOnly" Type="Bool">false</Property>"#,
                    false,
                ),
                (
                    r#"<Property Type="Bool" Name="NI.LV.All.SourceOnly"> true </Property>"#,
                    true,
                ),
            ] {
                let xml = format!("\u{feff}<?xml version=\"1.0\"?><{root}>{property}</{root}>");
                assert_eq!(
                    read_facts(
                        Path::new(&format!("file.{extension}")),
                        xml.as_bytes(),
                        false,
                        false,
                        false,
                    )
                    .unwrap()
                    .separate_compiled_code,
                    expected
                );
            }
        }
    }

    #[test]
    fn ignores_nested_properties_comments_and_escaped_property_names() {
        let xml = br#"<Project>
            <!-- <Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property> -->
            <Item><Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property></Item>
        </Project>"#;
        assert!(
            !xml::read_facts(xml, "Project", false, false)
                .unwrap()
                .separate_compiled_code
        );
        assert!(xml::read_facts(
            br#"<Project><Property Name="NI.LV.All.Source&#79;nly" Type="Bool">true</Property></Project>"#,
            "Project", false, false
        ).unwrap().separate_compiled_code);
    }

    #[test]
    fn rejects_invalid_xml_values_and_duplicate_settings() {
        for xml in [
            "<Project>",
            "<Library/>",
            r#"<Project><Property Name="NI.LV.All.SourceOnly" Type="Str">true</Property></Project>"#,
            r#"<Project><Property Name="NI.LV.All.SourceOnly" Type="Bool">yes</Property></Project>"#,
            r#"<Project><Property Name="NI.LV.All.SourceOnly" Type="Bool"/></Project>"#,
            r#"<Project><Property Name="NI.LV.All.SourceOnly" Type="Bool">true<Item/></Property></Project>"#,
            r#"<Project><Property Name="NI.LV.All.SourceOnly" Type="Bool">false</Property><Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property></Project>"#,
        ] {
            assert!(
                xml::read_facts(xml.as_bytes(), "Project", false, false).is_err(),
                "{xml}"
            );
        }
    }

    #[test]
    fn reads_xml_version_as_a_hexadecimal_word() {
        for (stamp, major, minor) in [
            ("19008000", 19, 0),
            ("20008000", 20, 0),
            ("21308000", 21, 3),
            ("9008000", 9, 0),
        ] {
            let xml = format!(r#"<Project LVVersion="{stamp}"/>"#);
            assert_eq!(
                xml::read_facts(xml.as_bytes(), "Project", true, false)
                    .unwrap()
                    .saved_version,
                Some(Version { major, minor })
            );
        }
        for xml in [
            "<Project/>",
            r#"<Project LVVersion=""/>"#,
            r#"<Project LVVersion="1"/>"#,
            r#"<Project LVVersion="0x20008000"/>"#,
            r#"<Project LVVersion="100000000"/>"#,
            r#"<Project LVVersion="2a008000"/>"#,
        ] {
            assert!(
                xml::read_facts(xml.as_bytes(), "Project", true, false).is_err(),
                "{xml}"
            );
            assert!(
                xml::read_facts(xml.as_bytes(), "Project", false, false).is_ok(),
                "{xml}"
            );
        }
    }

    #[test]
    fn reads_nonempty_owner_descriptions_for_all_xml_extensions() {
        for (extension, root, property) in [
            ("lvproj", "Project", "NI.Project.Description"),
            ("lvlib", "Library", "NI.Lib.Description"),
            ("lvclass", "LVClass", "NI.Lib.Description"),
        ] {
            for (content, expected) in [("", false), (" \n\t ", false), ("A description.", true)] {
                let xml = format!(
                    r#"<{root}><Property Name="{property}" Type="Str">{content}</Property></{root}>"#
                );
                assert_eq!(
                    read_facts(
                        Path::new(&format!("file.{extension}")),
                        xml.as_bytes(),
                        false,
                        true,
                        false
                    )
                    .unwrap()
                    .has_description,
                    Some(expected)
                );
            }
            let xml = format!("<{root}/>");
            assert_eq!(
                read_facts(
                    Path::new(&format!("file.{extension}")),
                    xml.as_bytes(),
                    false,
                    true,
                    false
                )
                .unwrap()
                .has_description,
                Some(false)
            );
        }
    }

    #[test]
    fn ignores_nested_descriptions_and_rejects_malformed_owner_descriptions() {
        assert_eq!(
            xml::read_facts(
                br#"<Project><Item><Property Name="NI.Project.Description" Type="Str">Nested</Property></Item></Project>"#,
                "Project",
                false,
                true
            )
            .unwrap()
            .has_description,
            Some(false)
        );
        for xml in [
            r#"<Project><Property Name="NI.Project.Description" Type="Bool">true</Property></Project>"#,
            r#"<Project><Property Name="NI.Project.Description" Type="Str">A</Property><Property Name="NI.Project.Description" Type="Str">B</Property></Project>"#,
            r#"<Project><Property Name="NI.Project.Description" Type="Str"><String>A</String></Property></Project>"#,
        ] {
            for read_description in [false, true] {
                assert!(
                    xml::read_facts(xml.as_bytes(), "Project", false, read_description).is_err(),
                    "{xml}"
                );
            }
        }
    }

    #[test]
    fn xml_directives_are_standalone_owner_description_lines() {
        let xml = br#"<Project>
            <Property Name="NI.Project.Description" Type="Str">&#35;wirelint saved-version
                <![CDATA[#wirelint separate-compiled-code]]>
            </Property>
            <Item><Property Name="NI.Project.Description" Type="Str">#wirelint file-description</Property></Item>
        </Project>"#;
        for read_description in [false, true] {
            let (facts, directives) =
                xml::read_facts_with_members(xml, "Project", false, read_description, false)
                    .unwrap();
            assert_eq!(facts.has_description, read_description.then_some(false));
            assert_eq!(
                directives,
                vec![
                    b"#wirelint saved-version".to_vec(),
                    b"#wirelint separate-compiled-code".to_vec(),
                ]
            );
        }
        let (facts, directives) = xml::read_facts_with_members(
            br#"<Project><Property Name="NI.Project.Description" Type="Str">Text mentioning #wirelint saved-version
#wirelint saved-version extra
#WireLint saved-version</Property></Project>"#,
            "Project", false, true, false,
        ).unwrap();
        assert_eq!(facts.has_description, Some(true));
        assert!(directives.is_empty());
    }

    #[test]
    fn reads_library_member_urls_only_when_requested() {
        let xml = br#"<Library>
            <Item Name="Group" Type="Folder">
                <Item Name="child.vi" Type="VI" URL="Subfolder/child.vi"/>
            </Item>
            <Item Name="root.vi" Type="VI" URL="root.vi"/>
        </Library>"#;
        assert_eq!(
            xml::read_facts_with_members(xml, "Library", false, false, true)
                .unwrap()
                .0
                .library_members,
            Some(vec!["Subfolder/child.vi".to_owned(), "root.vi".to_owned()])
        );
        assert_eq!(
            xml::read_facts_with_members(
                br#"<Library><Item Name="missing-url.vi" Type="VI"/></Library>"#,
                "Library",
                false,
                false,
                false,
            )
            .unwrap()
            .0
            .library_members,
            None
        );
        assert!(
            xml::read_facts_with_members(
                br#"<Library><Item Name="missing-url.vi" Type="VI"/></Library>"#,
                "Library",
                false,
                false,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn reads_mutation_history_only_from_the_class_root() {
        for (extension, root, contents, expected) in [
            (
                "lvclass",
                "LVClass",
                r#"<Property Name="NI.LVClass.Geneology" Type="Xml"><History/></Property>"#,
                Some(true),
            ),
            ("lvclass", "LVClass", "", Some(false)),
            (
                "lvclass",
                "LVClass",
                r#"<Property Name="NI.LVClass.Geneology" Type="Xml">  <![CDATA[ ]]>
</Property>"#,
                Some(false),
            ),
            (
                "lvclass",
                "LVClass",
                "<Item><Property Name=\"NI.LVClass.Geneology\" Type=\"Xml\">history</Property></Item>",
                Some(false),
            ),
            (
                "lvclass",
                "LVClass",
                r#"<Property Name="NI.LVClass.Geneology" Type="Xml">history</Property>"#,
                Some(true),
            ),
            (
                "lvclass",
                "LVClass",
                "<Property Name=\"NI.LVClass.Geneology\" Type=\"Str\">history</Property>",
                Some(false),
            ),
            (
                "lvlib",
                "Library",
                r#"<Property Name="NI.LVClass.Geneology" Type="Xml"/>"#,
                None,
            ),
            ("lvproj", "Project", "", None),
        ] {
            let xml = format!("<{root}>{contents}</{root}>");
            let facts = read_facts(
                Path::new(&format!("file.{extension}")),
                xml.as_bytes(),
                false,
                false,
                false,
            )
            .unwrap();
            assert_eq!(facts.has_mutation_history, expected, "{xml}");
        }
    }
}
