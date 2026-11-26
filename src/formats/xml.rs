//! Extracts shared analysis facts from LabVIEW project, library, and class XML.

use super::{FileFacts, Version, directive_rule, invalid};
use std::io;

/// Reads the document owner's properties without inspecting nested items.
///
/// Requested malformed metadata is reported as `InvalidData`; absent optional
/// properties retain the format's existing false or `None` semantics.
#[cfg(test)]
pub(super) fn read_facts(
    bytes: &[u8],
    expected_root: &str,
    read_version: bool,
    read_description: bool,
) -> io::Result<FileFacts> {
    read_facts_with_members(bytes, expected_root, read_version, read_description, false)
        .map(|(facts, _)| facts)
}

/// Reads owner facts and description directives, optionally listing VI members.
///
/// Owner descriptions are validated even when their rule is disabled because
/// directives can suppress other rules. Directive-only text is not a description.
/// VI items without a URL have no saved member path and are omitted.
pub(super) fn read_facts_with_members(
    bytes: &[u8],
    expected_root: &str,
    read_version: bool,
    read_description: bool,
    read_library_members: bool,
) -> io::Result<(FileFacts, Vec<Vec<u8>>)> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| invalid(format!("XML must be UTF-8: {error}")))?;
    let document = roxmltree::Document::parse(text.trim_start_matches('\u{feff}'))
        .map_err(|error| invalid(format!("invalid XML: {error}")))?;
    let root = document.root_element();
    if !root.has_tag_name(expected_root) {
        return Err(invalid(format!("expected XML root {expected_root}")));
    }

    let mut value = None;
    for property in root.children().filter(|node| {
        node.has_tag_name("Property") && node.attribute("Name") == Some("NI.LV.All.SourceOnly")
    }) {
        if value.is_some() {
            return Err(invalid("duplicate NI.LV.All.SourceOnly property"));
        }
        if property.attribute("Type") != Some("Bool")
            || property.children().any(|node| node.is_element())
        {
            return Err(invalid("NI.LV.All.SourceOnly must be a Bool property"));
        }
        let text: String = property
            .children()
            .filter_map(|node| node.text().filter(|_| node.is_text()))
            .collect();
        value = Some(match text.trim() {
            "true" => true,
            "false" => false,
            _ => return Err(invalid("NI.LV.All.SourceOnly must be true or false")),
        });
    }
    let saved_version = if read_version {
        let stamp = root
            .attribute("LVVersion")
            .ok_or_else(|| invalid("missing root LVVersion attribute"))?;
        if !(7..=8).contains(&stamp.len()) || !stamp.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid root LVVersion attribute"));
        }
        let word = u32::from_str_radix(stamp, 16)
            .map_err(|_| invalid("invalid root LVVersion attribute"))?;
        Some(Version::from_word(word)?)
    } else {
        None
    };
    let mut directives = Vec::new();
    let description_present = {
        let property_name = if expected_root == "Project" {
            "NI.Project.Description"
        } else {
            "NI.Lib.Description"
        };
        let mut value = None;
        for property in root.children().filter(|node| {
            node.has_tag_name("Property") && node.attribute("Name") == Some(property_name)
        }) {
            if value.is_some() {
                return Err(invalid(format!("duplicate {property_name} property")));
            }
            if property.attribute("Type") != Some("Str")
                || property.children().any(|node| node.is_element())
            {
                return Err(invalid(format!("{property_name} must be a Str property")));
            }
            let text: String = property
                .children()
                .filter_map(|node| node.text().filter(|_| node.is_text()))
                .collect();
            let mut has_prose = false;
            for line in text.lines().map(str::trim) {
                if directive_rule(line.as_bytes()).is_some() {
                    directives.push(line.as_bytes().to_vec());
                } else if !line.is_empty() {
                    has_prose = true;
                }
            }
            value = Some(has_prose);
        }
        value.unwrap_or(false)
    };
    let has_description = read_description.then_some(description_present);
    let library_members = if read_library_members && expected_root == "Library" {
        let mut members = Vec::new();
        for item in root
            .descendants()
            .filter(|node| node.has_tag_name("Item") && node.attribute("Type") == Some("VI"))
        {
            let Some(url) = item.attribute("URL") else {
                continue;
            };
            if url.trim().is_empty() {
                return Err(invalid("library VI item has an empty URL"));
            }
            members.push(url.to_owned());
        }
        Some(members)
    } else {
        None
    };
    let has_mutation_history = (expected_root == "LVClass").then(|| {
        root.children().any(|node| {
            node.has_tag_name("Property")
                && node.attribute("Name") == Some("NI.LVClass.Geneology")
                && node.attribute("Type") == Some("Xml")
                && node.children().any(|child| {
                    child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
                })
        })
    });
    Ok((
        FileFacts {
            call_inputs: Default::default(),
            separate_compiled_code: value.unwrap_or(false),
            has_description,
            saved_version,
            debugging_enabled: None,
            has_breakpoints: None,
            auto_error_handling: None,
            has_password: None,
            linked_library: None,
            library_members,
            orphaned_vi: None,
            has_mutation_history,
            terminal_icon_styles: None,
            connector_pane_pattern: None,
            default_string_values: None,
            diagram_string_values: None,
            path_usage: None,
        },
        directives,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_url_less_vi_items_without_dropping_saved_members_or_owner_facts() {
        let xml = br#"<Library>
            <Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property>
            <Property Name="NI.Lib.Description" Type="Str">Library description.</Property>
            <Item Name="Attribute" Type="Folder">
                <Item Name="Untitled 8" Type="VI"/>
                <Item Name="member.vi" Type="VI" URL="../member.vi"/>
            </Item>
        </Library>"#;
        let (facts, _) = read_facts_with_members(xml, "Library", false, true, true).unwrap();
        assert_eq!(facts.library_members, Some(vec!["../member.vi".to_owned()]));
        assert!(facts.separate_compiled_code);
        assert_eq!(facts.has_description, Some(true));
    }

    #[test]
    fn rejects_explicitly_empty_vi_member_urls() {
        for url in ["", "   "] {
            let xml =
                format!(r#"<Library><Item Name="member.vi" Type="VI" URL="{url}"/></Library>"#);
            let error =
                read_facts_with_members(xml.as_bytes(), "Library", false, false, true).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "library VI item has an empty URL");
        }
    }
}
