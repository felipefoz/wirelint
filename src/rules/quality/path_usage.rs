//! Warn about nonportable or hardcoded scalar LabVIEW paths.

use crate::config::{PathTarget, RuleConfig};
use crate::formats::{FileFacts, PathKind, PathUsage};
use crate::rules::{Rule, Severity};

/// Checks scalar path constants and front-panel defaults.
pub(super) struct PathUsageRule;

impl Rule for PathUsageRule {
    fn id(&self) -> &'static str {
        "path-usage"
    }
    fn description(&self) -> &'static str {
        "Detect empty, absolute, or nonportable path values"
    }
    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, options: Option<&RuleConfig>) -> Option<String> {
        let defaults = [PathTarget::Windows, PathTarget::Linux];
        let targets = options
            .and_then(|options| options.targets.as_deref())
            .unwrap_or(&defaults);
        let mut findings = facts.path_usage.iter().flatten().filter_map(|path| {
            let reason = classify(path, targets)?;
            let kind = if path.constant {
                "path constant"
            } else {
                "path control default"
            };
            let label = path
                .label
                .as_deref()
                .filter(|label| !label.is_empty())
                .map(|label| format!(" \"{}\"", safe_label(label)))
                .unwrap_or_default();
            Some(format!("{kind}{label}: {reason}"))
        });
        let first = findings.next()?;
        let remaining = findings.count();
        let others = if remaining == 0 {
            String::new()
        } else {
            format!("; {remaining} other path value(s)")
        };
        Some(format!(
            "{first}{others}. Use a portable relative path or construct the path at runtime."
        ))
    }
}

/// Classifies a stored value without consulting the local filesystem.
fn classify(path: &PathUsage, targets: &[PathTarget]) -> Option<&'static str> {
    if path.kind == PathKind::NotAPath {
        return None;
    }
    if path.kind == PathKind::Absolute && path.components.is_empty() {
        return path.constant.then_some("empty path");
    }
    if matches!(path.kind, PathKind::Absolute | PathKind::Unc) {
        return Some("absolute path");
    }
    if targets.contains(&PathTarget::Linux)
        && path
            .components
            .iter()
            .any(|part| part.contains(&0) || part.contains(&b'/'))
    {
        return Some("invalid Linux path syntax");
    }
    if targets.contains(&PathTarget::Windows)
        && path
            .components
            .iter()
            .any(|part| invalid_windows_component(part))
    {
        return Some("invalid Windows path syntax");
    }
    None
}

/// Validates a Windows filename component; an empty serialized component means `..`.
fn invalid_windows_component(part: &[u8]) -> bool {
    if part.is_empty() || part == b"." || part == b".." {
        return false;
    }
    if part
        .iter()
        .any(|byte| *byte < 32 || b"<>:\"/\\|?*".contains(byte))
        || matches!(part.last(), Some(b' ' | b'.'))
    {
        return true;
    }
    let stem = part
        .split(|byte| *byte == b'.')
        .next()
        .unwrap_or_default()
        .trim_ascii_end();
    let upper = stem.iter().map(u8::to_ascii_uppercase).collect::<Vec<_>>();
    matches!(upper.as_slice(), b"CON" | b"PRN" | b"AUX" | b"NUL")
        || ((upper.starts_with(b"COM") || upper.starts_with(b"LPT"))
            && matches!(
                &upper[3..],
                [b'1'..=b'9'] | [0xb9 | 0xb2 | 0xb3] | [0xc2, 0xb9 | 0xb2 | 0xb3]
            ))
}

/// Bounds and sanitizes the object label used in the diagnostic.
fn safe_label(label: &[u8]) -> String {
    String::from_utf8_lossy(label)
        .chars()
        .take(64)
        .map(|c| if c.is_control() || c == '"' { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(kind: PathKind, constant: bool, components: &[&[u8]]) -> PathUsage {
        PathUsage {
            object: None,
            label: None,
            constant,
            kind,
            components: components.iter().map(|v| v.to_vec()).collect(),
        }
    }
    #[test]
    fn checks_kinds_and_target_specific_syntax() {
        let both = [PathTarget::Windows, PathTarget::Linux];
        assert_eq!(
            classify(&value(PathKind::Absolute, true, &[]), &both),
            Some("empty path")
        );
        assert_eq!(
            classify(&value(PathKind::Absolute, false, &[]), &both),
            None
        );
        assert_eq!(classify(&value(PathKind::NotAPath, true, &[]), &both), None);
        assert_eq!(
            classify(&value(PathKind::Unc, true, &[b"server"]), &both),
            Some("absolute path")
        );
        assert_eq!(
            classify(
                &value(PathKind::Relative, true, &[b"foo", b"bar.txt"]),
                &both
            ),
            None
        );
        assert_eq!(
            classify(&value(PathKind::Relative, true, &[b"file:name"]), &both),
            Some("invalid Windows path syntax")
        );
        assert_eq!(
            classify(
                &value(PathKind::Relative, true, &[b"file:name"]),
                &[PathTarget::Linux]
            ),
            None
        );
        for name in [
            b"CON.txt".as_slice(),
            b"CON .txt",
            b"LPT1",
            b"COM\xc2\xb9",
            b"trailing.",
            b"a?b",
        ] {
            assert_eq!(
                classify(&value(PathKind::Relative, false, &[name]), &both),
                Some("invalid Windows path syntax")
            );
        }
        assert_eq!(
            classify(
                &value(PathKind::Relative, true, &[b"one/two"]),
                &[PathTarget::Linux]
            ),
            Some("invalid Linux path syntax")
        );
        assert_eq!(
            classify(&value(PathKind::Relative, true, &[b""]), &both),
            None
        );
    }
}
