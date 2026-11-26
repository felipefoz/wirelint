//! `hardcoded-secret-default`: credentials stored in VI defaults or constants.
//!
//! Each extracted string is classified by the strongest matching heuristic:
//! private-key blocks and well-known token formats, credential-named values,
//! then credential assignments embedded in text.
//! Every matcher is a bounded, ASCII case-insensitive byte heuristic that never
//! retains the matched value. A file yields at most one finding, which names
//! the first match's labels (or type entry) and kind and counts
//! the rest, but never repeats a stored value.

use crate::config::RuleConfig;
use crate::formats::{DefaultStringValue, FileFacts};
use crate::rules::{Rule, Severity};

/// Longest label text repeated in a finding message.
const MAX_REPORTED_LABEL: usize = 64;

/// Reports literal credentials stored in VI string defaults and constants.
pub(super) struct HardcodedSecretDefault;

impl Rule for HardcodedSecretDefault {
    fn id(&self) -> &'static str {
        "hardcoded-secret-default"
    }

    fn description(&self) -> &'static str {
        "Detect credentials stored in VI string defaults and constants"
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, facts: &FileFacts, _options: Option<&RuleConfig>) -> Option<String> {
        let defaults = facts
            .default_string_values
            .iter()
            .flatten()
            .filter_map(|value| classify(value).map(|kind| (location(value), kind, false)));
        let constants = facts
            .diagram_string_values
            .iter()
            .flatten()
            .filter_map(|value| {
                let kind = classify_content(&value.bytes, value.label.as_deref())?;
                let location = match value.label.as_deref().filter(|label| !label.is_empty()) {
                    Some(label) => format!("string constant \"{}\"", display_label(label)),
                    None => "unlabeled string constant".to_owned(),
                };
                Some((location, kind, true))
            });
        let mut matches = defaults.chain(constants);
        let (location, kind, first_is_constant) = matches.next()?;
        let mut has_constant = first_is_constant;
        let mut count = 0;
        for (_, _, is_constant) in matches {
            count += 1;
            has_constant |= is_constant;
        }
        let other_kind = if has_constant { "value" } else { "default" };
        let others = match count {
            0 => String::new(),
            1 => format!(" and 1 other {other_kind}"),
            count => format!(" and {count} other {other_kind}s"),
        };
        Some(format!(
            "Possible hardcoded secret in {} ({}){others}. Remove it or load the secret securely at runtime.",
            location,
            kind.description(first_is_constant),
        ))
    }

    fn cwe(&self) -> &'static [&'static str] {
        &["CWE-798", "CWE-259"]
    }
}

/// Why a default was classified as a possible secret, strongest first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretKind {
    PrivateKey,
    Token(&'static str),
    CredentialName,
    Assignment,
}

impl SecretKind {
    fn description(self, is_constant: bool) -> String {
        match self {
            Self::PrivateKey => "private key block".to_owned(),
            Self::Token(name) => format!("{name} format"),
            Self::CredentialName if is_constant => "credential-named constant".to_owned(),
            Self::CredentialName => "credential-named control".to_owned(),
            Self::Assignment => "credential assignment in text".to_owned(),
        }
    }
}

/// Returns the strongest reason a default looks like a stored secret.
fn classify(value: &DefaultStringValue) -> Option<SecretKind> {
    classify_content(&value.bytes, nearest_label(value))
}

/// Applies the same bounded matchers to either kind of stored string.
fn classify_content(bytes: &[u8], label: Option<&[u8]>) -> Option<SecretKind> {
    if contains_private_key(bytes) {
        return Some(SecretKind::PrivateKey);
    }
    if let Some(name) = known_token(bytes) {
        return Some(SecretKind::Token(name));
    }
    if label.is_some_and(is_credential_name) && is_plausible_secret(bytes) {
        return Some(SecretKind::CredentialName);
    }
    contains_credential_assignment(bytes).then_some(SecretKind::Assignment)
}

/// The innermost non-empty Type Descriptor label on the value's path.
fn nearest_label(value: &DefaultStringValue) -> Option<&[u8]> {
    value
        .labels
        .iter()
        .rev()
        .find(|label| !label.is_empty())
        .map(Vec::as_slice)
}

/// Describes where a value is stored using its labels, or its `VCTP` type
/// entry when no level is labeled.
fn location(value: &DefaultStringValue) -> String {
    let labels = value
        .labels
        .iter()
        .filter(|label| !label.is_empty())
        .map(|label| format!("\"{}\"", display_label(label)))
        .collect::<Vec<_>>();
    if !labels.is_empty() {
        return labels.join(" > ");
    }
    let mut text = format!("type entry {}", value.type_index);
    if !value.field_path.is_empty() {
        let fields = value
            .field_path
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>();
        text.push_str(&format!(", field {}", fields.join(".")));
    }
    text
}

/// Makes a label safe for one-line output and bounds its length.
fn display_label(label: &[u8]) -> String {
    let text = String::from_utf8_lossy(label);
    let mut shown = text
        .chars()
        .map(|character| {
            if character.is_control() || character == '"' {
                ' '
            } else {
                character
            }
        })
        .take(MAX_REPORTED_LABEL)
        .collect::<String>();
    if text.chars().count() > MAX_REPORTED_LABEL {
        shown.push_str("...");
    }
    shown.trim().to_owned()
}

// Matchers. Each inspects one string and never returns the matched value.

/// Shortest trimmed value that a label or key match can report.
const MIN_SECRET_LENGTH: usize = 4;
/// Longest identifier read backwards from an assignment separator.
const MAX_KEY_LENGTH: usize = 128;

/// Single-word name endings that denote a credential, e.g. `dbPassword`.
const CREDENTIAL_WORD_ENDINGS: &[&[u8]] = &[
    b"password",
    b"passwd",
    b"passwort",
    b"kennwort",
    b"passphrase",
    b"passcode",
    b"pwd",
    b"secret",
    b"token",
    b"credential",
    b"apikey",
    b"accesskey",
    b"secretkey",
    b"privatekey",
    b"accountkey",
];

/// Words that turn a following `key` into a credential name, e.g. `API Key`.
const KEY_QUALIFIERS: &[&[u8]] = &[
    b"api",
    b"access",
    b"secret",
    b"private",
    b"account",
    b"encryption",
    b"signing",
    b"master",
    b"auth",
    b"client",
    b"session",
];

/// Words that describe credential metadata rather than a credential value.
const EXCLUDED_NAME_WORDS: &[&[u8]] = &[
    b"hint",
    b"prompt",
    b"caption",
    b"label",
    b"length",
    b"len",
    b"policy",
    b"rule",
    b"rules",
    b"strength",
    b"expiry",
    b"expires",
    b"expiration",
    b"timeout",
    b"file",
    b"path",
    b"dir",
    b"folder",
    b"name",
    b"names",
    b"id",
    b"type",
    b"format",
    b"url",
    b"uri",
    b"endpoint",
    b"field",
    b"column",
    b"mode",
    b"enable",
    b"enabled",
    b"required",
    b"visible",
    b"valid",
    b"count",
    b"min",
    b"max",
    b"size",
    b"changed",
    b"reset",
    b"regex",
    b"pattern",
    b"delimiter",
    b"delimiters",
    b"separator",
    b"prefix",
    b"suffix",
    b"char",
    b"chars",
    b"character",
    b"characters",
    b"location",
    b"ref",
    b"refnum",
    b"error",
    b"status",
    b"message",
    b"msg",
    b"description",
    b"dialog",
    b"button",
];

/// Exact values (case-insensitive) that stand in for a real secret.
const PLACEHOLDERS: &[&[u8]] = &[
    b"changeme",
    b"change_me",
    b"change-me",
    b"placeholder",
    b"redacted",
    b"dummy",
    b"example",
    b"test",
    b"none",
    b"null",
    b"nil",
    b"undefined",
    b"empty",
    b"default",
    b"n/a",
    b"tbd",
    b"todo",
    b"true",
    b"false",
    b"yes",
    b"no",
    b"on",
    b"off",
    b"hidden",
    b"masked",
    b"password",
    b"passwd",
    b"pwd",
    b"secret",
    b"token",
    b"apikey",
    b"api_key",
    b"credentials",
];

/// Words (case-insensitive) that mark a value as instructions, not a secret.
const PROMPT_WORDS: &[&[u8]] = &[
    b"enter",
    b"please",
    b"type",
    b"your",
    b"here",
    b"required",
    b"optional",
    b"must",
];

/// Authorization schemes whose following word is the credential.
const AUTH_SCHEMES: &[&[u8]] = &[b"bearer", b"basic", b"token", b"digest"];

/// A vendor token with a fixed prefix and a bounded body of one character set.
struct TokenFormat {
    name: &'static str,
    prefixes: &'static [&'static [u8]],
    body: fn(u8) -> bool,
    min: usize,
    max: usize,
}

fn upper_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn alphanumeric_or_underscore(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn alphanumeric_or_dash(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

const TOKEN_FORMATS: &[TokenFormat] = &[
    TokenFormat {
        name: "AWS access key ID",
        prefixes: &[b"AKIA", b"ASIA"],
        body: upper_or_digit,
        min: 16,
        max: 16,
    },
    TokenFormat {
        name: "GitHub token",
        prefixes: &[b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"],
        body: alphanumeric,
        min: 36,
        max: 255,
    },
    TokenFormat {
        name: "GitHub token",
        prefixes: &[b"github_pat_"],
        body: alphanumeric_or_underscore,
        min: 22,
        max: 255,
    },
    TokenFormat {
        name: "GitLab token",
        prefixes: &[b"glpat-", b"glptt-", b"glrt-"],
        body: base64url,
        min: 20,
        max: 255,
    },
    TokenFormat {
        name: "Slack token",
        prefixes: &[b"xoxb-", b"xoxp-", b"xoxa-", b"xoxr-", b"xoxs-", b"xoxe-"],
        body: alphanumeric_or_dash,
        min: 10,
        max: 255,
    },
    TokenFormat {
        name: "Google API key",
        prefixes: &[b"AIza"],
        body: base64url,
        min: 35,
        max: 35,
    },
    TokenFormat {
        name: "Stripe secret key",
        prefixes: &[b"sk_live_", b"rk_live_"],
        body: alphanumeric,
        min: 16,
        max: 255,
    },
];

/// Splits a control label or key into lowercase words at non-alphanumeric
/// bytes and camel-case boundaries (`dbPassword`, `APIKey`).
fn name_words(name: &[u8]) -> Vec<Vec<u8>> {
    let mut words = Vec::new();
    for run in name
        .split(|byte| !byte.is_ascii_alphanumeric())
        .filter(|run| !run.is_empty())
    {
        let mut start = 0;
        for index in 1..run.len() {
            let (previous, current) = (run[index - 1], run[index]);
            let next_is_lower = run.get(index + 1).is_some_and(u8::is_ascii_lowercase);
            if current.is_ascii_uppercase()
                && (previous.is_ascii_lowercase()
                    || previous.is_ascii_digit()
                    || previous.is_ascii_uppercase() && next_is_lower)
            {
                words.push(run[start..index].to_ascii_lowercase());
                start = index;
            }
        }
        words.push(run[start..].to_ascii_lowercase());
    }
    words
}

/// Whether a label or key names a credential value rather than its metadata.
fn is_credential_name(name: &[u8]) -> bool {
    let words = name_words(name);
    if words
        .iter()
        .any(|word| EXCLUDED_NAME_WORDS.contains(&word.as_slice()))
    {
        return false;
    }
    words.iter().any(|word| {
        let singular = word.strip_suffix(b"s").unwrap_or(word);
        CREDENTIAL_WORD_ENDINGS
            .iter()
            .any(|ending| word.ends_with(ending) || singular.ends_with(ending))
    }) || words.windows(2).any(|pair| {
        KEY_QUALIFIERS.contains(&pair[0].as_slice())
            && matches!(pair[1].as_slice(), b"key" | b"keys")
    })
}

/// Whether a trimmed value is long enough and not a placeholder or prompt.
fn is_plausible_secret(value: &[u8]) -> bool {
    let value = value.trim_ascii();
    value.len() >= MIN_SECRET_LENGTH
        && !is_placeholder(value)
        && !is_prompt(value)
        && !is_prose(value)
}

/// Whether a value with spaces reads as a message, e.g. `The password is
/// incorrect!`: it ends like a sentence or mentions a credential term.
/// Space-separated passphrases without either remain plausible.
fn is_prose(value: &[u8]) -> bool {
    value.iter().any(u8::is_ascii_whitespace)
        && (matches!(value.last(), Some(b'.' | b'!' | b'?'))
            || name_words(value)
                .iter()
                .any(|word| CREDENTIAL_WORD_ENDINGS.contains(&word.as_slice())))
}

/// Excludes template values, masks, and environment-variable references.
fn is_placeholder(value: &[u8]) -> bool {
    let lower = value.to_ascii_lowercase();
    let wrapped = |open: &[u8], close: &[u8]| {
        lower.len() > open.len() + close.len() && lower.starts_with(open) && lower.ends_with(close)
    };
    PLACEHOLDERS.contains(&lower.as_slice())
        || value.iter().all(|byte| *byte == value[0])
        || lower.starts_with(b"your_")
        || lower.starts_with(b"your-")
        || lower.starts_with(b"$")
        || wrapped(b"{{", b"}}")
        || wrapped(b"<", b">")
        || wrapped(b"%", b"%")
        || wrapped(b"[", b"]")
}

/// Whether a value reads as instructions for a user, e.g. `Enter here`.
fn is_prompt(value: &[u8]) -> bool {
    value
        .split(|byte| !byte.is_ascii_alphanumeric())
        .any(|word| {
            PROMPT_WORDS
                .iter()
                .any(|prompt| word.eq_ignore_ascii_case(prompt))
        })
}

/// Whether the bytes contain a PEM or PGP private-key header.
fn contains_private_key(bytes: &[u8]) -> bool {
    const BEGIN: &[u8] = b"-----BEGIN ";
    find_all(bytes, BEGIN).any(|start| {
        let header_start = start + BEGIN.len();
        bytes[header_start..]
            .windows(5)
            .position(|window| window == b"-----")
            .is_some_and(|length| {
                let header = &bytes[header_start..header_start + length];
                header.ends_with(b"PRIVATE KEY") || header.ends_with(b"PRIVATE KEY BLOCK")
            })
    })
}

/// Returns the name of the first well-known token format in the bytes.
fn known_token(bytes: &[u8]) -> Option<&'static str> {
    TOKEN_FORMATS
        .iter()
        .find(|format| {
            format.prefixes.iter().any(|prefix| {
                find_all(bytes, prefix).any(|start| {
                    let body = &bytes[start + prefix.len()..];
                    let length = body
                        .iter()
                        .take(format.max + 1)
                        .take_while(|byte| (format.body)(**byte))
                        .count();
                    starts_word(bytes, start) && (format.min..=format.max).contains(&length)
                })
            })
        })
        .map(|format| format.name)
        .or_else(|| contains_jwt(bytes).then_some("JSON Web Token"))
}

/// Whether the bytes contain a signed `header.payload.signature` JWT.
fn contains_jwt(bytes: &[u8]) -> bool {
    fn segment(bytes: &[u8], start: usize) -> usize {
        bytes[start..]
            .iter()
            .take_while(|byte| base64url(**byte))
            .count()
    }
    find_all(bytes, b"eyJ").any(|start| {
        if !starts_word(bytes, start) {
            return false;
        }
        let header = segment(bytes, start);
        let payload_start = start + header + 1;
        if header < 10
            || bytes.get(start + header) != Some(&b'.')
            || !bytes[payload_start..].starts_with(b"eyJ")
        {
            return false;
        }
        let payload = segment(bytes, payload_start);
        let signature_start = payload_start + payload + 1;
        payload >= 10
            && bytes.get(payload_start + payload) == Some(&b'.')
            && segment(bytes, signature_start) >= 10
    })
}

/// Whether a match at `start` is not preceded by an identifier character.
fn starts_word(bytes: &[u8], start: usize) -> bool {
    start == 0 || !alphanumeric_or_underscore(bytes[start - 1])
}

/// Yields every start offset of `needle` in `bytes`.
fn find_all<'a>(bytes: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    bytes
        .windows(needle.len())
        .enumerate()
        .filter(move |(_, window)| *window == needle)
        .map(|(start, _)| start)
}

/// Whether the text assigns a plausible value to a credential-named key, in
/// `key=value`, `key: value`, `key := value`, `key => value`, quoted-key,
/// XML-element, URL-userinfo, or `Authorization: <scheme> <value>` form.
fn contains_credential_assignment(bytes: &[u8]) -> bool {
    (0..bytes.len()).any(|index| {
        let Some((key, value_start)) = assignment_at(bytes, index) else {
            return false;
        };
        let authorization = key.eq_ignore_ascii_case(b"authorization");
        if !authorization && !is_credential_name(key) {
            return false;
        }
        let (value, value_end) = value_at(bytes, value_start);
        if authorization {
            return AUTH_SCHEMES
                .iter()
                .any(|scheme| value.eq_ignore_ascii_case(scheme))
                && is_plausible_secret(value_at(bytes, value_end).0);
        }
        is_plausible_secret(value)
    }) || contains_xml_credential(bytes)
        || contains_url_credential(bytes)
}

fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// Returns the key before an assignment separator at `index` and the offset
/// where its value begins. Comparisons (`==`, `!=`, `<=`, `>=`) and URL
/// schemes (`://`) are not separators.
fn assignment_at(bytes: &[u8], index: usize) -> Option<(&[u8], usize)> {
    let next = bytes.get(index + 1).copied();
    let previous = index.checked_sub(1).map(|previous| bytes[previous]);
    let value_start = match bytes[index] {
        b'=' if next == Some(b'>') => index + 2,
        b'=' if next == Some(b'=')
            || matches!(previous, Some(b'=' | b'!' | b'<' | b'>' | b':')) =>
        {
            return None;
        }
        b'=' => index + 1,
        b':' if next == Some(b'=') => index + 2,
        b':' if bytes[index + 1..].starts_with(b"//") => return None,
        b':' => index + 1,
        _ => return None,
    };
    let mut end = index;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_key_byte(bytes[start - 1]) {
        start -= 1;
        if end - start > MAX_KEY_LENGTH {
            return None;
        }
    }
    (start < end).then(|| (&bytes[start..end], value_start))
}

/// Reads one quoted or unquoted value after optional whitespace, returning it
/// and the offset just past it.
fn value_at(bytes: &[u8], mut cursor: usize) -> (&[u8], usize) {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    match bytes.get(cursor) {
        Some(quote @ (b'\'' | b'"')) => {
            let start = cursor + 1;
            let end = bytes[start..]
                .iter()
                .position(|byte| byte == quote)
                .map_or(bytes.len(), |offset| start + offset);
            (&bytes[start..end], (end + 1).min(bytes.len()))
        }
        Some(_) => {
            let end = bytes[cursor..]
                .iter()
                .position(|byte| {
                    byte.is_ascii_whitespace()
                        || matches!(
                            byte,
                            b',' | b';' | b'&' | b'}' | b')' | b']' | b'<' | b'>' | b'"' | b'\''
                        )
                })
                .map_or(bytes.len(), |offset| cursor + offset);
            (&bytes[cursor..end], end)
        }
        None => (&[], cursor),
    }
}

/// Whether an XML element such as `<password>value</password>` holds a
/// plausible credential.
fn contains_xml_credential(bytes: &[u8]) -> bool {
    find_all(bytes, b"<").any(|open| {
        let name_start = open + 1;
        let name_length = bytes[name_start..]
            .iter()
            .take(MAX_KEY_LENGTH + 1)
            .take_while(|byte| is_key_byte(**byte) || **byte == b':')
            .count();
        if name_length == 0 || name_length > MAX_KEY_LENGTH {
            return false;
        }
        let name_end = name_start + name_length;
        if !is_credential_name(&bytes[name_start..name_end]) {
            return false;
        }
        let Some(tag_length) = bytes[name_end..].iter().position(|byte| *byte == b'>') else {
            return false;
        };
        let content_start = name_end + tag_length + 1;
        if bytes[content_start - 2] == b'/' {
            return false;
        }
        let content_end = bytes[content_start..]
            .windows(2)
            .position(|window| window == b"</")
            .map_or(bytes.len(), |offset| content_start + offset);
        is_plausible_secret(&bytes[content_start..content_end])
    })
}

/// Whether a URL such as `scheme://user:password@host` embeds a plausible
/// password in its userinfo.
fn contains_url_credential(bytes: &[u8]) -> bool {
    find_all(bytes, b"://").any(|scheme_end| {
        let authority_start = scheme_end + 3;
        let authority_end = bytes[authority_start..]
            .iter()
            .position(|byte| {
                byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
            })
            .map_or(bytes.len(), |offset| authority_start + offset);
        let authority = &bytes[authority_start..authority_end];
        authority
            .iter()
            .rposition(|byte| *byte == b'@')
            .and_then(|at| {
                let userinfo = &authority[..at];
                userinfo
                    .iter()
                    .position(|byte| *byte == b':')
                    .map(|colon| &userinfo[colon + 1..])
            })
            .is_some_and(is_plausible_secret)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(labels: &[&[u8]], bytes: &[u8]) -> DefaultStringValue {
        DefaultStringValue {
            object: None,
            type_index: 3,
            field_path: vec![0; labels.len().saturating_sub(1)],
            labels: labels.iter().map(|label| label.to_vec()).collect(),
            bytes: bytes.to_vec(),
        }
    }

    fn facts(values: Vec<DefaultStringValue>) -> FileFacts {
        FileFacts {
            call_inputs: Default::default(),
            separate_compiled_code: false,
            has_description: None,
            saved_version: None,
            debugging_enabled: None,
            has_breakpoints: None,
            auto_error_handling: None,
            has_password: None,
            linked_library: None,
            library_members: None,
            orphaned_vi: None,
            has_mutation_history: None,
            terminal_icon_styles: None,
            connector_pane_pattern: None,
            default_string_values: Some(values),
            path_usage: None,
            diagram_string_values: Some(Vec::new()),
        }
    }

    fn unlabeled(bytes: &[u8]) -> Option<SecretKind> {
        classify(&value(&[b""], bytes))
    }

    #[test]
    fn reports_plausible_defaults_of_credential_named_controls() {
        assert_eq!(
            classify(&value(&[b"DB Password"], b"hunter22")),
            Some(SecretKind::CredentialName)
        );
        for (label, text) in [
            (b"DB Password".as_slice(), b"".as_slice()),
            (b"DB Password", b"****"),
            (b"DB Password", b"Enter password"),
            (b"Token", b","),
            (b"Password File", b"C:\\secrets\\db.txt"),
            (b"Numeric", b"hunter22"),
        ] {
            assert_eq!(
                classify(&value(&[label], text)),
                None,
                "{}",
                String::from_utf8_lossy(label)
            );
        }
    }

    #[test]
    fn uses_the_innermost_label_of_nested_values() {
        assert_eq!(
            classify(&value(&[b"Credentials", b"Username"], b"operator")),
            None
        );
        assert_eq!(
            classify(&value(&[b"Settings", b"", b"Password"], b"hunter22")),
            Some(SecretKind::CredentialName)
        );
        assert_eq!(
            classify(&value(&[b"Passwords", b""], b"hunter22")),
            Some(SecretKind::CredentialName)
        );
    }

    #[test]
    fn classifies_by_the_strongest_matching_heuristic() {
        let token = format!("password=AKIA{}", "A1B2C3D4E5F6G7H8");
        assert_eq!(
            unlabeled(token.as_bytes()),
            Some(SecretKind::Token("AWS access key ID"))
        );
        assert_eq!(
            classify(&value(&[b"Password"], b"-----BEGIN PRIVATE KEY-----\nMIIE")),
            Some(SecretKind::PrivateKey)
        );
        assert_eq!(
            classify(&value(&[b"Password"], b"password=hunter22")),
            Some(SecretKind::CredentialName)
        );
        assert_eq!(
            unlabeled(b"password=hunter22"),
            Some(SecretKind::Assignment)
        );
        assert_eq!(unlabeled(b"plain text"), None);
    }

    #[test]
    fn reports_one_finding_with_locations_but_never_values() {
        let message = HardcodedSecretDefault
            .check(
                &facts(vec![
                    value(&[b"Settings", b"DB Password"], b"hunter22"),
                    value(&[b""], b"token=letmein1"),
                    value(&[b"Comment"], b"nothing here"),
                    value(&[b""], b"password = s3cr3t!!"),
                ]),
                None,
            )
            .unwrap();
        assert_eq!(
            message,
            "Possible hardcoded secret in \"Settings\" > \"DB Password\" (credential-named control) and 2 other defaults. Remove it or load the secret securely at runtime."
        );
        for secret in ["hunter22", "letmein1", "s3cr3t!!"] {
            assert!(!message.contains(secret));
        }
        let unlabeled_message = HardcodedSecretDefault
            .check(
                &facts(vec![DefaultStringValue {
                    object: None,
                    type_index: 7,
                    field_path: vec![1, 2],
                    labels: vec![Vec::new(); 3],
                    bytes: b"password=hunter22".to_vec(),
                }]),
                None,
            )
            .unwrap();
        assert!(
            unlabeled_message
                .contains("in type entry 7, field 1.2 (credential assignment in text). ")
        );
    }

    #[test]
    fn reports_labeled_and_unlabeled_diagram_constants_without_values() {
        let mut facts = facts(Vec::new());
        facts.diagram_string_values = Some(vec![
            crate::formats::DiagramStringConstant {
                object: None,
                label: Some(b"Password".to_vec()),
                bytes: b"apiXSDsdsdadasdsdsadsadas".to_vec(),
            },
            crate::formats::DiagramStringConstant {
                object: None,
                label: None,
                bytes: b"password=another-secret".to_vec(),
            },
            crate::formats::DiagramStringConstant {
                object: None,
                label: Some(b"Password".to_vec()),
                bytes: b"changeme".to_vec(),
            },
        ]);
        let message = HardcodedSecretDefault.check(&facts, None).unwrap();
        assert_eq!(
            message,
            "Possible hardcoded secret in string constant \"Password\" (credential-named constant) and 1 other value. Remove it or load the secret securely at runtime."
        );
        assert!(!message.contains("apiXSDsdsdadasdsdsadsadas"));
        assert!(!message.contains("another-secret"));

        facts.diagram_string_values.as_mut().unwrap().remove(0);
        let message = HardcodedSecretDefault.check(&facts, None).unwrap();
        assert!(message.contains("unlabeled string constant (credential assignment in text)"));
        assert!(!message.contains("another-secret"));
    }

    #[test]
    fn sanitizes_and_bounds_reported_labels() {
        assert_eq!(display_label(b"A\"b\nc"), "A b c");
        assert_eq!(display_label(&[b'x'; 70]), format!("{}...", "x".repeat(64)));
    }

    #[test]
    fn requires_default_string_facts_and_exposes_cwe_mapping() {
        assert!(
            HardcodedSecretDefault
                .check(
                    &FileFacts {
                        default_string_values: None,
                        ..facts(Vec::new())
                    },
                    None,
                )
                .is_none()
        );
        assert!(
            HardcodedSecretDefault
                .check(&facts(Vec::new()), None)
                .is_none()
        );
        assert_eq!(HardcodedSecretDefault.cwe(), &["CWE-798", "CWE-259"]);
        assert_eq!(HardcodedSecretDefault.default_severity(), Severity::Warning);
    }

    fn matches_anything(text: &[u8]) -> bool {
        contains_private_key(text)
            || known_token(text).is_some()
            || contains_credential_assignment(text)
    }

    #[test]
    fn finds_credential_assignments_in_text() {
        for text in [
            b"password = hunter2".as_slice(),
            b"API_KEY: \"sk-example-secret\"",
            b"db_password=letmein",
            b"{\"password\": \"hunter22\"}",
            b"{'client_secret': 'abcd1234'}",
            b"token := s3cr3tvalue",
            b"apiKey => 'abcd1234'",
            b"Server=db;Uid=sa;Pwd=Sup3rS3cret;",
            b"<config><password>hunter22</password></config>",
            b"<login user=\"admin\" password=\"hunter22\"/>",
            b"ftp://admin:hunter22@192.168.0.10/data",
            b"Authorization: Bearer abcdef123456",
        ] {
            assert!(
                contains_credential_assignment(text),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn ignores_prompts_metadata_placeholders_and_comparisons() {
        for text in [
            b"Enter your password".as_slice(),
            b"this-is-a-long-random-looking-value",
            b"password=",
            b"password=changeme",
            b"password=********",
            b"password=${PASSWORD}",
            b"password=%DB_PASSWORD%",
            b"password=$(Password)",
            b"secret=<placeholder>",
            b"Password: Enter here",
            b"password_hint=my dog",
            b"password_length=12",
            b"token_type=Bearer",
            b"pwd=abc",
            b"my_password_variable",
            b"if password == expected",
            b"https://admin@example.com/path",
            b"https://admin:${PASS}@example.com/path",
            b"<password/>",
            b"Authorization: Bearer <token>",
        ] {
            assert!(!matches_anything(text), "{}", String::from_utf8_lossy(text));
        }
    }

    #[test]
    fn classifies_credential_names_by_words() {
        for name in [
            b"Password".as_slice(),
            b"DB Password",
            b"dbPassword",
            b"API Key",
            b"APIKey",
            b"access_token",
            b"Client Secret",
            b"Kennwort",
            b"Credentials",
            b"Passwords",
        ] {
            assert!(
                is_credential_name(name),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
        for name in [
            b"Password Hint".as_slice(),
            b"Password File",
            b"Token URL",
            b"Registry Key",
            b"Pass/Fail",
            b"Key",
            b"Numeric",
            b"",
        ] {
            assert!(
                !is_credential_name(name),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn rejects_short_masked_placeholder_and_prompt_values() {
        assert!(is_plausible_secret(b"  hunter22  "));
        assert!(is_plausible_secret(b"correct horse battery staple"));
        for text in [
            b"".as_slice(),
            b"   ",
            b"abc",
            b"****",
            b"xxxxxxxx",
            b"changeme",
            b"Password",
            b"your-api-key",
            b"{{secret}}",
            b"[token]",
            b"Enter password",
            b"The password is incorrect!",
            b"VI is protected. Try again later.",
            b"needs a token from the server",
        ] {
            assert!(
                !is_plausible_secret(text),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
    }

    #[test]
    fn finds_known_token_formats_with_word_boundaries() {
        let cases = [
            (format!("AKIA{}", "A1B2C3D4E5F6G7H8"), "AWS access key ID"),
            (format!("ghp_{}", "a1".repeat(18)), "GitHub token"),
            (format!("github_pat_{}", "a1_".repeat(10)), "GitHub token"),
            (format!("glpat-{}", "a1-".repeat(7)), "GitLab token"),
            (format!("xoxb-{}", "1234-abcd".repeat(2)), "Slack token"),
            (format!("AIza{}", "a1_-b".repeat(7)), "Google API key"),
            (format!("sk_live_{}", "a1".repeat(12)), "Stripe secret key"),
            (
                format!("eyJ{0}.eyJ{0}.{0}", "hbGciOiJIUzI1"),
                "JSON Web Token",
            ),
        ];
        for (text, name) in cases {
            assert_eq!(
                known_token(format!("value {text} end").as_bytes()),
                Some(name),
                "{text}"
            );
        }
        for text in [
            format!("AKIA{}", "A1B2C3"),
            format!("AKIA{}", "A1B2C3D4E5F6G7H8J"),
            format!("XAKIA{}", "A1B2C3D4E5F6G7H8"),
            "eyJhbGciOiJIUzI1.short".to_owned(),
        ] {
            assert_eq!(known_token(text.as_bytes()), None, "{text}");
        }
    }

    #[test]
    fn finds_private_key_headers_only() {
        assert!(contains_private_key(
            b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"
        ));
        assert!(contains_private_key(
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----"
        ));
        assert!(!contains_private_key(b"-----BEGIN PUBLIC KEY-----"));
        assert!(!contains_private_key(b"-----BEGIN CERTIFICATE-----"));
        assert!(!contains_private_key(b"-----BEGIN PRIVATE KEY"));
    }
}
