//! Review findings for HTTP destination and TLS verification evidence.

use crate::config::RuleConfig;
use crate::formats::dataflow::{Influence, Scalar, Trace};
use crate::formats::{CallEvidence, CallLink, DiagramGraph, FileFacts};
use crate::rules::{Rule, Severity};
use std::collections::BTreeMap;

pub(super) enum HttpRule {
    ControlUrl,
    PlaintextUrl,
    ServerVerification,
}

impl Rule for HttpRule {
    fn id(&self) -> &'static str {
        match self {
            Self::ControlUrl => "http-control-url",
            Self::PlaintextUrl => "http-plaintext-url",
            Self::ServerVerification => "http-server-verification",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::ControlUrl => "Review control-influenced HTTP request URLs",
            Self::PlaintextUrl => "Review HTTP request URLs without a proven HTTPS scheme",
            Self::ServerVerification => "Review disabled HTTP server certificate verification",
        }
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn supports_call_suppression(&self) -> bool {
        true
    }

    fn check(&self, facts: &FileFacts, _: Option<&RuleConfig>) -> Option<String> {
        let evidence = facts.call_inputs.get(self.id())?;
        let message = match self {
            Self::ControlUrl => {
                "Front-panel control input reaches an HTTP request URL; review destination restrictions and possible SSRF"
            }
            Self::PlaintextUrl => {
                "An HTTP request URL does not have a proven HTTPS scheme; review the destination and require HTTPS where appropriate"
            }
            Self::ServerVerification => {
                "An HTTP client configuration explicitly disables server verification; review TLS certificate validation"
            }
        };
        (!evidence.calls.is_empty()).then(|| {
            format!(
                "{message} ({} call(s)). This is not proof of exploitability.",
                evidence.calls.len()
            )
        })
    }

    fn cwe(&self) -> &'static [&'static str] {
        match self {
            Self::ControlUrl => &["CWE-918"],
            Self::PlaintextUrl => &["CWE-319"],
            Self::ServerVerification => &["CWE-295"],
        }
    }
}

const URL_SLOT: i32 = 5;
const VERIFY_SLOT: i32 = 12;

/// Independent evidence for the three HTTP security rules.
#[derive(Debug, Default)]
struct HttpInputs {
    control_url: CallEvidence,
    plaintext_url: CallEvidence,
    verification: CallEvidence,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Kind {
    Request,
    Verify,
}

/// Avoids constructing a graph when no enabled rule has a recognized call.
pub(crate) fn has_calls(links: &[CallLink], enabled: [bool; 3]) -> bool {
    links.iter().any(|link| {
        !link.nodes.is_empty()
            && match kind(link) {
                Some(Kind::Request) => enabled[0] || enabled[1],
                Some(Kind::Verify) => enabled[2],
                None => false,
            }
    })
}

/// Matches the NI library qualifier and path, never a similarly named custom VI.
fn kind(link: &CallLink) -> Option<Kind> {
    if link.name.len() != 2 || !link.name[0].eq_ignore_ascii_case(b"LabVIEWHTTPClient.lvlib") {
        return None;
    }
    let name = &link.name[1];
    if link.path.len() < 3
        || !link.path[link.path.len() - 2].eq_ignore_ascii_case("httpClient")
        || !link.path.last()?.as_bytes().eq_ignore_ascii_case(name)
        || !link.path[..link.path.len() - 2]
            .iter()
            .any(|part| part.eq_ignore_ascii_case("<vilib>") || part.eq_ignore_ascii_case("vi.lib"))
    {
        return None;
    }
    if [
        b"GET.vi".as_slice(),
        b"HEAD.vi",
        b"DELETE.vi",
        b"POST.vi",
        b"POSTBuffer.vi",
        b"POSTFile.vi",
        b"POSTMultipart.vi",
        b"PUT.vi",
        b"PUTBuffer.vi",
        b"PUTFile.vi",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        Some(Kind::Request)
    } else if [b"OpenHandle.vi".as_slice(), b"ConfigSSL.vi"]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
    {
        Some(Kind::Verify)
    } else {
        None
    }
}

/// Classifies supported calls, preserving incomplete paths.
fn analyze(links: &[CallLink], graph: Option<&DiagramGraph>, enabled: [bool; 3]) -> HttpInputs {
    let mut result = HttpInputs::default();
    let mut trace = graph
        .filter(|graph| graph.issues.is_empty())
        .map(Trace::new);
    let calls = links
        .iter()
        .filter_map(|link| {
            kind(link)
                .filter(|kind| match kind {
                    Kind::Request => enabled[0] || enabled[1],
                    Kind::Verify => enabled[2],
                })
                .map(|kind| link.nodes.iter().map(move |&uid| (uid, kind)))
        })
        .flatten();
    for (uid, kind) in calls {
        match graph {
            Some(graph) if graph.issues.is_empty() => {}
            Some(_) => {
                record_error(
                    &mut result,
                    uid,
                    kind,
                    enabled,
                    "saved diagram has unresolved or ambiguous connections",
                );
                continue;
            }
            None => {
                record_error(
                    &mut result,
                    uid,
                    kind,
                    enabled,
                    "saved block-diagram source is missing",
                );
                continue;
            }
        }
        let trace = trace.as_mut().expect("graph was checked above");
        match kind {
            Kind::Request => {
                if enabled[0] {
                    record(
                        &mut result.control_url,
                        uid,
                        trace
                            .call_input(uid, URL_SLOT)
                            .map(|value| value == Some(Influence::Control)),
                    );
                }
                if enabled[1] {
                    let value =
                        trace
                            .call_input(uid, URL_SLOT)
                            .and_then(|influence| match influence {
                                Some(Influence::Control) => Ok(true),
                                Some(Influence::Literal) => match trace
                                    .literal_input(uid, URL_SLOT)?
                                {
                                    Some(Scalar::String(value)) => {
                                        Ok(!value.get(..8).is_some_and(|prefix| {
                                            prefix.eq_ignore_ascii_case(b"https://")
                                        }))
                                    }
                                    Some(Scalar::Boolean(_)) => Err("URL constant is not a string"),
                                    None => Err("URL input is unwired"),
                                },
                                None => Err("URL input is unwired"),
                            });
                    record(&mut result.plaintext_url, uid, value);
                }
            }
            Kind::Verify => {
                let value = trace
                    .literal_input(uid, VERIFY_SLOT)
                    .and_then(|value| match value {
                        None => Ok(false),
                        Some(Scalar::Boolean(value)) => Ok(!value),
                        Some(Scalar::String(_)) => Err("verification constant is not Boolean"),
                    });
                record(&mut result.verification, uid, value);
            }
        }
    }
    result
}

fn record(evidence: &mut CallEvidence, uid: i32, result: Result<bool, &'static str>) {
    match result {
        Ok(true) => evidence.calls.push(uid),
        Ok(false) => {}
        Err(reason) => evidence.incomplete.push((uid, reason.to_owned())),
    }
}

fn record_error(
    result: &mut HttpInputs,
    uid: i32,
    kind: Kind,
    enabled: [bool; 3],
    reason: &'static str,
) {
    if kind == Kind::Request {
        if enabled[0] {
            record(&mut result.control_url, uid, Err(reason));
        }
        if enabled[1] {
            record(&mut result.plaintext_url, uid, Err(reason));
        }
    } else if enabled[2] {
        record(&mut result.verification, uid, Err(reason));
    }
}

/// Reads only the graph needed by enabled HTTP checks and returns per-rule evidence.
pub(crate) fn analyze_links(
    links: &[CallLink],
    graph: Option<&DiagramGraph>,
    enabled: [bool; 3],
) -> BTreeMap<&'static str, CallEvidence> {
    let inputs = analyze(links, graph, enabled);
    BTreeMap::from([
        ("http-control-url", inputs.control_url),
        ("http-plaintext-url", inputs.plaintext_url),
        ("http-server-verification", inputs.verification),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats;
    use std::path::Path;

    fn fixture(rule: &str, name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("sast")
                .join(rule)
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn matches_only_ni_http_client_calls() {
        let mut link = CallLink {
            name: vec![b"LabVIEWHTTPClient.lvlib".to_vec(), b"GET.vi".to_vec()],
            path: vec!["<vilib>".into(), "httpClient".into(), "GET.vi".into()],
            nodes: vec![1],
        };
        assert!(kind(&link) == Some(Kind::Request));
        link.path[0] = "custom".into();
        assert!(kind(&link).is_none());
        link.path[0] = "<vilib>".into();
        link.name[0] = b"Custom.lvlib".to_vec();
        assert!(kind(&link).is_none());
    }

    #[test]
    fn checks_saved_request_and_verification_inputs() {
        for (rule, name, control, plaintext, verify) in [
            ("http-control-url", "GET Control.vi", 1, 1, 0),
            ("http-control-url", "PUT Control.vi", 1, 1, 0),
            ("http-control-url", "GET Concatenated Control.vi", 1, 1, 0),
            ("http-plaintext-url", "GET HTTP Literal.vi", 0, 1, 0),
            ("http-plaintext-url", "POST HTTP Literal.vi", 0, 1, 0),
            ("http-plaintext-url", "GET HTTPS Literal.vi", 0, 0, 0),
            (
                "http-server-verification",
                "OpenHandle Verify False.vi",
                0,
                0,
                1,
            ),
            (
                "http-server-verification",
                "OpenHandle Verify True.vi",
                0,
                0,
                0,
            ),
            (
                "http-server-verification",
                "OpenHandle Verify Unwired.vi",
                0,
                0,
                0,
            ),
            (
                "http-server-verification",
                "ConfigSSL Verify False.vi",
                0,
                0,
                1,
            ),
            (
                "http-server-verification",
                "ConfigSSL Verify True.vi",
                0,
                0,
                0,
            ),
        ] {
            let bytes = fixture(rule, name);
            let links = formats::read_call_links(Path::new(name), &bytes)
                .unwrap()
                .unwrap();
            let graph = formats::read_diagram_graph(&bytes).unwrap().unwrap();
            let result = analyze(&links, Some(&graph), [true; 3]);
            assert_eq!(result.control_url.calls.len(), control, "{name}");
            assert_eq!(result.plaintext_url.calls.len(), plaintext, "{name}");
            assert_eq!(result.verification.calls.len(), verify, "{name}");
            assert!(result.control_url.incomplete.is_empty(), "{name}");
            assert!(result.plaintext_url.incomplete.is_empty(), "{name}");
            assert!(result.verification.incomplete.is_empty(), "{name}");
        }
    }

    #[test]
    fn unknown_boolean_and_missing_diagram_are_incomplete() {
        let bytes = fixture("http-server-verification", "OpenHandle Verify False.vi");
        let mut graph = formats::read_diagram_graph(&bytes).unwrap().unwrap();
        let node = graph.objects.get_mut(&20183).unwrap();
        node.constant_value = Some(vec![2]);
        let links = formats::read_call_links(Path::new("x.vi"), &bytes)
            .unwrap()
            .unwrap();
        let result = analyze(&links, Some(&graph), [true; 3]);
        assert!(result.verification.calls.is_empty());
        assert_eq!(result.verification.incomplete.len(), 1);
        graph.objects.get_mut(&20183).unwrap().constant_value = Some(vec![1]);
        graph
            .objects
            .get_mut(&20183)
            .unwrap()
            .ambiguous_constant_display = true;
        let result = analyze(&links, Some(&graph), [true; 3]);
        assert!(result.verification.calls.is_empty());
        assert_eq!(result.verification.incomplete.len(), 1);
        let links = formats::read_call_links(Path::new("x.vi"), &bytes)
            .unwrap()
            .unwrap();
        let result = analyze(&links, None, [true; 3]);
        assert_eq!(result.verification.incomplete.len(), 1);
    }

    #[test]
    fn malformed_string_constants_are_incomplete() {
        let bytes = fixture("http-plaintext-url", "GET HTTP Literal.vi");
        let links = formats::read_call_links(Path::new("x.vi"), &bytes)
            .unwrap()
            .unwrap();
        for value in [
            vec![0, 0, 0],
            vec![0, 0, 0, 2, b'a'],
            vec![0, 0, 0, 1, b'a', b'b'],
        ] {
            let mut graph = formats::read_diagram_graph(&bytes).unwrap().unwrap();
            graph.objects.get_mut(&20183).unwrap().constant_value = Some(value);
            let result = analyze(&links, Some(&graph), [true; 3]);
            assert!(result.plaintext_url.calls.is_empty());
            assert_eq!(result.plaintext_url.incomplete.len(), 1);
        }
    }

    #[test]
    fn requires_an_explicit_https_scheme_and_reports_unknown_transfers() {
        let bytes = fixture("http-plaintext-url", "GET HTTP Literal.vi");
        for (url, expected) in [
            (b"HTTPS://example.invalid".as_slice(), 0),
            (b"http://example.invalid".as_slice(), 1),
            (b"example.invalid".as_slice(), 1),
        ] {
            let mut graph = formats::read_diagram_graph(&bytes).unwrap().unwrap();
            let mut value = (url.len() as u32).to_be_bytes().to_vec();
            value.extend_from_slice(url);
            graph.objects.get_mut(&20183).unwrap().constant_value = Some(value);
            let links = formats::read_call_links(Path::new("x.vi"), &bytes)
                .unwrap()
                .unwrap();
            let result = analyze(&links, Some(&graph), [true; 3]);
            assert_eq!(result.plaintext_url.calls.len(), expected);
        }

        let bytes = fixture("http-control-url", "GET Concatenated Control.vi");
        let mut graph = formats::read_diagram_graph(&bytes).unwrap().unwrap();
        graph
            .objects
            .values_mut()
            .find(|object| object.class == 62)
            .unwrap()
            .class = 47;
        let links = formats::read_call_links(Path::new("x.vi"), &bytes)
            .unwrap()
            .unwrap();
        let result = analyze(&links, Some(&graph), [true; 3]);
        assert_eq!(result.control_url.incomplete.len(), 1);
        assert_eq!(result.plaintext_url.incomplete.len(), 1);
        assert!(result.control_url.calls.is_empty());
        assert!(result.plaintext_url.calls.is_empty());
    }
}
