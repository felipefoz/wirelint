//! CI report serialization with file-level locations and stable finding identity.

use crate::analysis::{Finding, Report};
use crate::rules::{Rule, Severity};
use clap::ValueEnum;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Supported machine reports; destinations are selected separately by the CLI.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    /// GitLab Code Quality JSON; line 1 is a file-level placeholder.
    #[value(name = "gitlab-code-quality", alias = "gitlab")]
    Gitlab,
    /// GitLab Security Report Schema for the `sast` artifact type.
    GitlabSast,
    /// SARIF 2.1.0 for GitHub code scanning, with file-only locations.
    Sarif,
}

/// Wall-clock bounds for one completed analysis pass.
#[derive(Clone, Copy, Debug)]
pub struct ScanTimes {
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
}

/// Serializes a complete report as UTF-8 JSON without a BOM.
///
/// Paths remain relative to the scan root. Rejects non-UTF-8 paths rather than
/// emitting ambiguous lossy names. Analysis errors are SARIF invocation failures
/// and GitLab SAST scan messages, not rule findings; GitLab Code Quality
/// consumers must also check the process exit status.
/// `rules` is the registry that produced `report`; SARIF lists its full rule
/// metadata, including any CWE tags, independent of which rules produced findings.
pub fn render(
    report: &Report,
    format: Format,
    rules: &[&dyn Rule],
    times: ScanTimes,
) -> io::Result<Vec<u8>> {
    let findings = report
        .findings
        .iter()
        .map(|finding| {
            let path = report_path(&finding.path)?;
            let fingerprint = fingerprint(finding.rule, &path);
            Ok(match format {
                Format::Gitlab => json!({
                    "description": finding.message,
                    "check_name": finding.rule,
                    "fingerprint": fingerprint,
                    "severity": gitlab_severity(finding.severity),
                    "location": { "path": path, "lines": { "begin": 1 } }
                }),
                Format::GitlabSast => gitlab_sast_finding(finding, &path, &fingerprint, rules),
                Format::Sarif => sarif_finding(finding, &path, &fingerprint),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let document = match format {
        Format::Gitlab => Value::Array(findings),
        Format::GitlabSast => {
            let messages: Vec<_> = report
                .errors
                .iter()
                .map(|error| {
                    Ok(json!({
                        "level": "fatal",
                        "value": format!("{}: {}", report_path(&error.path)?, error.message)
                    }))
                })
                .collect::<io::Result<Vec<_>>>()?;
            json!({
                "schema": "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json",
                "version": "15.2.5",
                "scan": {
                    "analyzer": {
                        "id": "wirelint",
                        "name": "WireLint",
                        "url": "https://github.com/felipefoz/wire-lint",
                        "version": env!("CARGO_PKG_VERSION"),
                        "vendor": { "name": "WireLint" }
                    },
                    "scanner": {
                        "id": "wirelint-sast",
                        "name": "WireLint SAST",
                        "url": "https://github.com/felipefoz/wire-lint",
                        "version": env!("CARGO_PKG_VERSION"),
                        "vendor": { "name": "WireLint" }
                    },
                    "start_time": gitlab_timestamp(times.started_at)?,
                    "end_time": gitlab_timestamp(times.finished_at)?,
                    "status": if report.errors.is_empty() { "success" } else { "failure" },
                    "type": "sast",
                    "messages": messages
                },
                "vulnerabilities": findings
            })
        }
        Format::Sarif => {
            let notifications = report
                .errors
                .iter()
                .map(|error| {
                    Ok(json!({
                        "level": "error",
                        "message": { "text": error.message },
                        "locations": [sarif_location(&report_path(&error.path)?)]
                    }))
                })
                .collect::<io::Result<Vec<_>>>()?;
            let rules: Vec<_> = rules
                .iter()
                .map(|rule| {
                    let mut entry = json!({
                        "id": rule.id(),
                        "shortDescription": { "text": rule.description() },
                        "defaultConfiguration": {
                            "level": sarif_severity(rule.default_severity())
                        }
                    });
                    if !rule.cwe().is_empty() {
                        entry["properties"] = json!({ "tags": cwe_tags(rule.cwe()) });
                    }
                    entry
                })
                .collect();
            json!({
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": { "driver": {
                        "name": "WireLint",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/felipefoz/wire-lint",
                        "rules": rules
                    }},
                    "invocations": [{
                        "executionSuccessful": report.errors.is_empty(),
                        "toolExecutionNotifications": notifications
                    }],
                    "results": findings
                }]
            })
        }
    };
    let mut bytes = serde_json::to_vec_pretty(&document).map_err(io::Error::other)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Converts native path components to slash-separated UTF-8 without changing names.
fn report_path(path: &Path) -> io::Result<String> {
    path.iter()
        .map(|part| {
            part.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("report path is not valid UTF-8: {}", path.display()),
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

/// Identifies one rule per file, independent of message, severity, and scan machine.
fn fingerprint(rule: &str, path: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(rule.as_bytes());
    hash.update([0]);
    hash.update(path.as_bytes());
    format!("{:x}", hash.finalize())
}

fn gitlab_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "minor",
        Severity::Error => "major",
    }
}

fn gitlab_sast_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "Info",
        Severity::Warning => "Medium",
        Severity::Error => "High",
    }
}

/// Formats a UTC timestamp as required by GitLab's security-report schema.
fn gitlab_timestamp(time: SystemTime) -> io::Result<String> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    let days = i64::try_from(seconds / 86_400)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let day_seconds = seconds % 86_400;

    // Convert days since the Unix epoch to a proleptic Gregorian date.
    let shifted_days = days + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);

    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        day_seconds / 3_600,
        day_seconds / 60 % 60,
        day_seconds % 60
    ))
}

/// Converts a finding to the GitLab SAST vulnerability shape.
fn gitlab_sast_finding(
    finding: &Finding,
    path: &str,
    fingerprint: &str,
    rules: &[&dyn Rule],
) -> Value {
    let rule = rules.iter().find(|rule| rule.id() == finding.rule);
    let name = rule.map(|rule| rule.description()).unwrap_or(finding.rule);
    let mut identifiers = vec![json!({
        "type": "wirelint_rule",
        "name": finding.rule,
        "value": finding.rule
    })];
    if let Some(rule) = rule {
        for cwe in rule.cwe() {
            let value = cwe.strip_prefix("CWE-").unwrap_or(cwe);
            identifiers.push(json!({
                "type": "cwe",
                "name": cwe,
                "value": value,
                "url": format!("https://cwe.mitre.org/data/definitions/{value}.html")
            }));
        }
    }
    json!({
        "id": fingerprint,
        "category": "sast",
        "name": name,
        "description": finding.message,
        "severity": gitlab_sast_severity(finding.severity),
        "identifiers": identifiers,
        "location": { "file": path }
    })
}

fn sarif_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "note",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Converts `CWE-NNN` identifiers to GitHub code scanning's lowercase
/// `external/cwe/cwe-NNN` tag convention.
fn cwe_tags(cwe: &[&str]) -> Vec<String> {
    cwe.iter()
        .map(|id| format!("external/cwe/{}", id.to_lowercase()))
        .collect()
}

/// Uses file-only locations because current rules have no meaningful source lines.
fn sarif_finding(finding: &Finding, path: &str, fingerprint: &str) -> Value {
    json!({
        "ruleId": finding.rule,
        "level": sarif_severity(finding.severity),
        "message": { "text": finding.message },
        "locations": [sarif_location(path)],
        "partialFingerprints": { "wirelintFileRule/v1": fingerprint }
    })
}

/// Encodes UTF-8 bytes as a relative URI, preserving only separators and unreserved bytes.
fn sarif_location(path: &str) -> Value {
    let uri: String = path
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect();
    json!({ "physicalLocation": { "artifactLocation": { "uri": uri } } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AnalysisError;
    use crate::rules::quality::BUILT_INS;
    use std::path::PathBuf;

    fn sample() -> Report {
        Report {
            analyzed: 1,
            findings: vec![Finding {
                path: Path::new("folder").join("a #%.vi"),
                rule: "separate-compiled-code",
                severity: Severity::Warning,
                message: "A \"quoted\" message\nwith details.".into(),
            }],
            errors: Vec::new(),
            skipped: Vec::new(),
        }
    }

    fn value(report: &Report, format: Format, rules: &[&dyn Rule]) -> Value {
        let times = ScanTimes {
            started_at: UNIX_EPOCH,
            finished_at: UNIX_EPOCH + std::time::Duration::from_secs(1),
        };
        serde_json::from_slice(&render(report, format, rules, times).unwrap()).unwrap()
    }

    #[test]
    fn gitlab_fields_escape_messages_and_map_all_severities() {
        let mut report = sample();
        for (severity, expected) in [
            (Severity::Info, "info"),
            (Severity::Warning, "minor"),
            (Severity::Error, "major"),
        ] {
            report.findings[0].severity = severity;
            let json = value(&report, Format::Gitlab, BUILT_INS);
            assert_eq!(json[0]["severity"], expected);
            assert_eq!(json[0]["location"]["path"], "folder/a #%.vi");
            assert_eq!(json[0]["location"]["lines"]["begin"], 1);
            assert_eq!(json[0]["description"], report.findings[0].message);
            assert_eq!(json[0]["check_name"], "separate-compiled-code");
        }
    }

    #[test]
    fn fingerprints_track_file_and_rule_not_presentation() {
        let mut report = sample();
        let original = value(&report, Format::Gitlab, BUILT_INS)[0]["fingerprint"].clone();
        assert_eq!(original.as_str().unwrap().len(), 64);
        report.findings[0].message = "Changed message".into();
        report.findings[0].severity = Severity::Error;
        assert_eq!(
            original,
            value(&report, Format::Gitlab, BUILT_INS)[0]["fingerprint"]
        );
        assert_eq!(
            original,
            value(&report, Format::Sarif, BUILT_INS)["runs"][0]["results"][0]["partialFingerprints"]
                ["wirelintFileRule/v1"]
        );
        report.findings[0].path = PathBuf::from("other.vi");
        assert_ne!(
            original,
            value(&report, Format::Gitlab, BUILT_INS)[0]["fingerprint"]
        );
        report.findings[0].path = sample().findings.remove(0).path;
        report.findings[0].rule = "saved-version";
        assert_ne!(
            original,
            value(&report, Format::Gitlab, BUILT_INS)[0]["fingerprint"]
        );
        assert_ne!(fingerprint("ab", "c"), fingerprint("a", "bc"));
    }

    #[test]
    fn gitlab_sast_contains_schema_metadata_cwe_identifiers_and_stable_ids() {
        use crate::rules::sast::BUILT_INS as SAST_BUILT_INS;

        let mut report = sample();
        report.findings[0].rule = "hardcoded-secret-default";
        report.findings[0].severity = Severity::Warning;
        let json = value(&report, Format::GitlabSast, SAST_BUILT_INS);
        assert_eq!(json["version"], "15.2.5");
        assert_eq!(json["scan"]["type"], "sast");
        assert_eq!(json["scan"]["status"], "success");
        assert_eq!(json["scan"]["analyzer"]["id"], "wirelint");
        assert_eq!(json["scan"]["scanner"]["id"], "wirelint-sast");
        assert_eq!(json["scan"]["start_time"], "1970-01-01T00:00:00");
        assert_eq!(json["scan"]["end_time"], "1970-01-01T00:00:01");
        let vulnerability = &json["vulnerabilities"][0];
        assert_eq!(
            vulnerability["id"],
            fingerprint("hardcoded-secret-default", "folder/a #%.vi")
        );
        assert_eq!(vulnerability["category"], "sast");
        assert_eq!(
            vulnerability["name"],
            "Detect credentials stored in VI string defaults and constants"
        );
        assert_eq!(vulnerability["severity"], "Medium");
        assert_eq!(vulnerability["location"]["file"], "folder/a #%.vi");
        assert_eq!(
            vulnerability["identifiers"],
            json!([
                {
                    "type": "wirelint_rule",
                    "name": "hardcoded-secret-default",
                    "value": "hardcoded-secret-default"
                },
                {
                    "type": "cwe",
                    "name": "CWE-798",
                    "value": "798",
                    "url": "https://cwe.mitre.org/data/definitions/798.html"
                },
                {
                    "type": "cwe",
                    "name": "CWE-259",
                    "value": "259",
                    "url": "https://cwe.mitre.org/data/definitions/259.html"
                }
            ])
        );
    }

    #[test]
    fn gitlab_sast_maps_all_severities_and_marks_analysis_errors() {
        let mut report = sample();
        for (severity, expected) in [
            (Severity::Info, "Info"),
            (Severity::Warning, "Medium"),
            (Severity::Error, "High"),
        ] {
            report.findings[0].severity = severity;
            assert_eq!(
                value(&report, Format::GitlabSast, BUILT_INS)["vulnerabilities"][0]["severity"],
                expected
            );
        }
        report.errors.push(AnalysisError {
            path: PathBuf::from("broken.vi"),
            message: "Cannot parse".into(),
        });
        let json = value(&report, Format::GitlabSast, BUILT_INS);
        assert_eq!(json["scan"]["status"], "failure");
        assert_eq!(
            json["scan"]["messages"][0],
            json!({ "level": "fatal", "value": "broken.vi: Cannot parse" })
        );
    }

    #[test]
    fn gitlab_timestamps_convert_epoch_and_leap_day() {
        assert_eq!(gitlab_timestamp(UNIX_EPOCH).unwrap(), "1970-01-01T00:00:00");
        assert_eq!(
            gitlab_timestamp(UNIX_EPOCH + std::time::Duration::from_secs(1_709_164_800)).unwrap(),
            "2024-02-29T00:00:00"
        );
    }

    #[test]
    fn sarif_has_rule_metadata_encoded_file_locations_and_effective_levels() {
        let mut report = sample();
        for (severity, expected) in [
            (Severity::Info, "note"),
            (Severity::Warning, "warning"),
            (Severity::Error, "error"),
        ] {
            report.findings[0].severity = severity;
            let json = value(&report, Format::Sarif, BUILT_INS);
            assert_eq!(json["version"], "2.1.0");
            let run = &json["runs"][0];
            assert_eq!(run["tool"]["driver"]["name"], "WireLint");
            for rule in BUILT_INS {
                assert!(
                    run["tool"]["driver"]["rules"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|entry| entry["id"] == rule.id())
                );
            }
            assert_eq!(run["invocations"][0]["executionSuccessful"], true);
            let result = &run["results"][0];
            assert_eq!(result["level"], expected);
            assert_eq!(result["ruleId"], report.findings[0].rule);
            assert_eq!(result["message"]["text"], report.findings[0].message);
            assert_eq!(
                result["locations"][0],
                json!({"physicalLocation": {
                    "artifactLocation": { "uri": "folder/a%20%23%25.vi" }
                }})
            );
        }
        assert_eq!(
            sarif_location("a:\u{e9}\\b.vi")["physicalLocation"]["artifactLocation"]["uri"],
            "a%3A%C3%A9%5Cb.vi"
        );
    }

    #[test]
    fn sarif_omits_properties_for_rules_without_a_cwe_mapping() {
        let json = value(&sample(), Format::Sarif, BUILT_INS);
        let quality_rule = &json["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(quality_rule["id"], "separate-compiled-code");
        assert!(quality_rule["properties"].is_null());
    }

    #[test]
    fn cwe_tags_use_githubs_lowercase_external_cwe_convention() {
        assert_eq!(
            cwe_tags(&["CWE-284", "CWE-306"]),
            ["external/cwe/cwe-284", "external/cwe/cwe-306"]
        );
        assert!(cwe_tags(&[]).is_empty());
    }

    #[test]
    fn empty_reports_and_analysis_failures_remain_distinguishable_in_sarif() {
        let mut report = Report::default();
        assert_eq!(value(&report, Format::Gitlab, BUILT_INS), json!([]));
        assert_eq!(
            value(&report, Format::GitlabSast, BUILT_INS)["vulnerabilities"],
            json!([])
        );
        let sarif = value(&report, Format::Sarif, BUILT_INS);
        assert_eq!(sarif["runs"][0]["results"], json!([]));
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        report.errors.push(AnalysisError {
            path: PathBuf::from("broken.vi"),
            message: "Cannot parse".into(),
        });
        assert_eq!(value(&report, Format::Gitlab, BUILT_INS), json!([]));
        let sarif = value(&report, Format::Sarif, BUILT_INS);
        let invocation = &sarif["runs"][0]["invocations"][0];
        assert_eq!(invocation["executionSuccessful"], false);
        let notification = &invocation["toolExecutionNotifications"][0];
        assert_eq!(notification["message"]["text"], "Cannot parse");
        assert_eq!(notification["level"], "error");
        assert_eq!(notification["locations"][0], sarif_location("broken.vi"));
        assert_eq!(sarif["runs"][0]["results"], json!([]));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_paths_without_lossy_substitution() {
        use std::os::unix::ffi::OsStringExt;
        let mut report = sample();
        report.findings[0].path = std::ffi::OsString::from_vec(b"bad-\xff.vi".to_vec()).into();
        for format in [Format::Gitlab, Format::GitlabSast, Format::Sarif] {
            assert_eq!(
                render(
                    &report,
                    format,
                    BUILT_INS,
                    ScanTimes {
                        started_at: UNIX_EPOCH,
                        finished_at: UNIX_EPOCH
                    }
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
