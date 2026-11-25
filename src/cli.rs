//! Command-line parsing, terminal summaries, and optional CI report files.

use crate::analysis;
use crate::config::{Config, FailOn};
use crate::reports::{self, Format};
use crate::rules::quality::BUILT_INS as QUALITY_BUILT_INS;
use crate::rules::sast::BUILT_INS as SAST_BUILT_INS;
use crate::rules::{Rule, Severity};
use crate::scan;
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Parser)]
#[command(
    name = "wirelint",
    version,
    about = "Static analysis for LabVIEW",
    long_about = "Recursively discover LabVIEW files and run enabled built-in analysis rules. Use 'wirelint rules' to list rules. Files are read without launching LabVIEW or modifying source files."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover LabVIEW files and run enabled analysis rules.
    #[command(
        long_about = "Recursively analyze .vi, .vit, .vim, .ctl, .lvproj, .lvclass, and .lvlib files (case-insensitive). Skip .llb archives and symbolic links below the root. A '#wirelint RULE-ID' directive in a VI block-diagram free label or on a standalone line in an XML file's own description skips that enabled rule for that file and is reported on stdout. Directive lines alone do not satisfy file-description. All built-in rules are enabled by default, including saved-version with a minimum saved LabVIEW version of 20.0 and no maximum. The class-mutation-history rule warns when an .lvclass contains mutation-history content in its NI.LVClass.Geneology XML property. The orphaned-vi rule resolves owner paths relative to the VI file and library member URLs relative to the library file. Library VI items without a URL attribute are skipped. The connector-pane-pattern rule skips global and polymorphic VIs without a connector pane. The auto-error-handling rule skips global and polymorphic VIs because they have no executable diagram of their own. Configure inclusive minimum-version and/or maximum-version bounds in YAML; a maximum-only configuration has no minimum. The debugging-status rule flags VIs with debugging enabled by default; set fail-when: disabled in YAML to reverse the check. The no-breakpoints rule reports VIs saved with block diagram breakpoints as errors by default. Print the scan type on stdout. Show summary totals and elapsed scan time by default; use --verbose for individual findings, without listing every discovered path. Elapsed time covers discovery and analysis, excluding configuration loading and final report rendering. Analysis errors always include file details. Exit status: 0 = success, 1 = threshold reached, 2 = configuration, I/O, or analysis error. Unsupported binary formats are errors, never passing checks."
    )]
    Scan {
        /// Folder to scan.
        #[arg(value_name = "FOLDER")]
        folder: PathBuf,
        /// Explicit YAML file for rules and exclude-folders; no automatic discovery.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Failure threshold; overrides YAML (default: error). 'none' still fails on analysis errors.
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Print individual findings in addition to summary totals.
        #[arg(short, long)]
        verbose: bool,
        /// CI report format; requires --output. Terminal output is unchanged.
        #[arg(long, value_enum, requires = "output")]
        format: Option<ScanFormat>,
        /// Write the CI report to FILE (overwrite); requires --format. Parent must exist.
        #[arg(long, value_name = "FILE", requires = "format")]
        output: Option<PathBuf>,
    },
    /// Discover LabVIEW files and run enabled security analysis rules.
    #[command(
        long_about = "Recursively analyze the same file types as 'scan', using a separate security-focused rule registry (see 'wirelint rules'). Print the scan type on stdout. The hardcoded-secret-default rule checks VI string defaults and scalar block-diagram string constants for credentials (credential-named controls and constants, key/value assignments, URL credentials, private keys, and well-known token formats) and does not report the stored value. The system-exec-command-input rule reviews front-panel control influence on NI System Exec.vi command input through direct wires or Concatenate Strings. Calls alone and constant-only commands are not findings. Unsupported call-link layouts or command paths are analysis errors, even with --fail-on none. Findings mean 'needs review', not 'confirmed exploitable'. Use --format gitlab-sast to write a GitLab Security Report Schema report for artifacts:reports:sast. Exit status: 0 = success, 1 = threshold reached, 2 = configuration, I/O, or analysis error."
    )]
    Sast {
        /// Folder to scan.
        #[arg(value_name = "FOLDER")]
        folder: PathBuf,
        /// Explicit YAML file for rules and exclude-folders; no automatic discovery.
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Failure threshold; overrides YAML (default: error). 'none' still fails on analysis errors.
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
        /// Print individual findings in addition to summary totals.
        #[arg(short, long)]
        verbose: bool,
        /// CI report format; requires --output. Terminal output is unchanged.
        #[arg(long, value_enum, requires = "output")]
        format: Option<Format>,
        /// Write the CI report to FILE (overwrite); requires --format. Parent must exist.
        #[arg(long, value_name = "FILE", requires = "format")]
        output: Option<PathBuf>,
    },
    /// List built-in rule IDs, descriptions, and default severities.
    Rules,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScanFormat {
    /// GitLab Code Quality JSON; line 1 is a file-level placeholder.
    #[value(name = "gitlab-code-quality", alias = "gitlab")]
    Gitlab,
    /// SARIF 2.1.0 for GitHub code scanning, with file-only locations.
    Sarif,
}

impl From<ScanFormat> for Format {
    fn from(format: ScanFormat) -> Self {
        match format {
            ScanFormat::Gitlab => Self::Gitlab,
            ScanFormat::Sarif => Self::Sarif,
        }
    }
}

/// Executes the command and returns the process status, propagating I/O errors.
pub fn run(cli: Cli, output: &mut impl Write, errors: &mut impl Write) -> io::Result<u8> {
    match cli.command {
        Command::Rules => {
            for (registry, rules) in [("scan", QUALITY_BUILT_INS), ("sast", SAST_BUILT_INS)] {
                for rule in rules {
                    let cwe = rule.cwe();
                    writeln!(
                        output,
                        "{} [{registry}, {}]{}: {}",
                        rule.id(),
                        rule.default_severity(),
                        if cwe.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", cwe.join(", "))
                        },
                        rule.description()
                    )?;
                }
            }
            Ok(0)
        }
        Command::Scan {
            folder,
            config,
            fail_on,
            verbose,
            format,
            output: destination,
        } => run_rules(
            folder,
            config,
            fail_on,
            verbose,
            format.map(Format::from),
            destination,
            "scan (quality)",
            QUALITY_BUILT_INS,
            output,
            errors,
        ),
        Command::Sast {
            folder,
            config,
            fail_on,
            verbose,
            format,
            output: destination,
        } => run_rules(
            folder,
            config,
            fail_on,
            verbose,
            format,
            destination,
            "sast (security)",
            SAST_BUILT_INS,
            output,
            errors,
        ),
    }
}

/// Discovers files, runs `rules`, prints the terminal summary, and optionally
/// writes a CI report, identifying the active command and rule registry.
#[allow(clippy::too_many_arguments)]
fn run_rules(
    folder: PathBuf,
    config_path: Option<PathBuf>,
    fail_on: Option<FailOn>,
    verbose: bool,
    format: Option<Format>,
    destination: Option<PathBuf>,
    scan_type: &str,
    rules: &[&dyn Rule],
    output: &mut impl Write,
    errors: &mut impl Write,
) -> io::Result<u8> {
    let config = config_path
        .as_deref()
        .map(|path| Config::load_for(path, rules))
        .transpose()?
        .unwrap_or_default();
    let fail_on = fail_on.unwrap_or(config.fail_on);
    let started = Instant::now();
    let wall_clock_started = SystemTime::now();
    let files = scan::discover_files(&folder, &config.exclude_folders)?;
    if files.is_empty() {
        writeln!(output, "No supported LabVIEW files found.")?;
    } else {
        writeln!(
            output,
            "Found {} supported LabVIEW file(s). Running enabled rules...",
            files.len()
        )?;
    }
    writeln!(output, "Scan type: {scan_type}")?;
    output.flush()?;
    let report = analysis::analyze(&folder, &files, &config, rules);
    let wall_clock_finished = SystemTime::now();
    let elapsed = started.elapsed();
    if verbose {
        for finding in &report.findings {
            writeln!(
                output,
                "{}: {} [{}]: {}",
                finding.path.display(),
                finding.severity,
                finding.rule,
                finding.message
            )?;
        }
    }
    for skipped in &report.skipped {
        writeln!(
            output,
            "{}: skipped [{}] (#wirelint directive)",
            skipped.path.display(),
            skipped.rule
        )?;
    }
    for error in &report.errors {
        writeln!(
            errors,
            "{}: analysis error: {}",
            error.path.display(),
            error.message
        )?;
    }
    write_summary(&report, elapsed, output)?;
    if let (Some(format), Some(destination)) = (format, destination) {
        check_destination(&destination, &folder, &files, config_path.as_deref())?;
        let bytes = reports::render(
            &report,
            format,
            rules,
            reports::ScanTimes {
                started_at: wall_clock_started,
                finished_at: wall_clock_finished,
            },
        )?;
        fs::write(&destination, bytes).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot write report '{}': {error}", destination.display()),
            )
        })?;
    }
    Ok(report.exit_status(fail_on))
}

/// Rejects existing destinations that resolve to an input file or configuration.
///
/// Canonicalization catches alternate spellings and symbolic links. New files
/// are allowed; other inspection errors propagate rather than disabling checks.
fn check_destination(
    destination: &Path,
    root: &Path,
    files: &[PathBuf],
    config: Option<&Path>,
) -> io::Result<()> {
    let target = match fs::canonicalize(destination) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "cannot inspect report destination '{}': {error}",
                    destination.display()
                ),
            ));
        }
    };
    for input in files
        .iter()
        .map(|path| root.join(path))
        .chain(config.map(Path::to_path_buf))
    {
        if fs::canonicalize(&input)? == target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "report destination would overwrite input '{}'",
                    input.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Writes totals and elapsed scan time without individual file paths.
///
/// Omits empty breakdowns and sorts rule IDs independently of finding order.
/// Analysis errors are counted separately from finding severities. The caller
/// supplies the scan duration, excluding report rendering. Propagates output errors.
fn write_summary(
    report: &analysis::Report,
    elapsed: Duration,
    output: &mut impl Write,
) -> io::Result<()> {
    writeln!(
        output,
        "Analyzed {} file(s); {} finding(s); {} analysis error(s).",
        report.analyzed,
        report.findings.len(),
        report.errors.len()
    )?;
    writeln!(output, "Elapsed scan time: {:.3} s.", elapsed.as_secs_f64())?;
    if report.findings.is_empty() {
        return Ok(());
    }

    let mut info = 0_usize;
    let mut warning = 0_usize;
    let mut error = 0_usize;
    let mut rules = BTreeMap::new();
    for finding in &report.findings {
        match finding.severity {
            Severity::Info => info += 1,
            Severity::Warning => warning += 1,
            Severity::Error => error += 1,
        }
        *rules.entry(finding.rule).or_insert(0_usize) += 1;
    }
    writeln!(
        output,
        "Findings by severity: {info} info; {warning} warning; {error} error."
    )?;
    writeln!(output, "Findings by rule:")?;
    for (rule, count) in rules {
        writeln!(output, "  {rule}: {count} finding(s).")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn accepts_scan_configuration_and_threshold() {
        let cli = Cli::try_parse_from([
            "wirelint",
            "scan",
            "project",
            "--config",
            "checks.yaml",
            "--fail-on",
            "warning",
            "--verbose",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, Command::Scan { folder, config: Some(config), fail_on: Some(FailOn::Warning), verbose: true, .. }
            if folder == std::path::Path::new("project") && config == std::path::Path::new("checks.yaml"))
        );
        assert!(matches!(
            Cli::try_parse_from(["wirelint", "scan", "project"])
                .unwrap()
                .command,
            Command::Scan { verbose: false, .. }
        ));
        assert!(matches!(
            Cli::try_parse_from(["wirelint", "scan", "project", "-v"])
                .unwrap()
                .command,
            Command::Scan { verbose: true, .. }
        ));
        assert!(Cli::try_parse_from(["wirelint", "scan", ".", "--fail-on", "info"]).is_err());
    }

    #[test]
    fn accepts_canonical_and_legacy_gitlab_code_quality_names() {
        for format in ["gitlab-code-quality", "gitlab"] {
            assert!(
                Cli::try_parse_from([
                    "wirelint",
                    "scan",
                    ".",
                    "--format",
                    format,
                    "--output",
                    "report.json"
                ])
                .is_ok(),
                "{format}"
            );
        }
    }

    #[test]
    fn help_describes_rules_and_exit_behavior() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .unwrap()
            .render_long_help()
            .to_string();
        for expected in [
            "--config",
            "--fail-on",
            "2 =",
            ".ctl",
            "default: error",
            "symbolic links",
            "without listing every discovered path",
            "Print the scan type on stdout",
            "exclude-folders",
            "--verbose",
            "summary totals and elapsed scan time by default",
            "excluding configuration loading and final report rendering",
            "Analysis errors always include file details",
            "minimum saved LabVIEW version of 20.0",
            "saved-version",
            "class-mutation-history",
            "contains mutation-history content in its NI.LVClass.Geneology XML property",
            "owner paths relative to the VI file",
            "library member URLs relative to the library file",
            "Library VI items without a URL attribute are skipped",
            "connector-pane-pattern rule skips global and polymorphic VIs",
            "auto-error-handling rule skips global and polymorphic VIs",
            "#wirelint RULE-ID",
            "XML file's own description",
            "Directive lines alone do not satisfy file-description",
            "maximum-version",
            "maximum-only configuration has no minimum",
            "debugging-status",
            "fail-when: disabled",
            "--format",
            "--output",
            "gitlab",
            "gitlab-code-quality",
            "sarif",
            "line 1",
            "file-only",
        ] {
            assert!(help.contains(expected), "{expected}: {help}");
        }
        assert!(help.contains("gitlab"), "{help}");
        assert!(!help.contains("gitlab-sast"), "{help}");
        let help = command
            .find_subcommand_mut("sast")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("Print the scan type on stdout"), "{help}");
        assert!(help.contains("block-diagram string constants"), "{help}");
        assert!(help.contains("gitlab-sast"), "{help}");
    }

    #[test]
    fn summary_counts_severities_and_rules_without_individual_paths() {
        let report = analysis::Report {
            analyzed: 3,
            findings: [
                ("z-rule", Severity::Warning),
                ("a-rule", Severity::Error),
                ("z-rule", Severity::Warning),
                ("a-rule", Severity::Info),
                ("z-rule", Severity::Error),
            ]
            .into_iter()
            .map(|(rule, severity)| analysis::Finding {
                path: PathBuf::from("private-path.vi"),
                rule,
                severity,
                message: "Individual detail".to_owned(),
            })
            .collect(),
            errors: Vec::new(),
            skipped: Vec::new(),
        };
        let mut output = Vec::new();
        write_summary(&report, Duration::from_millis(1234), &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            [
                "Analyzed 3 file(s); 5 finding(s); 0 analysis error(s).",
                "Elapsed scan time: 1.234 s.",
                "Findings by severity: 1 info; 2 warning; 2 error.",
                "Findings by rule:",
                "  a-rule: 2 finding(s).",
                "  z-rule: 3 finding(s).",
            ]
        );
    }

    #[test]
    fn summary_omits_empty_breakdowns_and_keeps_analysis_errors_separate() {
        let report = analysis::Report {
            errors: vec![analysis::AnalysisError {
                path: PathBuf::from("broken.vi"),
                message: "Cannot parse".to_owned(),
            }],
            ..analysis::Report::default()
        };
        let mut output = Vec::new();
        write_summary(&report, Duration::ZERO, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .lines()
                .collect::<Vec<_>>(),
            [
                "Analyzed 0 file(s); 0 finding(s); 1 analysis error(s).",
                "Elapsed scan time: 0.000 s.",
            ]
        );
    }
}
