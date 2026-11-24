//! End-to-end coverage of configuration, analysis, output, and process status.

mod support;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIRECTORY_ID: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        loop {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("wirelint-cli-test-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create test directory: {error}"),
            }
        }
    }

    fn write(&self, name: &str, content: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    fn scan(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wirelint"))
            .arg("scan")
            .arg(&self.0)
            .args(args)
            .output()
            .unwrap()
    }

    fn configured_scan(&self, config: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_wirelint"))
            .arg("scan")
            .arg(&self.0)
            .arg("--config")
            .arg(config)
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("cannot clean up test directory");
    }
}

/// Checks the variable elapsed-time line and returns the deterministic scan output.
fn scan_lines_without_timing(stdout: &str) -> Vec<&str> {
    let lines: Vec<_> = stdout.lines().collect();
    let timings: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("Elapsed scan time: "))
        .collect();
    assert_eq!(timings.len(), 1, "{stdout}");
    let seconds: f64 = timings[0].strip_suffix(" s.").unwrap().parse().unwrap();
    assert!(seconds.is_finite() && seconds >= 0.0, "{stdout}");
    lines
        .into_iter()
        .filter(|line| !line.starts_with("Elapsed scan time: "))
        .collect()
}

/// Constructs a format-3 VI with LVSR and, by default, a nonempty STRG description.
fn vi_with_separation(enabled: bool, kind: &[u8; 4]) -> Vec<u8> {
    vi_with_description_and_password(enabled, kind, Some(b"Fixture VI description"), None)
}

fn vi_without_description(enabled: bool, kind: &[u8; 4]) -> Vec<u8> {
    vi_with_description_and_password(enabled, kind, None, None)
}

fn vi_with_description(enabled: bool, kind: &[u8; 4], description: Option<&[u8]>) -> Vec<u8> {
    vi_with_description_and_password(enabled, kind, description, None)
}

fn vi_with_password(enabled: bool, kind: &[u8; 4]) -> Vec<u8> {
    vi_with_description_and_password(
        enabled,
        kind,
        Some(b"Fixture VI description"),
        Some(&[1; 16]),
    )
}

fn vi_with_description_and_password(
    enabled: bool,
    kind: &[u8; 4],
    description: Option<&[u8]>,
    password_hashes: Option<&[u8]>,
) -> Vec<u8> {
    vi_with_diagram(enabled, kind, description, password_hashes, None)
}

/// Constructs a VI with an optional compressed version-b diagram heap.
fn vi_with_diagram(
    enabled: bool,
    kind: &[u8; 4],
    description: Option<&[u8]>,
    password_hashes: Option<&[u8]>,
    heap: Option<&[u8]>,
) -> Vec<u8> {
    let description_size = description.map_or(0, |text| 8 + text.len());
    let password_record_offset = 72 + description_size;
    let password_size = password_hashes.map_or(0, |hashes| 4 + hashes.len());
    let diagram = heap.map(|heap| {
        let mut plain = (heap.len() as u32).to_be_bytes().to_vec();
        plain.extend_from_slice(heap);
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&plain).unwrap();
        let mut compressed = (plain.len() as u32).to_be_bytes().to_vec();
        compressed.extend(encoder.finish().unwrap());
        compressed
    });
    let diagram_offset = password_record_offset + password_size;
    let diagram_size = diagram.as_ref().map_or(0, |payload| 4 + payload.len());
    let mut resources = vec![(b"LVSR", 0)];
    if description.is_some() {
        resources.push((b"STRG", 72));
    }
    if password_hashes.is_some() {
        resources.push((b"BDPW", password_record_offset));
    }
    if diagram.is_some() {
        resources.push((b"BDHb", diagram_offset));
    }
    let block_count = resources.len();
    let data_size = diagram_offset + diagram_size;
    let table_size = 4 + block_count * 12;
    let info_size = 52 + table_size + block_count * 20;
    let info_offset = 32 + data_size;
    let mut bytes = vec![0; info_offset + info_size];
    for header in [0, info_offset] {
        bytes[header..header + 16].copy_from_slice(b"RSRC\r\n\0\x03LVINLBVW");
        bytes[header + 8..header + 12].copy_from_slice(kind);
        put_u32(&mut bytes, header + 16, info_offset as u32);
        put_u32(&mut bytes, header + 20, info_size as u32);
        put_u32(&mut bytes, header + 24, 32);
        put_u32(&mut bytes, header + 28, data_size as u32);
    }
    let flags: u32 = if enabled { 1 << 10 } else { 0 };
    put_u32(&mut bytes, 32, 68);
    put_u32(&mut bytes, 36, 0x20008000);
    put_u32(&mut bytes, 44, flags);

    put_u32(&mut bytes, info_offset + 40, 32);
    put_u32(&mut bytes, info_offset + 44, 52);
    put_u32(&mut bytes, info_offset + 48, info_size as u32);
    let table = info_offset + 52;
    put_u32(&mut bytes, table, (block_count - 1) as u32);
    for (index, (id, data_offset)) in resources.iter().enumerate() {
        let entry = table + 4 + index * 12;
        let section = table + table_size + index * 20;
        bytes[entry..entry + 4].copy_from_slice(*id);
        put_u32(&mut bytes, entry + 8, (table_size + index * 20) as u32);
        put_u32(&mut bytes, section + 4, u32::MAX);
        put_u32(&mut bytes, section + 12, *data_offset as u32);
    }
    if let Some(description) = description {
        let record = 32 + 72;
        put_u32(&mut bytes, record, (4 + description.len()) as u32);
        put_u32(&mut bytes, record + 4, description.len() as u32);
        bytes[record + 8..record + 8 + description.len()].copy_from_slice(description);
    }
    if let Some(hashes) = password_hashes {
        let record = 32 + password_record_offset;
        put_u32(&mut bytes, record, hashes.len() as u32);
        bytes[record + 4..record + 4 + hashes.len()].copy_from_slice(hashes);
    }
    if let Some(diagram) = diagram {
        let record = 32 + diagram_offset;
        put_u32(&mut bytes, record, diagram.len() as u32);
        bytes[record + 4..record + 4 + diagram.len()].copy_from_slice(&diagram);
    }
    bytes
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

/// Appends one BDHb heap node: open/self-closing/close scope 0/1/2.
///
/// Mirrors the private encoding covered at the unit level in
/// `src/formats/heap.rs`, so integration tests can build minimal diagrams
/// without exporting that encoder from the crate.
fn heap_node(heap: &mut Vec<u8>, tag: i32, scope: u8, class: Option<i16>, content: &[u8]) {
    let tag = (tag + 31) as u16;
    let size = if content.is_empty() { 0 } else { 6 };
    heap.push((size << 5) | (u8::from(class.is_some()) << 4) | (scope << 2) | (tag >> 8) as u8);
    heap.push(tag as u8);
    if let Some(class) = class {
        heap.extend_from_slice(&[1, 0xfe]);
        heap.extend_from_slice(&class.to_be_bytes());
    }
    if !content.is_empty() {
        heap.push(content.len() as u8);
        heap.extend_from_slice(content);
    }
}

/// Appends one front-panel terminal (`fPTerm`) with the given `objFlags`.
fn heap_terminal(heap: &mut Vec<u8>, object_flags: u32) {
    const ARRAY_ELEMENT: i32 = -6;
    const FP_TERM: i32 = 22;
    const OBJ_FLAGS: i32 = 172;
    heap_node(heap, ARRAY_ELEMENT, 0, Some(FP_TERM as i16), &[]);
    heap_node(heap, OBJ_FLAGS, 1, None, &object_flags.to_be_bytes());
    heap_node(heap, ARRAY_ELEMENT, 2, None, &[]);
}

#[test]
fn terminal_style_defaults_to_requiring_data_type_style_and_honors_configuration() {
    const ICON_STYLE: u32 = 0x0402_0040;
    const DATA_STYLE: u32 = 0x0002_0040;
    let directory = TestDirectory::new();

    let mut all_icon = Vec::new();
    heap_terminal(&mut all_icon, ICON_STYLE);
    heap_terminal(&mut all_icon, ICON_STYLE);
    directory.write(
        "all-icon.vi",
        vi_with_diagram(true, b"LVIN", None, None, Some(&all_icon)),
    );

    let mut all_data = Vec::new();
    heap_terminal(&mut all_data, DATA_STYLE);
    directory.write(
        "all-data.vi",
        vi_with_diagram(true, b"LVIN", None, None, Some(&all_data)),
    );

    let mut mixed = Vec::new();
    heap_terminal(&mut mixed, ICON_STYLE);
    heap_terminal(&mut mixed, DATA_STYLE);
    directory.write(
        "mixed.vi",
        vi_with_diagram(true, b"LVIN", None, None, Some(&mixed)),
    );

    let output = directory.scan(&["--fail-on", "warning", "--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(
            "all-icon.vi: warning [terminal-style]: This VI has 2 terminal(s) not using data type display."
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "mixed.vi: warning [terminal-style]: This VI has 1 terminal(s) not using data type display."
        ),
        "{stdout}"
    );
    assert!(!stdout.contains("all-data.vi: warning [terminal-style]"));
    assert!(stdout.contains("terminal-style: 2 finding(s)."));

    let config = directory.write(
        "icon-preferred.yaml",
        "version: 1\nrules:\n  terminal-style:\n    preferred-style: icon\n",
    );
    let output = directory.configured_scan(&config, &["--fail-on", "warning", "--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(
            "all-data.vi: warning [terminal-style]: This VI has 1 terminal(s) not using icon display."
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "mixed.vi: warning [terminal-style]: This VI has 1 terminal(s) not using icon display."
        ),
        "{stdout}"
    );
    assert!(!stdout.contains("all-icon.vi: warning [terminal-style]"));
    assert!(stdout.contains("terminal-style: 2 finding(s)."));
}

#[test]
fn bookmark_skips_only_the_named_enabled_rule_and_is_always_reported() {
    let directory = TestDirectory::new();
    // Diagram -> zPlaneList -> free label -> text record -> text.
    let text = b"#wirelint file-description";
    let mut heap = vec![
        0x10,
        0x18,
        1,
        0xfe,
        0,
        27,
        0x01,
        0x4e,
        0x10,
        0x19,
        1,
        0xfe,
        0,
        10,
        0x11,
        0x2d,
        1,
        0xfe,
        0,
        1,
        0xc4,
        0x22,
        text.len() as u8,
    ];
    heap.extend_from_slice(text);
    heap.extend_from_slice(&[0x09, 0x2d, 0x08, 0x19, 0x09, 0x4e, 0x08, 0x18]);
    directory.write(
        "ignored.vi",
        vi_with_diagram(false, b"LVIN", None, None, Some(&heap)),
    );
    directory.write("ordinary.vi", vi_without_description(false, b"LVIN"));
    let output = directory.scan(&["--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("ignored.vi: skipped [file-description]"),
        "{stdout}"
    );
    assert!(stdout.contains("file-description: 1 finding(s)."));
    assert!(stdout.contains("separate-compiled-code: 2 finding(s)."));

    let config = directory.write(
        "disabled.yaml",
        "version: 1\nrules:\n  file-description:\n    enabled: false\n",
    );
    let output = directory.configured_scan(&config, &[]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("skipped [file-description]"));
}

#[test]
fn malformed_block_diagram_is_an_analysis_error() {
    let directory = TestDirectory::new();
    directory.write(
        "broken.vi",
        vi_with_diagram(true, b"LVIN", None, None, Some(&[0x08, 24])),
    );
    let output = directory.scan(&["--fail-on", "none"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("broken.vi: analysis error:"), "{stderr}");
    assert!(stderr.contains("BDHb"), "{stderr}");
}

#[test]
fn xml_description_directives_skip_only_owner_rules_in_both_output_modes() {
    let directory = TestDirectory::new();
    for (extension, root, property) in [
        ("lvproj", "Project", "NI.Project.Description"),
        ("lvlib", "Library", "NI.Lib.Description"),
        ("LVCLASS", "LVClass", "NI.Lib.Description"),
    ] {
        let mutation_history = if root == "LVClass" {
            r#"<Property Name="NI.LVClass.Geneology" Type="Xml"/>"#
        } else {
            ""
        };
        directory.write(&format!("suppressed.{extension}"), format!(
            r#"<{root} LVVersion="19008000">{mutation_history}<Property Name="{property}" Type="Str">Shared drivers.
#wirelint saved-version
  #wirelint separate-compiled-code
#wirelint saved-version
#wirelint unknown-rule
</Property></{root}>"#,
        ));
    }
    directory.write("ordinary.lvproj", r#"<Project LVVersion="20008000">
        <Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property>
        <Item><Property Name="NI.Project.Description" Type="Str">#wirelint file-description</Property></Item>
    </Project>"#);
    for verbose in [false, true] {
        let destination = directory.0.join("report.json");
        let mut args = vec![
            "--fail-on",
            "warning",
            "--format",
            "gitlab-code-quality",
            "--output",
            destination.to_str().unwrap(),
        ];
        if verbose {
            args.push("--verbose");
        }
        let output = directory.scan(&args);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.matches(": skipped [").count(), 6, "{stdout}");
        assert!(!stdout.contains("skipped [unknown-rule]"), "{stdout}");
        assert!(!stdout.contains("ordinary.lvproj: skipped"), "{stdout}");
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(destination).unwrap()).unwrap();
        let findings = report.as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["check_name"], "file-description");
        assert_eq!(findings[0]["location"]["path"], "ordinary.lvproj");
    }
    let config = directory.write(
        "config.yaml",
        "version: 1\nrules:\n  file-description:\n    enabled: false\n",
    );
    let output = directory.configured_scan(&config, &["--fail-on", "warning"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches(": skipped [").count(), 6, "{stdout}");
}

#[test]
fn xml_directives_alone_do_not_satisfy_file_description_or_hide_analysis_errors() {
    let directory = TestDirectory::new();
    for (extension, root, property) in [
        ("lvproj", "Project", "NI.Project.Description"),
        ("lvlib", "Library", "NI.Lib.Description"),
        ("lvclass", "LVClass", "NI.Lib.Description"),
    ] {
        let mutation_history = if root == "LVClass" {
            r#"<Property Name="NI.LVClass.Geneology" Type="Xml"/>"#
        } else {
            ""
        };
        directory.write(
            &format!("empty.{extension}"),
            format!(
                r#"<{root} LVVersion="19008000">{mutation_history}
                <Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property>
                <Property Name="{property}" Type="Str">#wirelint saved-version</Property>
            </{root}>"#,
            ),
        );
    }
    let output = directory.scan(&["--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("file-description: 3 finding(s)."),
        "{stdout}"
    );
    assert_eq!(stdout.matches(": skipped [saved-version]").count(), 3);

    directory.write(
        "explicit.lvproj",
        r#"<Project LVVersion="20008000">
        <Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property>
        <Property Name="NI.Project.Description" Type="Str">#wirelint file-description</Property>
    </Project>"#,
    );
    let output = directory.scan(&["--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("explicit.lvproj: skipped [file-description]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("file-description: 3 finding(s)."),
        "{stdout}"
    );

    directory.write(
        "broken.lvproj",
        r#"<Project>
        <Property Name="NI.Project.Description" Type="Str">#wirelint saved-version</Property>
    </Project>"#,
    );
    let output = directory.scan(&["--fail-on", "none"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("broken.lvproj: analysis error: missing root LVVersion attribute"),
        "{stderr}"
    );
}

#[test]
fn scans_binary_flags_across_the_vi_family_without_modifying_files() {
    let directory = TestDirectory::new();
    let cases = [
        ("a.vi", false, b"LVIN"),
        ("b.VIT", true, b"sVIN"),
        ("c.vim", false, b"LVIN"),
        ("d.ctl", true, b"LVCC"),
    ];
    for (name, enabled, kind) in cases {
        directory.write(name, vi_with_separation(enabled, kind));
    }
    let output = directory.scan(&["--verbose", "--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    scan_lines_without_timing(&stdout);
    assert!(stdout.contains("Analyzed 4 file(s); 2 finding(s); 0 analysis error(s)."));
    for (name, enabled, kind) in cases {
        assert_eq!(
            stdout.contains(&format!("{name}: warning [separate-compiled-code]")),
            !enabled
        );
        assert_eq!(
            fs::read(directory.0.join(name)).unwrap(),
            vi_with_separation(enabled, kind)
        );
    }
}

#[test]
fn debugging_status_defaults_to_enabled_and_supports_reversed_or_disabled_policy() {
    let directory = TestDirectory::new();
    for (extension, kind) in [("VI", b"LVIN"), ("vit", b"sVIN"), ("vim", b"LVIN")] {
        for enabled in [false, true] {
            let mut bytes = vi_with_separation(true, kind);
            put_u32(&mut bytes, 36 + 24, if enabled { 1 << 9 } else { 0 });
            directory.write(&format!("{enabled}.{extension}"), bytes);
        }
    }
    let mut control = vi_with_separation(true, b"LVCC");
    put_u32(&mut control, 36 + 24, 1 << 9);
    directory.write("ignored.ctl", control);
    for (extension, root) in [
        ("lvproj", "Project"),
        ("lvlib", "Library"),
        ("lvclass", "LVClass"),
    ] {
        let property = if root == "Project" {
            "NI.Project.Description"
        } else {
            "NI.Lib.Description"
        };
        let mutation_history = if root == "LVClass" {
            r#"<Property Name="NI.LVClass.Geneology" Type="Xml"/>"#
        } else {
            ""
        };
        directory.write(
            &format!("ignored.{extension}"),
            format!(r#"<{root} LVVersion="20008000">{mutation_history}<Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property><Property Name="{property}" Type="Str">Description</Property></{root}>"#),
        );
    }

    for (args, status) in [
        (vec!["--verbose"], 0),
        (vec!["--verbose", "--fail-on", "warning"], 1),
    ] {
        let output = directory.scan(&args);
        assert_eq!(output.status.code(), Some(status));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains("Analyzed 10 file(s); 3 finding(s); 0 analysis error(s)."),
            "{stdout}"
        );
        for extension in ["VI", "vit", "vim"] {
            assert!(stdout.contains(&format!(
                "true.{extension}: warning [debugging-status]: Debugging is enabled. Disable"
            )));
            assert!(!stdout.contains(&format!("false.{extension}:")));
        }
        assert!(!stdout.contains("ignored."));
    }

    let config = directory.write(
        "checks.yaml",
        "rules:\n  debugging-status:\n    fail-when: disabled\n    severity: error\n",
    );
    let report = directory.0.join("report.json");
    let output = directory.configured_scan(
        &config,
        &[
            "--verbose",
            "--format",
            "sarif",
            "--output",
            report.to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 10 file(s); 3 finding(s); 0 analysis error(s)."));
    for extension in ["VI", "vit", "vim"] {
        assert!(stdout.contains(&format!(
            "false.{extension}: error [debugging-status]: Debugging is disabled. Enable"
        )));
        assert!(!stdout.contains(&format!("true.{extension}:")));
    }
    assert!(!stdout.contains("ignored."));
    let json: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    let results = json["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    assert!(
        results
            .iter()
            .all(|finding| finding["ruleId"] == "debugging-status" && finding["level"] == "error")
    );

    fs::write(&config, "rules:\n  debugging-status:\n    enabled: false\n").unwrap();
    let output = directory.configured_scan(&config, &["--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 10 file(s); 0 finding(s); 0 analysis error(s)."));
}

#[test]
fn breakpoints_fail_by_default_but_controls_are_not_checked() {
    let directory = TestDirectory::new();
    let mut breakpoint_vi = vi_with_separation(true, b"LVIN");
    put_u32(&mut breakpoint_vi, 36 + 24, 0x2000_0000);
    directory.write("with-breakpoint.vi", breakpoint_vi);
    directory.write("without-breakpoint.vi", vi_with_separation(true, b"LVIN"));
    let mut breakpoint_control = vi_with_separation(true, b"LVCC");
    put_u32(&mut breakpoint_control, 36 + 24, 0x2000_0000);
    directory.write("control.ctl", breakpoint_control);

    let output = directory.scan(&["--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 3 file(s); 1 finding(s); 0 analysis error(s)."));
    assert!(stdout.contains(
        "with-breakpoint.vi: error [no-breakpoints]: Remove all block diagram breakpoints before committing this VI."
    ));
    assert!(!stdout.contains("without-breakpoint.vi:"));
    assert!(!stdout.contains("control.ctl:"));
}

#[test]
fn password_findings_are_warnings_and_follow_the_failure_threshold() {
    let directory = TestDirectory::new();
    directory.write("protected.vi", vi_with_password(true, b"LVIN"));
    directory.write("clear.vi", vi_with_separation(true, b"LVIN"));

    let output = directory.scan(&["--verbose"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 2 file(s); 1 finding(s); 0 analysis error(s)."));
    assert!(stdout.contains(
        "protected.vi: warning [password-set]: This VI has a password set. Remove it if the VI should remain editable."
    ));
    assert!(!stdout.contains("clear.vi:"));

    let output = directory.scan(&["--verbose", "--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("protected.vi: warning [password-set]")
    );

    let config = directory.write(
        "checks.yaml",
        "rules:\n  password-set:\n    severity: error\n",
    );
    let output = directory.configured_scan(&config, &["--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("protected.vi: error [password-set]")
    );

    fs::write(&config, "rules:\n  password-set:\n    enabled: false\n").unwrap();
    let output = directory.configured_scan(&config, &["--verbose", "--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("[password-set]")
    );
}

#[test]
fn automatic_error_handling_fails_only_for_vi_files_with_the_flag_set() {
    let directory = TestDirectory::new();
    let mut enabled = vi_with_separation(true, b"LVIN");
    let flags = u32::from_be_bytes(enabled[44..48].try_into().unwrap());
    enabled[44..48].copy_from_slice(&(flags | 0x2000_0000).to_be_bytes());
    directory.write("enabled.vi", enabled);
    directory.write("disabled.vi", vi_with_separation(true, b"LVIN"));
    let mut control = vi_with_separation(true, b"LVCC");
    let flags = u32::from_be_bytes(control[44..48].try_into().unwrap());
    control[44..48].copy_from_slice(&(flags | 0x2000_0000).to_be_bytes());
    directory.write("control.ctl", control);

    let output = directory.scan(&["--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 3 file(s); 1 finding(s); 0 analysis error(s)."));
    assert!(stdout.contains(
        "enabled.vi: error [auto-error-handling]: Automatic error handling is enabled. Disable 'Enable automatic error handling' in VI Properties > Execution."
    ));
    assert!(!stdout.contains("disabled.vi:"));
    assert!(!stdout.contains("control.ctl:"));
}

#[test]
fn automatic_error_handling_skips_global_and_polymorphic_fixtures() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality")
        .join("auto-error-handling");
    let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("scan")
        .arg(&fixtures)
        .arg("--verbose")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert!(stdout.contains("Analyzed 3 file(s)"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
    assert!(
        stdout.contains("enabled.vi: error [auto-error-handling]"),
        "{stdout}"
    );
    assert_eq!(
        stdout.matches(": error [auto-error-handling]").count(),
        1,
        "{stdout}"
    );
}

#[test]
fn scans_xml_and_applies_yaml_severity_and_cli_threshold() {
    let directory = TestDirectory::new();
    directory.write(
        "a.lvproj",
        r#"<Project LVVersion="20008000"><Property Name="NI.Project.Description" Type="Str">Project documentation</Property></Project>"#,
    );
    directory.write(
        "b.LVCLASS",
        r#"<LVClass LVVersion="20008000"><Property Name="NI.LVClass.Geneology" Type="Xml"/><Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property><Property Name="NI.Lib.Description" Type="Str">Class documentation</Property></LVClass>"#,
    );
    directory.write(
        "c.lvlib",
        r#"<Library LVVersion="20008000"><Property Name="NI.LV.All.SourceOnly" Type="Bool">false</Property><Property Name="NI.Lib.Description" Type="Str">Library documentation</Property></Library>"#,
    );
    let output = directory.scan(&[]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let summary = scan_lines_without_timing(&stdout);
    assert_eq!(
        summary,
        [
            "Found 3 supported LabVIEW file(s). Running enabled rules...",
            "Scan type: scan (quality)",
            "Analyzed 3 file(s); 2 finding(s); 0 analysis error(s).",
            "Findings by severity: 0 info; 2 warning; 0 error.",
            "Findings by rule:",
            "  separate-compiled-code: 2 finding(s).",
        ]
    );
    assert!(output.stderr.is_empty());
    for verbosity in [None, Some("--verbose")] {
        let mut args = vec!["--fail-on", "warning"];
        args.extend(verbosity);
        let output = directory.scan(&args);
        assert_eq!(output.status.code(), Some(1));
        if verbosity.is_some() {
            let verbose = String::from_utf8(output.stdout).unwrap();
            assert!(verbose.contains("a.lvproj: warning [separate-compiled-code]"));
            assert!(verbose.contains("c.lvlib: warning [separate-compiled-code]"));
            assert!(!verbose.contains("b.LVCLASS"));
            assert!(scan_lines_without_timing(&verbose).ends_with(&summary[2..]));
        } else {
            assert_eq!(
                scan_lines_without_timing(&String::from_utf8(output.stdout).unwrap()),
                summary
            );
        }
    }

    let config = directory.write(
        "checks.yaml",
        "version: 1\nfail-on: none\nrules:\n  separate-compiled-code:\n    severity: error\n",
    );
    assert_eq!(
        directory.configured_scan(&config, &[]).status.code(),
        Some(0)
    );
    for args in [
        vec!["--fail-on", "error"],
        vec!["--fail-on", "error", "--verbose"],
    ] {
        let output = directory.configured_scan(&config, &args);
        assert_eq!(output.status.code(), Some(1));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Findings by severity: 0 info; 0 warning; 2 error."));
        assert_eq!(
            stdout.contains("a.lvproj: error [separate-compiled-code]"),
            args.contains(&"--verbose")
        );
    }

    fs::write(
        &config,
        "rules:\n  separate-compiled-code:\n    severity: info\n",
    )
    .unwrap();
    for args in [
        vec!["--fail-on", "warning"],
        vec!["--fail-on", "warning", "--verbose"],
    ] {
        let output = directory.configured_scan(&config, &args);
        assert_eq!(output.status.code(), Some(0));
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("Findings by severity: 2 info; 0 warning; 0 error.")
        );
    }
}

#[test]
fn class_mutation_history_flags_content_but_accepts_absent_or_empty_properties() {
    let directory = TestDirectory::new();
    directory.write("absent.lvclass", "<LVClass/>");
    directory.write(
        "empty.lvclass",
        r#"<LVClass><Property Name="NI.LVClass.Geneology" Type="Xml"/></LVClass>"#,
    );
    directory.write(
        "present.lvclass",
        r#"<LVClass><Property Name="NI.LVClass.Geneology" Type="Xml"><History/></Property></LVClass>"#,
    );
    directory.write(
        "nested.lvclass",
        r#"<LVClass><Item><Property Name="NI.LVClass.Geneology" Type="Xml"><History/></Property></Item></LVClass>"#,
    );
    directory.write(
        "ignored.lvlib",
        r#"<Library><Property Name="NI.LVClass.Geneology" Type="Xml"><History/></Property></Library>"#,
    );
    let config = directory.write(
        "checks.yaml",
        "rules:\n  separate-compiled-code: { enabled: false }\n  saved-version: { enabled: false }\n  file-description: { enabled: false }\n  debugging-status: { enabled: false }\n  no-breakpoints: { enabled: false }\n  auto-error-handling: { enabled: false }\n  password-set: { enabled: false }\n  orphaned-vi: { enabled: false }\n  class-mutation-history: { enabled: true }\n",
    );

    let output = directory.configured_scan(&config, &["--verbose", "--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 5 file(s); 1 finding(s); 0 analysis error(s)."));
    assert!(stdout.contains("present.lvclass: warning [class-mutation-history]"));
    assert!(!stdout.contains("absent.lvclass:"));
    assert!(!stdout.contains("empty.lvclass:"));
    assert!(!stdout.contains("nested.lvclass:"));
    assert!(!stdout.contains("ignored.lvlib:"));
}

#[test]
fn file_description_checks_every_supported_labview_extension() {
    let directory = TestDirectory::new();
    let config = directory.write(
        "checks.yaml",
        "rules:\n  separate-compiled-code:\n    enabled: false\n  saved-version:\n    enabled: false\n  file-description:\n    enabled: true\n",
    );
    for (extension, kind) in [
        ("vi", b"LVIN"),
        ("vit", b"sVIN"),
        ("vim", b"LVIN"),
        ("ctl", b"LVCC"),
    ] {
        directory.write(
            &format!("documented.{extension}"),
            vi_with_description(true, kind, Some(b"File description")),
        );
        directory.write(
            &format!("undocumented.{extension}"),
            vi_without_description(true, kind),
        );
    }
    for (extension, root, property) in [
        ("lvproj", "Project", "NI.Project.Description"),
        ("lvclass", "LVClass", "NI.Lib.Description"),
        ("lvlib", "Library", "NI.Lib.Description"),
    ] {
        let mutation_history = if root == "LVClass" {
            r#"<Property Name="NI.LVClass.Geneology" Type="Xml"/>"#
        } else {
            ""
        };
        directory.write(
            &format!("documented.{extension}"),
            format!("<{root}>{mutation_history}<Property Name=\"{property}\" Type=\"Str\">File description</Property></{root}>"),
        );
        directory.write(
            &format!("undocumented.{extension}"),
            format!("<{root}>{mutation_history}</{root}>"),
        );
    }

    let output = directory.configured_scan(&config, &["--verbose", "--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 14 file(s); 7 finding(s); 0 analysis error(s)."));
    for extension in ["vi", "vit", "vim", "ctl", "lvproj", "lvclass", "lvlib"] {
        assert!(
            stdout.contains(&format!(
                "undocumented.{extension}: warning [file-description]"
            )),
            "{stdout}"
        );
        assert!(
            !stdout
                .lines()
                .any(|line| line.starts_with(&format!("documented.{extension}:"))),
            "{stdout}"
        );
    }
}

#[test]
fn analysis_errors_are_explicit_and_do_not_stop_other_files() {
    let directory = TestDirectory::new();
    directory.write("a.vi", b"not an RSRC file");
    directory.write(
        "b.lvproj",
        r#"<Project LVVersion="20008000"><Property Name="NI.Project.Description" Type="Str">Project documentation</Property></Project>"#,
    );
    directory.write("c.lvlib", "<Library>");
    let output = directory.scan(&["--fail-on", "none"]);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    scan_lines_without_timing(&stdout);
    assert!(stderr.contains("a.vi: analysis error:"));
    assert!(stderr.contains("c.lvlib: analysis error:"));
    assert!(!stdout.contains("b.lvproj"));
    assert!(stdout.contains("Analyzed 1 file(s); 1 finding(s); 2 analysis error(s)."));
    assert!(stdout.contains("Findings by severity: 0 info; 1 warning; 0 error."));
    let verbose = directory.scan(&["--verbose", "--fail-on", "none"]);
    assert_eq!(verbose.status.code(), Some(2));
    assert_eq!(String::from_utf8(verbose.stderr).unwrap(), stderr);
    assert!(
        String::from_utf8(verbose.stdout)
            .unwrap()
            .contains("b.lvproj: warning [separate-compiled-code]")
    );
}

#[test]
fn orphaned_vi_rule_flags_only_a_scanned_library_that_omits_the_vi() {
    let rule_config = "rules:\n  separate-compiled-code: { enabled: false }\n  saved-version: { enabled: false }\n  file-description: { enabled: false }\n  debugging-status: { enabled: false }\n  no-breakpoints: { enabled: false }\n  auto-error-handling: { enabled: false }\n  password-set: { enabled: false }\n  orphaned-vi: { enabled: true }\n  class-mutation-history: { enabled: false }\n";

    let orphaned = TestDirectory::new();
    orphaned.write(
        "orphan-vi.vi",
        support::vi_with_library_link("orphaned-example.lvlib"),
    );
    orphaned.write("orphaned-example.lvlib", "<Library/>");
    let config = orphaned.write("checks.yaml", rule_config);
    let output = orphaned.configured_scan(&config, &["--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 2 file(s); 1 finding(s); 0 analysis error(s)."));
    assert!(stdout.contains("orphan-vi.vi: error [orphaned-vi]"));
    assert!(stdout.contains("Findings by severity: 0 info; 0 warning; 1 error."));

    let listed = TestDirectory::new();
    listed.write(
        "orphan-vi.vi",
        support::vi_with_library_link("orphaned-example.lvlib"),
    );
    listed.write(
        "orphaned-example.lvlib",
        r#"<Library><Item Name="orphan-vi.vi" Type="VI" URL="../orphan-vi.vi"/></Library>"#,
    );
    let config = listed.write("checks.yaml", rule_config);
    let output = listed.configured_scan(&config, &["--verbose"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Analyzed 2 file(s); 0 finding(s); 0 analysis error(s)."));
    assert!(!stdout.contains("[orphaned-vi]"));
}

#[test]
fn nested_vi_owner_paths_do_not_match_a_same_named_library_in_the_wrong_folder() {
    let directory = TestDirectory::new();
    let nested = directory.0.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(
        nested.join("member.vi"),
        support::vi_with_library_path(&["", "", "owner.lvlib"]),
    )
    .unwrap();
    let member = r#"<Item Name="member.vi" Type="VI" URL="../nested/member.vi"/>"#;
    directory.write(
        "owner.lvlib",
        format!(r#"<Library LVVersion="24008000">{member}</Library>"#),
    );
    fs::write(
        nested.join("owner.lvlib"),
        r#"<Library LVVersion="24008000"/>"#,
    )
    .unwrap();

    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("[orphaned-vi]"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");

    directory.write("owner.lvlib", r#"<Library LVVersion="24008000"/>"#);
    fs::write(
        nested.join("owner.lvlib"),
        r#"<Library LVVersion="24008000"><Item Name="member.vi" Type="VI" URL="../member.vi"/></Library>"#,
    )
    .unwrap();
    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "{}: error [orphaned-vi]",
            Path::new("nested").join("member.vi").display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
}

#[test]
fn owner_paths_can_descend_and_cannot_escape_the_scan_root() {
    let directory = TestDirectory::new();
    let owners = directory.0.join("owners");
    fs::create_dir(&owners).unwrap();
    directory.write(
        "member.vi",
        support::vi_with_library_path(&["", "owners", "owner.lvlib"]),
    );
    fs::write(
        owners.join("owner.lvlib"),
        r#"<Library LVVersion="24008000"/>"#,
    )
    .unwrap();
    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("member.vi: error [orphaned-vi]"),
        "{stdout}"
    );
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");

    fs::write(
        owners.join("owner.lvlib"),
        r#"<Library LVVersion="24008000"><Item Name="member.vi" Type="VI" URL="../../member.vi"/></Library>"#,
    )
    .unwrap();
    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("[orphaned-vi]"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");

    directory.write(
        "member.vi",
        support::vi_with_library_path(&["", "", "owner.lvlib"]),
    );
    directory.write("owner.lvlib", r#"<Library LVVersion="24008000"/>"#);
    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("[orphaned-vi]"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
}

#[test]
fn labview_nested_vi_uses_its_actual_owning_library() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality")
        .join("orphaned-vi")
        .join("nested-owner");
    let directory = TestDirectory::new();
    let members = directory.0.join("members");
    fs::create_dir(&members).unwrap();
    fs::copy(
        fixture.join("members").join("NestedMember.vi"),
        members.join("NestedMember.vi"),
    )
    .unwrap();
    fs::copy(
        fixture.join("NestedOwner.lvlib"),
        directory.0.join("NestedOwner.lvlib"),
    )
    .unwrap();
    fs::write(
        members.join("NestedOwner.lvlib"),
        r#"<Library LVVersion="24008000"/>"#,
    )
    .unwrap();

    let output = directory.scan(&["--verbose", "--fail-on", "none"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("[orphaned-vi]"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");

    directory.write("NestedOwner.lvlib", r#"<Library LVVersion="24008000"/>"#);
    fs::write(
        members.join("NestedOwner.lvlib"),
        r#"<Library LVVersion="24008000"><Item Name="NestedMember.vi" Type="VI" URL="../NestedMember.vi"/></Library>"#,
    )
    .unwrap();
    let output = directory.scan(&["--verbose", "--fail-on", "none"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "{}: error [orphaned-vi]",
            Path::new("members").join("NestedMember.vi").display()
        )),
        "{stdout}"
    );
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
}

#[test]
fn labview_library_member_urls_are_relative_to_the_library_file() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality")
        .join("orphaned-vi")
        .join("orphaned-member");
    let directory = TestDirectory::new();
    directory.write(
        "orphan-vi.vi",
        fs::read(fixtures.join("orphan-vi.vi")).unwrap(),
    );
    let library = fs::read_to_string(fixtures.join("orphaned-example.lvlib")).unwrap();
    let item = r#"<Item Name="orphan-vi.vi" Type="VI" URL="../orphan-vi.vi"/>"#;
    assert!(library.contains("</Library>"));
    let listed = library.replace("</Library>", &format!("{item}\n</Library>"));
    directory.write("orphaned-example.lvlib", listed);
    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(!stdout.contains("[orphaned-vi]"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");

    directory.write("orphaned-example.lvlib", library);
    let output = directory.scan(&["--verbose"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("orphan-vi.vi: error [orphaned-vi]"),
        "{stdout}"
    );
}

#[test]
fn global_and_polymorphic_fixtures_are_read_without_a_configured_pane_rule() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality")
        .join("connector-pane-pattern");
    let directory = TestDirectory::new();
    for file in ["global.vi", "poly.vi"] {
        directory.write(file, fs::read(fixtures.join(file)).unwrap());
    }
    let output = directory.scan(&[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Analyzed 2 file(s)"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
}

#[test]
fn configured_connector_pane_rule_skips_global_and_polymorphic_vis() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality")
        .join("connector-pane-pattern");
    let directory = TestDirectory::new();
    for file in ["global.vi", "poly.vi", "icons-style.vi"] {
        directory.write(file, fs::read(fixtures.join(file)).unwrap());
    }
    let config = directory.write(
        "checks.yaml",
        fs::read(fixtures.join("checks.yaml")).unwrap(),
    );
    let output = directory.configured_scan(&config, &["--verbose", "--fail-on", "none"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("Analyzed 3 file(s)"), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
    assert!(!stdout.contains("global.vi: warning [connector-pane-pattern]"));
    assert!(!stdout.contains("poly.vi: warning [connector-pane-pattern]"));
    assert!(stdout.contains("icons-style.vi: warning [connector-pane-pattern]"));
}

#[test]
fn owner_fixtures_are_read_without_labview() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality")
        .join("support");
    for folder in ["class-neutral", "control-neutral"] {
        let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
            .arg("scan")
            .arg(fixtures.join(folder))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{folder}: {stdout}");
        assert!(stdout.contains("Analyzed 2 file(s)"), "{folder}: {stdout}");
        assert!(stdout.contains("0 analysis error(s)"), "{folder}: {stdout}");
    }
}

#[test]
fn example_fixtures_cover_bookmarks_and_terminal_styles() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("quality");
    let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("scan")
        .arg(&fixtures)
        .arg("--verbose")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
    assert!(
        stdout.contains("bookmark.vi: skipped [file-description]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("orphan-vi.vi: error [orphaned-vi]"),
        "{stdout}"
    );
    assert!(
        stdout.contains("class1.lvclass: warning [class-mutation-history]"),
        "{stdout}"
    );
    for (name, count) in [("icons-style.vi", 1), ("icons-style-2.vi", 2)] {
        assert!(
            stdout.contains(&format!(
                "{name}: warning [terminal-style]: This VI has {count} terminal(s)"
            )),
            "{stdout}"
        );
    }
    for name in ["data-style.vi", "data-style-2.vi"] {
        assert!(
            !stdout.contains(&format!("{name}: warning [terminal-style]")),
            "{stdout}"
        );
    }
}

#[test]
fn disabling_all_rules_skips_parsing() {
    let directory = TestDirectory::new();
    directory.write("broken.vi", []);
    let config = directory.write(
        "checks.yaml",
        "rules:\n  separate-compiled-code:\n    enabled: false\n  saved-version:\n    enabled: false\n  file-description:\n    enabled: false\n  debugging-status:\n    enabled: false\n  no-breakpoints:\n    enabled: false\n  auto-error-handling:\n    enabled: false\n  password-set:\n    enabled: false\n  orphaned-vi:\n    enabled: false\n  class-mutation-history:\n    enabled: false\n  terminal-style:\n    enabled: false\n  connector-pane-pattern:\n    enabled: false\n",
    );
    let output = directory.configured_scan(&config, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        scan_lines_without_timing(&stdout),
        [
            "Found 1 supported LabVIEW file(s). Running enabled rules...",
            "Scan type: scan (quality)",
            "Analyzed 0 file(s); 0 finding(s); 0 analysis error(s).",
        ]
    );
}

#[test]
fn passing_scan_omits_empty_breakdowns_in_both_modes() {
    let directory = TestDirectory::new();
    directory.write(
        "passing.lvproj",
        r#"<Project LVVersion="20008000"><Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property><Property Name="NI.Project.Description" Type="Str">Project documentation</Property></Project>"#,
    );
    for args in [vec![], vec!["--verbose"]] {
        let output = directory.scan(&args);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            scan_lines_without_timing(&stdout),
            [
                "Found 1 supported LabVIEW file(s). Running enabled rules...",
                "Scan type: scan (quality)",
                "Analyzed 1 file(s); 0 finding(s); 0 analysis error(s).",
            ]
        );
    }
}

#[test]
fn template_excludes_git_and_labview_environments_before_analysis() {
    let directory = TestDirectory::new();
    let nested = directory.0.join("nested");
    fs::create_dir(&nested).unwrap();
    for parent in [&directory.0, &nested] {
        for name in [".git", ".lv-venv"] {
            let excluded = parent.join(name).join("deeper");
            fs::create_dir_all(&excluded).unwrap();
            fs::write(excluded.join("invalid.vi"), b"not an RSRC file").unwrap();
        }
    }
    fs::create_dir(directory.0.join(".git-backup")).unwrap();
    directory.write(
        "root.lvproj",
        r#"<Project LVVersion="20008000"><Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property><Property Name="NI.Project.Description" Type="Str">Project documentation</Property></Project>"#,
    );
    fs::write(
        nested.join("nested.lvlib"),
        r#"<Library LVVersion="20008000"><Property Name="NI.LV.All.SourceOnly" Type="Bool">true</Property><Property Name="NI.Lib.Description" Type="Str">Library documentation</Property></Library>"#,
    )
    .unwrap();
    fs::write(
        directory.0.join(".git-backup").join("kept.lvproj"),
        r#"<Project LVVersion="20008000"><Property Name="NI.Project.Description" Type="Str">Project documentation</Property></Project>"#,
    )
    .unwrap();

    let template = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs")
        .join("wirelint.example.yaml");
    let output = directory.configured_scan(&template, &["--verbose"]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(output.stderr.is_empty());
    assert!(stdout.starts_with("Found 3 supported LabVIEW file(s)."));
    assert!(stdout.contains("Analyzed 3 file(s); 1 finding(s); 0 analysis error(s)."));
    assert!(stdout.contains(&format!(
        "{}: warning [separate-compiled-code]",
        Path::new(".git-backup").join("kept.lvproj").display()
    )));

    let output = directory.scan(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("Found 7 supported LabVIEW file(s).")
    );
    assert_eq!(
        String::from_utf8(output.stderr)
            .unwrap()
            .lines()
            .filter(|line| line.contains("analysis error:"))
            .count(),
        4
    );
}

#[test]
fn invalid_or_missing_configuration_fails_before_scanning() {
    let directory = TestDirectory::new();
    for contents in [
        "rules:\n  unknown-rule: {}",
        "rules:\n  separate-compiled-code:\n    severity: fatal",
        "exclude-folders: ['nested/.git']",
    ] {
        let config = directory.write("checks.yaml", contents);
        let output = directory.configured_scan(&config, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("configuration")
        );
    }
    let output = directory.configured_scan(&directory.0.join("missing.yaml"), &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("missing.yaml")
    );
}

#[test]
fn sast_rejects_quality_rule_configuration() {
    let directory = TestDirectory::new();
    let config = directory.write("checks.yaml", "rules:\n  separate-compiled-code: {}\n");
    let scan = directory.configured_scan(&config, &[]);
    assert!(scan.status.success());

    let sast = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("sast")
        .arg(&directory.0)
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(sast.status.code(), Some(2));
    assert!(sast.stdout.is_empty());
    let error = String::from_utf8(sast.stderr).unwrap();
    assert!(error.contains("separate-compiled-code"), "{error}");

    let config = directory.write(
        "sast.yaml",
        include_str!("../docs/wirelint-sast.example.yaml"),
    );
    let sast = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("sast")
        .arg(&directory.0)
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        sast.status.success(),
        "{}",
        String::from_utf8_lossy(&sast.stderr)
    );
}

#[test]
fn sast_reports_control_defaults_in_separated_and_embedded_vis() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sast");
    let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("sast")
        .arg(&fixtures)
        .arg("--verbose")
        .output()
        .unwrap();
    let stdout =
        String::from_utf8(output.stdout).unwrap() + &String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line == "Scan type: sast (security)")
    );
    for file in ["credentials-embedded.vi", "credentials-separated.vi"] {
        assert!(
            stdout.contains(&format!(
                "{file}: warning [hardcoded-secret-default]: Possible hardcoded secret in \"Notes\" (credential assignment in text) and 2 other defaults."
            )),
            "{stdout}"
        );
    }
    assert!(stdout.contains("0 analysis error(s)"), "{stdout}");
    for secret in ["WLMARK", "Sup3rS3cret", "hunter22"] {
        assert!(!stdout.contains(secret), "{stdout}");
    }
}

#[test]
fn sast_writes_a_gitlab_security_report() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sast");
    let directory = TestDirectory::new();
    let destination = directory.0.join("gl-sast-report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("sast")
        .arg(&fixtures)
        .args(["--format", "gitlab-sast", "--output"])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(destination).unwrap()).unwrap();
    assert_eq!(report["scan"]["type"], "sast");
    assert_eq!(report["scan"]["status"], "success");
    let vulnerabilities = report["vulnerabilities"].as_array().unwrap();
    assert!(!vulnerabilities.is_empty());
    for vulnerability in vulnerabilities {
        assert_eq!(vulnerability["severity"], "Medium");
        assert!(vulnerability["location"]["file"].is_string());
        assert_eq!(vulnerability["id"].as_str().unwrap().len(), 64);
        assert!(
            vulnerability["identifiers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|identifier| identifier["type"] == "cwe")
        );
    }
    let serialized = serde_json::to_string(&report).unwrap();
    for secret in ["WLMARK", "Sup3rS3cret", "hunter22"] {
        assert!(!serialized.contains(secret), "{serialized}");
    }
}

#[test]
fn gitlab_sast_report_is_rejected_by_scan() {
    let directory = TestDirectory::new();
    let destination = directory.0.join("gl-sast-report.json");
    let output = directory.scan(&[
        "--format",
        "gitlab-sast",
        "--output",
        destination.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("gitlab-sast"), "{error}");
    assert!(error.contains("possible values:"), "{error}");
    assert!(error.contains("gitlab-code-quality"), "{error}");
    assert!(!destination.exists());
}

#[test]
fn lists_rules_and_handles_an_empty_folder() {
    let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("rules")
        .output()
        .unwrap();
    assert!(output.status.success());
    let rules = String::from_utf8(output.stdout).unwrap();
    assert!(rules.contains("separate-compiled-code [scan, warning]"));
    assert!(rules.contains("saved-version [scan, warning]"));
    assert!(!rules.contains("minimum-saved-version"));
    assert!(rules.contains("file-description [scan, warning]"));
    assert!(rules.contains("debugging-status [scan, warning]"));
    assert!(rules.contains("no-breakpoints [scan, error]"));
    assert!(rules.contains("auto-error-handling [scan, error]"));
    assert!(rules.contains("password-set [scan, warning]"));
    assert!(rules.contains("hardcoded-secret-default [sast, warning] (CWE-798, CWE-259)"));
    let directory = TestDirectory::new();
    for args in [vec![], vec!["--verbose"]] {
        let output = directory.scan(&args);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            scan_lines_without_timing(&stdout),
            [
                "No supported LabVIEW files found.",
                "Scan type: scan (quality)",
                "Analyzed 0 file(s); 0 finding(s); 0 analysis error(s).",
            ]
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_wirelint"))
        .arg("sast")
        .arg(&directory.0)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        scan_lines_without_timing(&stdout),
        [
            "No supported LabVIEW files found.",
            "Scan type: sast (security)",
            "Analyzed 0 file(s); 0 finding(s); 0 analysis error(s).",
        ]
    );
}

#[test]
fn saved_version_rule_checks_files_and_respects_configuration() {
    let directory = TestDirectory::new();
    let mut older = vi_with_separation(true, b"LVIN");
    older[36..40].copy_from_slice(&0x19008000_u32.to_be_bytes());
    directory.write("older.vi", older);
    directory.write("equal.lvproj", r#"<Project LVVersion="20008000"/>"#);
    directory.write(
        "newer.lvclass",
        r#"<LVClass LVVersion="21008000"><Property Name="NI.LVClass.Geneology" Type="Xml"/></LVClass>"#,
    );
    directory.write("old.lvlib", r#"<Library LVVersion="19008000"/>"#);
    let config = directory.write(
        "checks.yaml",
        "rules:\n  separate-compiled-code:\n    enabled: false\n  file-description:\n    enabled: false\n",
    );
    let output = directory.configured_scan(&config, &["--verbose", "--fail-on", "warning"]);
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(
        "older.vi: warning [saved-version]: Saved LabVIEW version 19.0 is below the minimum 20.0."
    ));
    assert!(text.contains("old.lvlib: warning [saved-version]"));
    assert!(!text.contains("equal.lvproj:"));
    assert!(!text.contains("newer.lvclass:"));

    fs::write(&config, "rules:\n  separate-compiled-code:\n    enabled: false\n  file-description:\n    enabled: false\n  saved-version:\n    minimum-version: '20.1'\n").unwrap();
    let output = directory.configured_scan(&config, &["--verbose"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("equal.lvproj: warning [saved-version]: Saved LabVIEW version 20.0 is below the minimum 20.1."));
    assert!(!text.contains("newer.lvclass:"));

    fs::write(&config, "rules:\n  separate-compiled-code:\n    enabled: false\n  file-description:\n    enabled: false\n  saved-version:\n    minimum-version: '21.0'\n    severity: error\n").unwrap();
    let output = directory.configured_scan(&config, &["--verbose"]);
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains(
        "equal.lvproj: error [saved-version]: Saved LabVIEW version 20.0 is below the minimum 21.0."
    ));
    assert!(!text.contains("newer.lvclass:"));

    directory.write("missing.lvproj", "<Project/>");
    let output = directory.configured_scan(&config, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("missing root LVVersion")
    );
    fs::write(
        &config,
        "rules:\n  saved-version:\n    enabled: false\n  file-description:\n    enabled: false\n",
    )
    .unwrap();
    let output = directory.configured_scan(&config, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
}

#[test]
fn saved_version_bounds_apply_to_binary_and_xml_files() {
    let directory = TestDirectory::new();
    for (name, word) in [
        ("older.vi", 0x19008000_u32),
        ("equal.vi", 0x20008000_u32),
        ("newer.vi", 0x21008000_u32),
    ] {
        let mut bytes = vi_with_separation(true, b"LVIN");
        bytes[36..40].copy_from_slice(&word.to_be_bytes());
        directory.write(name, bytes);
    }
    directory.write("older.lvproj", r#"<Project LVVersion="19008000"/>"#);
    directory.write(
        "equal.lvclass",
        r#"<LVClass LVVersion="20008000"><Property Name="NI.LVClass.Geneology" Type="Xml"/></LVClass>"#,
    );
    directory.write("newer.lvlib", r#"<Library LVVersion="21008000"/>"#);
    for (bounds, expected_count) in [
        ("maximum-version: '20.0'", 2),
        ("minimum-version: '20.0'\n    maximum-version: '20.0'", 4),
    ] {
        let config = directory.write(
            "checks.yaml",
            format!(
                "rules:\n  separate-compiled-code:\n    enabled: false\n  file-description:\n    enabled: false\n  debugging-status:\n    enabled: false\n  saved-version:\n    {bounds}\n"
            ),
        );
        let output = directory.configured_scan(&config, &["--verbose", "--fail-on", "warning"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("newer.vi: warning [saved-version]: Saved LabVIEW version 21.0 is above the maximum 20.0."));
        assert!(text.contains("newer.lvlib: warning [saved-version]: Saved LabVIEW version 21.0 is above the maximum 20.0."));
        assert!(!text.contains("equal.vi:"));
        assert!(!text.contains("equal.lvclass:"));
        assert_eq!(text.matches("[saved-version]").count(), expected_count);
        assert_eq!(text.contains("older.vi:"), expected_count == 4);
        assert_eq!(text.contains("older.lvproj:"), expected_count == 4);
    }
}

#[test]
fn saved_version_configuration_errors_prevent_scanning() {
    let directory = TestDirectory::new();
    directory.write("unreadable.vi", []);
    for (rule, options, expected) in [
        (
            "minimum-saved-version",
            "enabled: false",
            "renamed to 'saved-version'",
        ),
        (
            "saved-version",
            "minimum-version: '21.0'\n    maximum-version: '20.0'",
            "minimum-version must not exceed maximum-version",
        ),
    ] {
        let config = directory.write("checks.yaml", format!("rules:\n  {rule}:\n    {options}\n"));
        let output = directory.configured_scan(&config, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("checks.yaml"), "{error}");
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn ci_reports_preserve_terminal_output_thresholds_and_stable_fingerprints() {
    let directory = TestDirectory::new();
    let nested = directory.0.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(
        nested.join("example #.vi"),
        vi_with_separation(false, b"LVIN"),
    )
    .unwrap();
    let config = directory.write(
        "checks.yaml",
        "rules:\n  separate-compiled-code:\n    severity: error\n",
    );
    let destination = directory.0.join("report.json");
    let destination_arg = destination.to_str().unwrap();
    let baseline = directory.configured_scan(&config, &["--verbose"]);
    for (format, threshold, status) in [
        ("gitlab-code-quality", "error", 1),
        ("sarif", "error", 1),
        ("gitlab-code-quality", "none", 0),
        ("sarif", "none", 0),
    ] {
        let output = directory.configured_scan(
            &config,
            &[
                "--verbose",
                "--fail-on",
                threshold,
                "--format",
                format,
                "--output",
                destination_arg,
            ],
        );
        assert_eq!(output.status.code(), Some(status));
        assert!(output.stderr.is_empty());
        assert_eq!(
            scan_lines_without_timing(std::str::from_utf8(&output.stdout).unwrap()),
            scan_lines_without_timing(std::str::from_utf8(&baseline.stdout).unwrap())
        );
        let bytes = fs::read(&destination).unwrap();
        assert!(!bytes.starts_with(&[0xEF, 0xBB, 0xBF]));
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if format == "gitlab-code-quality" {
            assert_eq!(json.as_array().unwrap().len(), 1);
            assert_eq!(json[0]["location"]["path"], "nested/example #.vi");
            assert_eq!(json[0]["location"]["lines"]["begin"], 1);
            assert_eq!(json[0]["severity"], "major");
        } else {
            let run = &json["runs"][0];
            assert_eq!(run["results"].as_array().unwrap().len(), 1);
            assert_eq!(run["results"][0]["level"], "error");
            assert_eq!(run["invocations"][0]["executionSuccessful"], true);
            assert_eq!(
                run["results"][0]["locations"][0]["physicalLocation"],
                serde_json::json!({
                    "artifactLocation": { "uri": "nested/example%20%23.vi" }
                })
            );
        }
        let repeated =
            directory.configured_scan(&config, &["--format", format, "--output", destination_arg]);
        assert_eq!(repeated.status.code(), Some(1));
        assert_eq!(fs::read(&destination).unwrap(), bytes);
    }
}

#[test]
fn ci_reports_cover_empty_scans_disabled_rules_and_partial_analysis_failures() {
    let directory = TestDirectory::new();
    let destination = directory.0.join("report.json");
    for format in ["gitlab-code-quality", "sarif"] {
        let args = [
            "--format",
            format,
            "--output",
            destination.to_str().unwrap(),
        ];
        let output = directory.scan(&args);
        assert_eq!(output.status.code(), Some(0));
        let empty: serde_json::Value =
            serde_json::from_slice(&fs::read(&destination).unwrap()).unwrap();
        if format == "gitlab-code-quality" {
            assert_eq!(empty, serde_json::json!([]));
        } else {
            assert_eq!(empty["runs"][0]["results"], serde_json::json!([]));
            assert_eq!(
                empty["runs"][0]["invocations"][0]["executionSuccessful"],
                true
            );
        }
    }
    directory.write("broken.vi", b"not an RSRC file");
    directory.write(
        "finding.lvproj",
        r#"<Project LVVersion="20008000"><Property Name="NI.Project.Description" Type="Str">Description</Property></Project>"#,
    );
    for format in ["gitlab-code-quality", "sarif"] {
        let output = directory.scan(&[
            "--format",
            format,
            "--output",
            destination.to_str().unwrap(),
            "--fail-on",
            "none",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            std::str::from_utf8(&output.stderr)
                .unwrap()
                .contains("broken.vi: analysis error:")
        );
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(&destination).unwrap()).unwrap();
        if format == "gitlab-code-quality" {
            assert_eq!(json.as_array().unwrap().len(), 1);
            assert_eq!(json[0]["location"]["path"], "finding.lvproj");
        } else {
            let run = &json["runs"][0];
            assert_eq!(run["results"].as_array().unwrap().len(), 1);
            assert_eq!(run["invocations"][0]["executionSuccessful"], false);
            assert_eq!(
                run["invocations"][0]["toolExecutionNotifications"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
    let config = directory.write(
        "checks.yaml",
        "rules:\n  separate-compiled-code:\n    enabled: false\n  saved-version:\n    enabled: false\n  file-description:\n    enabled: false\n  debugging-status:\n    enabled: false\n  no-breakpoints:\n    enabled: false\n  auto-error-handling:\n    enabled: false\n  password-set:\n    enabled: false\n  orphaned-vi:\n    enabled: false\n  class-mutation-history:\n    enabled: false\n  terminal-style:\n    enabled: false\n  connector-pane-pattern:\n    enabled: false\n",
    );
    let output = directory.configured_scan(
        &config,
        &[
            "--format",
            "sarif",
            "--output",
            destination.to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&destination).unwrap()).unwrap();
    assert_eq!(json["runs"][0]["results"], serde_json::json!([]));
    assert_eq!(
        json["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
}

#[test]
fn ci_report_options_and_write_errors_fail_explicitly() {
    let directory = TestDirectory::new();
    for args in [
        vec!["--format", "gitlab-code-quality"],
        vec!["--output", "report.json"],
        vec!["--format", "unknown", "--output", "report.json"],
    ] {
        let output = directory.scan(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    for destination in [
        directory.0.join("missing").join("report.json"),
        directory.0.clone(),
    ] {
        let output = directory.scan(&[
            "--format",
            "gitlab-code-quality",
            "--output",
            destination.to_str().unwrap(),
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            std::str::from_utf8(&output.stderr)
                .unwrap()
                .contains("cannot write report")
        );
    }
}

#[test]
fn ci_reports_cannot_overwrite_discovered_sources_or_configuration() {
    let directory = TestDirectory::new();
    let source = directory.write("source.vi", vi_with_separation(false, b"LVIN"));
    let config = directory.write("checks.yaml", "version: 1\n");
    for path in [&source, &config] {
        let original = fs::read(path).unwrap();
        let output = directory.configured_scan(
            &config,
            &[
                "--format",
                "gitlab-code-quality",
                "--output",
                path.to_str().unwrap(),
            ],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(
            std::str::from_utf8(&output.stderr)
                .unwrap()
                .contains("would overwrite input")
        );
        assert_eq!(fs::read(path).unwrap(), original);
    }
}
