use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    io::{Cursor, Read},
    path::Path,
};

use flate2::read::MultiGzDecoder;
use rulec::{Blocklist, Conversion, ConversionSummary, RuleBundle, Source, compile};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use yaml_rust2::YamlLoader;

use super::{Result, read, write};

#[derive(Deserialize)]
struct Input {
    source: String,
    path: Option<String>,
    version: Option<String>,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Report {
    pub source: String,
    pub error: Option<String>,
    pub input_count: usize,
    pub summary: Option<ConversionSummary>,
    pub accepted_ids: Vec<String>,
}

pub(super) fn included_et(path: &str) -> Option<&str> {
    let name = path.trim_start_matches("./").strip_prefix("rules/")?;
    if name.contains('/')
        || !name.ends_with(".rules")
        || name.starts_with("threatview")
        || matches!(
            name,
            "emerging-retired.rules"
                | "botcc.rules"
                | "botcc.portgrouped.rules"
                | "ciarmy.rules"
                | "compromised.rules"
                | "drop.rules"
                | "dshield.rules"
                | "tor.rules"
        )
    {
        None
    } else {
        Some(name)
    }
}

// Deliberately independent of the library's line iterator: verifies its accounting.
fn logical_lines(bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut lines = Vec::new();
    let mut pending = Vec::new();
    let mut first = None;
    for (n, line) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        if first.is_none() && (line.trim_ascii().is_empty() || line.trim_ascii().starts_with(b"#"))
        {
            continue;
        }
        let number = *first.get_or_insert(n + 1);
        if let Some(prefix) = line.trim_ascii_end().strip_suffix(b"\\") {
            pending.extend_from_slice(prefix);
        } else {
            pending.extend_from_slice(line);
            lines.push((number, std::mem::take(&mut pending)));
            first = None;
        }
    }
    if let Some(number) = first {
        lines.push((number, pending));
    }
    lines
}

pub(super) fn et_lines(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut archive = tar::Archive::new(MultiGzDecoder::new(bytes));
    let mut result = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path_bytes();
        let included = std::str::from_utf8(&raw_path)
            .ok()
            .and_then(included_et)
            .is_some();
        if !entry.header().entry_type().is_file() || !included {
            continue;
        }
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        result.extend(logical_lines(&contents).into_iter().map(|(_, line)| line));
    }
    Ok(result)
}

fn sigma_count(bytes: &[u8], emerging: bool) -> Result<usize> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))?;
    let root = if emerging {
        "rules-emerging-threats"
    } else {
        "rules"
    };
    let directory = format!("{root}/");
    let roots: BTreeSet<_> = zip
        .file_names()
        .filter_map(|name| name.split_once('/').map(|(root, _)| root))
        .collect();
    let selected = if zip.file_names().any(|name| name.starts_with(&directory)) {
        directory
    } else if let Some(wrapper) = roots.first().filter(|_| roots.len() == 1) {
        format!("{wrapper}/{directory}")
    } else {
        directory
    };
    let mut count = 0;
    for n in 0..zip.len() {
        let file = zip.by_index_raw(n)?;
        if !file.is_file() {
            continue;
        }
        let Some(path) = file.name().strip_prefix(&selected) else {
            continue;
        };
        let relative: Vec<_> = path.split('/').collect();
        if relative
            .iter()
            .any(|part| matches!(*part, "" | "." | "..") || part.contains('\\'))
        {
            continue;
        }
        let Some(name) = relative.last() else {
            continue;
        };
        if !(name.ends_with(".yml") || name.ends_with(".yaml"))
            || (!emerging && relative[..relative.len() - 1].contains(&"deprecated"))
        {
            continue;
        }
        drop(file);
        let mut file = zip.by_index(n)?;
        let mut text = String::new();
        let parsed = file
            .read_to_string(&mut text)
            .ok()
            .and_then(|_| YamlLoader::load_from_str(&text).ok());
        let skipped = parsed
            .as_ref()
            .filter(|docs| docs.len() == 1)
            .and_then(|docs| docs.first())
            .and_then(|doc| doc["status"].as_str())
            .is_some_and(|status| matches!(status, "deprecated" | "unsupported"));
        count += usize::from(!skipped);
    }
    Ok(count)
}

fn validate(input_count: usize, summary: &ConversionSummary, rules: &[rulec::Rule]) -> Result<()> {
    let accepted: usize = summary.accepted.values().sum();
    let dropped: usize = summary.dropped.values().map(Vec::len).sum();
    if accepted + dropped != input_count || accepted != rules.len() {
        return Err(format!("accounting mismatch: input={input_count}, accepted={accepted}, dropped={dropped}, rules={}", rules.len()).into());
    }
    let mut reasons = BTreeMap::new();
    for (reason, ids) in &summary.dropped {
        for id in ids {
            if reasons.insert(id, reason).is_some() {
                return Err(format!("dropped id {id} has more than one reason/entry").into());
            }
        }
    }
    let compiled = compile(rules.to_vec())?;
    if !compiled.stats().excluded().is_empty() || compiled.stats().accepted() != accepted {
        return Err("accepted rules were excluded on recompilation".into());
    }
    Ok(())
}

pub(super) fn run(input: &Path, output: &Path) -> Result<()> {
    fs::create_dir_all(output)
        .map_err(|error| format!("creating output directory {}: {error}", output.display()))?;
    let inputs: Vec<Input> = read(&input.join("sources.json"))?;
    let blocklist = Blocklist::builtin()?;
    let mut reports = Vec::new();
    for item in inputs {
        let mut report = Report {
            source: item.source.clone(),
            error: item.error,
            input_count: 0,
            summary: None,
            accepted_ids: Vec::new(),
        };
        if report.error.is_none() {
            let result = (|| -> Result<Conversion> {
                let path = input.join(item.path.ok_or("missing downloaded archive path")?);
                let bytes =
                    fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
                let converted = match item.source.as_str() {
                    "et_open" => {
                        report.input_count = et_lines(&bytes)?.len();
                        write(
                            &input.join("et-sha256.json"),
                            &Sha256::digest(&bytes).iter().fold(
                                String::with_capacity(64),
                                |mut hex, byte| {
                                    let _ = write!(hex, "{byte:02x}");
                                    hex
                                },
                            ),
                        )?;
                        rulec::convert_et_open(
                            &bytes,
                            item.version.as_deref().map(str::parse).transpose()?,
                            &blocklist,
                        )?
                    }
                    "sigma_hq" => {
                        report.input_count = sigma_count(&bytes, false)?;
                        rulec::convert_sigma_hq(&bytes, item.version.as_deref(), &blocklist)?
                    }
                    "sigma_hq_emerging" => {
                        report.input_count = sigma_count(&bytes, true)?;
                        rulec::convert_sigma_hq_emerging(&bytes, &blocklist)?
                    }
                    _ => return Err("unknown source".into()),
                };
                // Keep the summary even if the independent audit fails.
                report.summary = Some(converted.summary.clone());
                report.accepted_ids = converted
                    .rules
                    .iter()
                    .map(|r| r.source_rule_id().to_owned())
                    .collect();
                validate(report.input_count, &converted.summary, &converted.rules)?;
                if item.source == "et_open" {
                    let bundle = RuleBundle::new(Source::EtOpen, converted.rules.clone())?;
                    let path = input.join("et.bundle");
                    fs::write(&path, bundle.to_bytes()?).map_err(|error| {
                        format!("writing ephemeral bundle {}: {error}", path.display())
                    })?;
                }
                Ok(converted)
            })();
            if let Err(error) = result {
                report.error = Some(error.to_string());
            }
        }
        write(&output.join(format!("{}.json", item.source)), &report)?;
        reports.push(report);
    }
    write(&output.join("conversion.json"), &reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_documented_et_scope_and_joins_continuations() {
        assert!(included_et("./rules/emerging-dns.rules").is_some());
        for path in [
            "rules/sub/test.rules",
            "rules/botcc.rules",
            "rules/emerging-retired.rules",
            "rules/threatview1.rules",
        ] {
            assert!(included_et(path).is_none());
        }
        assert_eq!(
            logical_lines(b"# comment\n\nalert \\\n  #literal\nalert two\n"),
            vec![
                (3, b"alert   #literal".to_vec()),
                (5, b"alert two".to_vec())
            ]
        );
    }

    #[test]
    fn rejects_bad_accounting_and_duplicate_drop_reasons() {
        let version = rulec::SourceVersion {
            version: "test".into(),
            release_name: None,
            order_key: rulec::OrderKey {
                date: "2026-01-01".parse().unwrap(),
                number: None,
            },
            content_digest: "test".into(),
        };
        let mut summary = ConversionSummary::new(Source::EtOpen, version);
        summary.record_dropped("a", "1");
        assert!(validate(1, &summary, &[]).is_ok());
        assert!(validate(2, &summary, &[]).is_err());
        summary.record_dropped("b", "1");
        assert!(validate(2, &summary, &[]).is_err());
    }

    #[test]
    fn rejects_accepted_rules_excluded_on_recompilation() {
        let rule = rulec::Rule::from_yaml("source: et_open\nsource_rule_id: '1'\nmodel: EtSignature\ntitle: test\nlogsource:\n  category: http\ndetection:\n  s:\n    uri|re: '(?<=a)b'\n  condition: s\n").unwrap();
        let mut summary = ConversionSummary::new(
            Source::EtOpen,
            rulec::SourceVersion {
                version: "test".into(),
                release_name: None,
                order_key: rulec::OrderKey {
                    date: "2026-01-01".parse().unwrap(),
                    number: None,
                },
                content_digest: "test".into(),
            },
        );
        summary.accepted.insert(rule.model(), 1);
        assert!(validate(1, &summary, &[rule]).is_err());
    }

    #[test]
    fn sigma_count_excludes_statuses_and_deprecated_directories() {
        use std::io::Write;
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (path, text) in [
            ("sigma/rules/a.yml", "status: stable"),
            ("sigma/rules/b.yaml", "status: deprecated"),
            ("sigma/rules/c.yml", "status: unsupported"),
            ("sigma/rules/d.yml", "invalid: ["),
            ("sigma/rules/deprecated/e.yml", "status: stable"),
            ("sigma/rules-emerging-threats/e.yml", "status: experimental"),
        ] {
            zip.start_file(path, zip::write::SimpleFileOptions::default())
                .unwrap();
            zip.write_all(text.as_bytes()).unwrap();
        }
        let bytes = zip.finish().unwrap().into_inner();
        assert_eq!(sigma_count(&bytes, false).unwrap(), 2);
        assert_eq!(sigma_count(&bytes, true).unwrap(), 1);
    }

    #[test]
    fn sigma_count_selects_root_or_sole_wrapper_without_mixing_them() {
        use std::io::Write;
        for (paths, expected) in [
            (vec!["rules/a.yml", "other/rules/b.yml"], 1),
            (vec!["one/rules/a.yml", "two/rules/b.yml"], 0),
            (vec!["only/rules/a.yml", "only/README.md"], 1),
            (vec!["rules/../a.yml", "rules//b.yml", "rules/./c.yml"], 0),
        ] {
            for emerging in [false, true] {
                let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
                for path in &paths {
                    let path = if emerging {
                        path.replace("rules/", "rules-emerging-threats/")
                    } else {
                        (*path).to_owned()
                    };
                    zip.start_file(path, zip::write::SimpleFileOptions::default())
                        .unwrap();
                    zip.write_all(b"status: stable").unwrap();
                }
                let bytes = zip.finish().unwrap().into_inner();
                assert_eq!(
                    sigma_count(&bytes, emerging).unwrap(),
                    expected,
                    "{paths:?}"
                );
            }
        }
    }

    #[test]
    fn sigma_count_does_not_decode_excluded_members() {
        use std::io::Write;
        for path in ["rules/a.yml", "rules-emerging-threats/a.yml"] {
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            for (name, text) in [("outside.bin", "opaque"), (path, "status: stable")] {
                zip.start_file(name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(text.as_bytes()).unwrap();
            }
            let mut bytes = zip.finish().unwrap().into_inner();
            // The excluded member advertises a codec the crate does not enable.
            for (signature, offset) in [(b"PK\x03\x04", 8), (b"PK\x01\x02", 10)] {
                let header = bytes.windows(4).position(|s| s == signature).unwrap();
                bytes
                    .get_mut(header + offset..header + offset + 2)
                    .unwrap()
                    .copy_from_slice(&12_u16.to_le_bytes());
            }
            assert_eq!(
                sigma_count(&bytes, path.starts_with("rules-emerging")).unwrap(),
                1
            );
        }
    }

    #[test]
    fn source_failures_preserve_other_reports_and_et_skip_reason() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let output = directory.path().join("output");
        fs::create_dir(&input).unwrap();
        // A local, handwritten ET fixture; no upstream signature bytes.
        let text = b"alert dns any any -> any any (msg:\"test\"; dns.query; content:\"example.invalid\"; sid:1; rev:1; metadata:updated_at 2026_01_01;)\n";
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(text.len()).unwrap());
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, "rules/emerging-dns.rules", text.as_slice())
            .unwrap();
        let mut encoder = archive.into_inner().unwrap();
        encoder.flush().unwrap();
        fs::write(input.join("et.tar.gz"), encoder.finish().unwrap()).unwrap();
        write(
            &input.join("sources.json"),
            &serde_json::json!([
                {"source":"et_open","path":"et.tar.gz","version":"1","error":null},
                {"source":"sigma_hq","path":null,"version":null,"error":"download failed"},
                {"source":"sigma_hq_emerging","path":null,"version":null,"error":"download failed"}
            ]),
        )
        .unwrap();
        run(&input, &output).unwrap();
        let reports: Vec<Report> = read(&output.join("conversion.json")).unwrap();
        assert!(reports.first().unwrap().error.is_none());
        assert_eq!(reports.first().unwrap().input_count, 1);
        assert!(reports.get(1).unwrap().error.is_some());
        assert!(input.join("et.bundle").exists());
        for (path, root, emerging) in [
            ("sigma.zip", "rules", false),
            ("emerging.zip", "rules-emerging-threats", true),
        ] {
            let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let mut options = zip::write::FullFileOptions::default();
            if emerging {
                zip.set_comment("0123456789abcdef0123456789abcdef01234567")
                    .unwrap();
                let mut extra = vec![1];
                extra.extend_from_slice(&1_783_598_400_u32.to_le_bytes());
                options
                    .add_extra_data(0x5455, extra.into_boxed_slice(), false)
                    .unwrap();
            }
            zip.start_file(format!("{root}/test.yml"), options).unwrap();
            zip.write_all(b"id: daily-test\ntitle: synthetic daily test\nlogsource: {category: proxy}\ndetection:\n  selection: {c-uri: /probe}\n  condition: selection\n")
                .unwrap();
            if !emerging {
                zip.start_file("version.txt", zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(b"Release Date: 2026-07-09\nLabel: test\n")
                    .unwrap();
            }
            fs::write(input.join(path), zip.finish().unwrap().into_inner()).unwrap();
        }
        write(
            &input.join("sources.json"),
            &serde_json::json!([
                {"source":"et_open","path":"et.tar.gz","version":"1","error":null},
                {"source":"sigma_hq","path":"sigma.zip","version":"release-tag","error":null},
                {"source":"sigma_hq_emerging","path":"emerging.zip","version":null,"error":null}
            ]),
        )
        .unwrap();
        fs::write(input.join("et.tar.gz"), b"corrupt").unwrap();
        run(&input, &output).unwrap();
        super::super::compare::run(&input, &output).unwrap();
        let differential: serde_json::Value = read(&output.join("differential.json")).unwrap();
        assert_eq!(differential["status"], "skipped");
        assert!(differential["reason"].as_str().unwrap().contains("ET Open"));
        let reports: Vec<Report> = read(&output.join("conversion.json")).unwrap();
        assert_eq!(reports.len(), 3);
        assert!(reports.first().unwrap().error.is_some());
        for report in reports.iter().skip(1) {
            assert!(report.error.is_none(), "{:?}", report.error);
            assert_eq!(report.input_count, 1);
            assert_eq!(report.accepted_ids, vec!["daily-test"]);
        }
        assert_eq!(
            reports
                .get(1)
                .unwrap()
                .summary
                .as_ref()
                .unwrap()
                .source_version
                .release_name
                .as_deref(),
            Some("release-tag")
        );
    }
}
