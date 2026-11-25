//! The tool's reader of case files (`src/cases.rs`) holds to the real format:
//! it reads every case file of the repository, every guard's, refuses none,
//! and finds a case on every line that has one, with the text a case of each
//! escape decodes to. A change to the format that it does not know fails
//! here, not in what the tool compares.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    clippy::unwrap_used,
    reason = "the test reads the repository's case files; a helper of a test fails it as the test does"
)]

use std::fs;
use std::path::{Path, PathBuf};

use grammar_check::cases::{self, Word};
use grammar_check::lines::{self, Family};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `*.cases` of the repository: each crate's `tests/cases`.
fn case_files() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root().join("crates")).unwrap().flatten() {
        let folder = entry.path().join("tests/cases");
        let Ok(files) = fs::read_dir(&folder) else {
            continue;
        };
        found.extend(
            files
                .flatten()
                .map(|file| file.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "cases")),
        );
    }
    found.sort();
    found
}

#[test]
fn every_case_file_of_the_repository_is_read_whole() {
    let files = case_files();
    assert!(files.len() > 50, "found only {} case files", files.len());
    let mut cases = 0;
    for file in &files {
        let source = fs::read_to_string(file).unwrap();
        let records = cases::parse(&file.display().to_string(), &source)
            .unwrap_or_else(|refused| panic!("{}", refused.join("\n")));
        let with_text = records
            .iter()
            .filter(|record| record.text.is_some())
            .count();
        // A case is a line with ` | ` (or a last ` |`, an empty line) that
        // is not a comment; the rest are declarations, blank lines and
        // comments.
        let expected = source
            .split('\n')
            .filter(|line| !line.starts_with('#') && (line.contains(" | ") || line.ends_with(" |")))
            .count();
        assert_eq!(with_text, expected, "{}", file.display());
        for record in &records {
            if let Some(text) = &record.text {
                assert_eq!(
                    cases::decode(&cases::encode(text), false).as_deref(),
                    Ok(text.as_str()),
                    "{}",
                    record.at
                );
            }
        }
        cases += with_text;
    }
    assert!(cases > 20_000, "found only {cases} cases");
}

#[test]
fn each_escape_reads_as_the_format_says() {
    // Lines the shell guard's case files hold, as they hold them.
    let source = "posix safe | cd sub <<EOF > out.txt\\nx\\nEOF\n\
                  cmd finds=overwrite | cd sub > ..\\\\x.txt\n\
                  posix finds=delete reason=\"deletes your home directory\" | tar -cf x.tar ~ --remove-files\n\
                  posix safe | echo\\sa\\tb\\r\\u{0}\\u{202e}\n\
                  paths home cwd=/home/me home=/home/me workspace=/home/me\n\
                  posix@home finds=delete | rm -rf .ssh\n";
    let records = cases::parse("sample.cases", source).unwrap();
    let texts: Vec<Option<&str>> = records.iter().map(|r| r.text.as_deref()).collect();
    assert_eq!(
        texts,
        [
            Some("cd sub <<EOF > out.txt\nx\nEOF"),
            Some("cd sub > ..\\x.txt"),
            Some("tar -cf x.tar ~ --remove-files"),
            Some("echo a\tb\r\u{0}\u{202e}"),
            None,
            Some("rm -rf .ssh"),
        ]
    );
    assert_eq!(
        records[2].words[2],
        Word::Field("reason".into(), "deletes your home directory".into())
    );
    assert_eq!(
        cases::head(&records[5].words),
        Some(("posix", Some("home")))
    );
}

#[test]
fn the_lines_are_the_posix_and_powershell_cases() {
    let root = root();
    let shell = root.join("crates/shell/tests/cases");
    let lines = lines::from_cases(&root, &[&shell]).unwrap();
    assert!(lines.iter().any(|line| line.family == Family::Posix));
    assert!(lines.iter().any(|line| line.family == Family::PowerShell));
    assert!(lines.iter().all(|line| line
        .from
        .iter()
        .all(|at| at.starts_with("crates/shell/tests/cases/"))));
}
