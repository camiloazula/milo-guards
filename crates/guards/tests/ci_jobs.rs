//! CI runs the gate `just verify` runs locally, in two jobs: the `verify`
//! job runs every recipe of it but `timing`, in its order, and the `timing`
//! job runs `just timing` alone. A recipe added to `verify` and not to CI
//! fails here. The `test` job runs `just test` alone, on Windows and on
//! macOS, and the `oldest-rust` job runs `just oldest-rust` alone, on Linux:
//! a job removed, a system dropped or another command fails here too. The
//! two recipes that need the network, `advisories` (the advisory database)
//! and `semver` (each crate's last release on crates.io), are not part of
//! `just verify`, and each has a job of its own, on Linux, that runs it
//! alone. The semver job checks out with no credentials kept, may only read
//! the repository, and installs the cargo-semver-checks that CONTRIBUTING.md
//! installs; the justfile's `next_bump`, which it reads, is empty or
//! `minor`, and empty while CHANGELOG.md's Unreleased section is.
//!
//! The workflow is read line by line, as plain block YAML: each job under
//! `jobs:`, each key by where it sits, comments skipped. In the six jobs
//! held here, some ways a job could run less than it shows are refused, never
//! read: the keys `if:`, `continue-on-error:`, `needs:`, `shell:`,
//! `include:`, `exclude:` and `working-directory:`; a quoted key, an explicit
//! `? key` and any other line without a key; a flow mapping, a merge key, an
//! anchor, an alias and a tag; a `run:` written as a block or off a step; a
//! value continued on the next line; a key written twice; and a tab anywhere.
//! That list is not every way. What this test does not hold: `env:` at any
//! level (just itself reads variables such as `JUST_DRY_RUN` and
//! `JUST_JUSTFILE`), the workflow's `on:` filters and its `defaults:`,
//! `timeout-minutes:`, a `uses:` step added beside the run, and a
//! `container:` a job runs in. The Rust each job installs is held by
//! `toolchain.rs`, not here.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// A file at the repository root, or a message saying which one is missing.
fn read(relative: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {relative} ({e}) at {}", path.display()))
}

/// The recipes `recipe` depends on in `justfile`, in order.
fn dependencies(justfile: &str, recipe: &str) -> Result<Vec<String>, String> {
    let head = format!("{recipe}:");
    justfile
        .lines()
        .find_map(|line| line.strip_prefix(&head))
        .map(|rest| rest.split_whitespace().map(str::to_string).collect())
        .ok_or_else(|| format!("the justfile has no recipe `{recipe}`"))
}

/// Keys that skip or forgive a job, a step or a system, or change how or
/// where a step runs: a held job runs what it shows, so these are refused in
/// it. None of the held jobs uses one.
const REFUSED: [&str; 7] = [
    "if",
    "continue-on-error",
    "needs",
    "shell",
    "include",
    "exclude",
    "working-directory",
];

/// One key of a job: the keys above it inside the job (`-N` for the Nth item
/// of a list), its own, and its value, unquoted.
#[derive(Debug)]
struct Entry {
    path: Vec<String>,
    value: String,
}

impl Entry {
    fn at(&self, path: &[&str]) -> bool {
        self.path.len() == path.len()
            && self
                .path
                .iter()
                .zip(path)
                .all(|(have, want)| (*want == "-" && have.starts_with('-')) || have == want)
    }
}

/// How many spaces `line` starts with.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// `line` without a comment after it.
fn uncommented(line: &str) -> &str {
    line.split_once(" #")
        .map_or(line, |(before, _)| before)
        .trim_end()
}

/// Whether `line` holds nothing: blank, or a comment.
fn blank(line: &str) -> bool {
    let text = line.trim();
    text.is_empty() || text.starts_with('#')
}

/// The lines of the job `name`: those below `  name:` inside `jobs:`, up to
/// the next job or the end of `jobs:`.
fn lines_of<'a>(workflow: &'a str, name: &str) -> Result<Vec<&'a str>, String> {
    let lines: Vec<&str> = workflow.lines().collect();
    let tops: Vec<usize> = (0..lines.len())
        .filter(|&i| uncommented(lines[i]) == "jobs:")
        .collect();
    let [top] = tops[..] else {
        return Err(format!(
            "ci.yml must have one line `jobs:`, at the start of the line, and has {}",
            tops.len()
        ));
    };
    let jobs: Vec<&str> = lines[top + 1..]
        .iter()
        .copied()
        .take_while(|line| blank(line) || indent(line) > 0)
        .collect();
    let head = format!("  {name}:");
    let heads: Vec<usize> = (0..jobs.len())
        .filter(|&i| uncommented(jobs[i]) == head)
        .collect();
    match heads[..] {
        [at] => Ok(jobs[at + 1..]
            .iter()
            .copied()
            .take_while(|line| blank(line) || indent(line) > 2)
            .collect()),
        [] => Err(format!(
            "ci.yml has no job `{name}` under `jobs:`, written `  {name}:` on a line of its own"
        )),
        _ => Err(format!("ci.yml has the job `{name}` twice")),
    }
}

/// Whether `key` is written the one way this reader reads a key: bare.
fn bare(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// `value` without its comment and its quotes.
fn plain(value: &str) -> String {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            if !inner.contains(quote) {
                return inner.to_string();
            }
        }
    }
    value
        .split_once(" #")
        .map_or(value, |(before, _)| before)
        .trim_end()
        .to_string()
}

/// The keys of the job `name` in `workflow`, in order, or why a line of it
/// is refused.
fn job(workflow: &str, name: &str) -> Result<Vec<Entry>, String> {
    let refuse = |line: &str, why: &str| Err(format!("job `{name}`, `{}`: {why}", line.trim()));
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen = HashSet::new();
    // The open keys and list items, each with the column it starts at and
    // whether it is a key with no value on its line, which a list may sit
    // under at its own column (`steps:` then `- run:` below it, unindented).
    let mut stack: Vec<(usize, String, bool)> = Vec::new();
    let mut items: HashMap<Vec<String>, usize> = HashMap::new();
    // A key whose value is on its line: a deeper line is that value going
    // on, read as text after a block's `|` or `>` and refused otherwise.
    let mut open: Option<(usize, bool)> = None;
    for line in lines_of(workflow, name)? {
        if line.contains('\t') {
            return refuse(line, "a tab anywhere in a held job is refused, not read");
        }
        if line.trim().is_empty() {
            continue;
        }
        let mut column = indent(line);
        if let Some((key, block)) = open {
            if column > key {
                if block {
                    continue;
                }
                return refuse(
                    line,
                    "a value continued on the next line is refused, not read",
                );
            }
            open = None;
        }
        if blank(line) {
            continue;
        }
        let mut content = &line[column..];
        let item = content.starts_with("- ");
        stack.retain(|(at, _, parent)| *at < column || (item && *at == column && *parent));
        while let Some(rest) = content.strip_prefix('-') {
            if !rest.starts_with(' ') {
                break;
            }
            let parent: Vec<String> = stack.iter().map(|(_, key, _)| key.clone()).collect();
            let index = items.entry(parent).or_insert(0);
            stack.push((column, format!("-{index}"), false));
            *index += 1;
            let text = rest.trim_start_matches(' ');
            column += 1 + rest.len() - text.len();
            content = text;
        }
        let (key, value) = match content.split_once(": ") {
            Some((key, value)) => (key, value),
            None => match content.strip_suffix(':') {
                Some(key) => (key, ""),
                None => ("", content),
            },
        };
        if key.is_empty() {
            return refuse(
                line,
                "a line with no key (a plain list item, an explicit `? key` or its `: value`) \
                 is refused, not read",
            );
        }
        if !bare(key) {
            return refuse(
                line,
                "a key is written bare, as `run:`: a quoted key, a flow mapping `{…}` and a \
                 merge `<<` are refused, not read",
            );
        }
        if REFUSED.contains(&key) {
            return refuse(
                line,
                "this key can keep the job from running what it shows, so it is refused here",
            );
        }
        let value = value.trim();
        if value.starts_with(['{', '&', '*', '!']) || value.starts_with('[') && key != "os" {
            return refuse(
                line,
                "a flow mapping or list, an anchor, an alias and a tag are refused, not read",
            );
        }
        let is_block = value.starts_with(['|', '>'])
            && value[1..]
                .chars()
                .all(|c| matches!(c, '+' | '-' | '0'..='9'));
        if is_block && key == "run" {
            return refuse(line, "a `run:` is written on its line, not as a block");
        }
        if !value.is_empty() {
            open = Some((column, is_block));
        }
        stack.push((column, key.to_string(), value.is_empty()));
        let path: Vec<String> = stack.iter().map(|(_, key, _)| key.clone()).collect();
        if !seen.insert(path.clone()) {
            return refuse(line, "a key written twice in one place");
        }
        entries.push(Entry {
            path,
            value: plain(value),
        });
    }
    Ok(entries)
}

/// The commands of every `run:` step of the job `name` in `workflow`, in
/// order. A `run:` anywhere but on a step is refused.
fn runs(workflow: &str, name: &str) -> Result<Vec<String>, String> {
    let entries = job(workflow, name)?;
    let mut found = Vec::new();
    for entry in &entries {
        if entry.path.last().is_some_and(|key| key == "run") {
            if !entry.at(&["steps", "-", "run"]) {
                return Err(format!(
                    "job `{name}`: a `run:` at `{}` is not on a step (`steps:`, then `- run:`), and is refused",
                    entry.path.join(".")
                ));
            }
            found.push(entry.value.clone());
        }
    }
    Ok(found)
}

/// The value at `path` in the job `name` of `workflow`.
fn setting(workflow: &str, name: &str, path: &[&str]) -> Result<String, String> {
    job(workflow, name)?
        .into_iter()
        .find(|entry| entry.at(path))
        .map(|entry| entry.value)
        .ok_or_else(|| format!("the job `{name}` of ci.yml has no `{}:`", path.join(".")))
}

/// The systems the job `name` runs on: its `strategy.matrix.os: [a, b]`, in
/// order.
fn systems(workflow: &str, name: &str) -> Result<Vec<String>, String> {
    let list = setting(workflow, name, &["strategy", "matrix", "os"])?;
    let inner = list
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| {
            format!("the job `{name}` of ci.yml names its systems `os: [a, b]`, not `os: {list}`")
        })?;
    Ok(inner.split(',').map(|os| os.trim().to_string()).collect())
}

#[test]
fn ci_runs_every_recipe_of_verify_with_timing_in_a_job_of_its_own() -> Result<(), String> {
    let verify = dependencies(&read("justfile")?, "verify")?;
    let workflow = read(".github/workflows/ci.yml")?;
    assert!(
        verify.iter().any(|recipe| recipe == "timing"),
        "`just verify` must run `timing` locally: {verify:?}"
    );
    let deterministic: Vec<&str> = verify
        .iter()
        .map(String::as_str)
        .filter(|recipe| *recipe != "timing")
        .collect();
    assert_eq!(
        runs(&workflow, "verify")?,
        [format!("just {}", deterministic.join(" "))],
        "the verify job of ci.yml must run every recipe of `just verify` but `timing`, in its order"
    );
    assert_eq!(
        setting(&workflow, "verify", &["name"])?,
        "verify",
        "release.yml asks for the check named `verify` before it publishes, and the ruleset requires it"
    );
    assert_eq!(
        runs(&workflow, "timing")?,
        ["just timing"],
        "the timing job of ci.yml must run `just timing` alone"
    );
    assert_eq!(
        setting(&workflow, "timing", &["name"])?,
        "timing",
        "the timing job's check is named `timing`"
    );
    Ok(())
}

#[test]
fn ci_runs_just_test_alone_on_windows_and_macos() -> Result<(), String> {
    let justfile = read("justfile")?;
    let workflow = read(".github/workflows/ci.yml")?;
    assert!(
        dependencies(&justfile, "test")?.is_empty(),
        "`just test` runs its own command, not other recipes"
    );
    assert_eq!(
        runs(&workflow, "test")?,
        ["just test"],
        "the test job of ci.yml must run `just test` alone"
    );
    // CONTRIBUTING.md names its checks, for the ruleset to require later.
    assert_eq!(
        setting(&workflow, "test", &["name"])?,
        "test (${{ matrix.os }})",
        "the test job's checks are named `test (<system>)`"
    );
    assert_eq!(
        setting(&workflow, "test", &["runs-on"])?,
        "${{ matrix.os }}",
        "the test job of ci.yml must run on each system of its matrix"
    );
    assert_eq!(
        systems(&workflow, "test")?,
        ["windows-latest", "macos-latest"],
        "the test job of ci.yml must run on Windows and on macOS"
    );
    Ok(())
}

#[test]
fn ci_runs_just_oldest_rust_alone_on_linux() -> Result<(), String> {
    let justfile = read("justfile")?;
    let workflow = read(".github/workflows/ci.yml")?;
    assert!(
        dependencies(&justfile, "oldest-rust")?.is_empty(),
        "`just oldest-rust` runs its own commands, not other recipes"
    );
    assert!(
        !dependencies(&justfile, "verify")?
            .iter()
            .any(|recipe| recipe == "oldest-rust"),
        "`just verify` runs with the pinned Rust alone, so it does not run `oldest-rust`"
    );
    assert_eq!(
        runs(&workflow, "oldest-rust")?,
        ["just oldest-rust"],
        "the oldest-rust job of ci.yml must run `just oldest-rust` alone"
    );
    assert_eq!(
        setting(&workflow, "oldest-rust", &["name"])?,
        "oldest-rust",
        "the oldest-rust job's check is named `oldest-rust`"
    );
    assert_eq!(
        setting(&workflow, "oldest-rust", &["runs-on"])?,
        "ubuntu-latest",
        "the oldest-rust job of ci.yml runs on Linux"
    );
    Ok(())
}

/// The recipes that need the network, each run by the CI job of its name:
/// their answer depends on the advisory database and on crates.io, which
/// change without a commit here, so `just verify` runs neither.
const NETWORK: [&str; 2] = ["advisories", "semver"];

#[test]
fn ci_runs_each_recipe_that_needs_the_network_alone_in_a_job_of_its_own() -> Result<(), String> {
    let justfile = read("justfile")?;
    let workflow = read(".github/workflows/ci.yml")?;
    let verify = dependencies(&justfile, "verify")?;
    for recipe in NETWORK {
        assert!(
            dependencies(&justfile, recipe)?.is_empty(),
            "`just {recipe}` runs its own command, not other recipes"
        );
        assert!(
            !verify.iter().any(|name| name == recipe),
            "`just verify` reads no network, so it does not run `{recipe}`"
        );
        assert_eq!(
            runs(&workflow, recipe)?,
            [format!("just {recipe}")],
            "the {recipe} job of ci.yml must run `just {recipe}` alone"
        );
        assert_eq!(
            setting(&workflow, recipe, &["name"])?,
            recipe,
            "the {recipe} job's check is named `{recipe}`"
        );
        assert_eq!(
            setting(&workflow, recipe, &["runs-on"])?,
            "ubuntu-latest",
            "the {recipe} job of ci.yml runs on Linux"
        );
    }
    Ok(())
}

/// The value of the justfile variable `name` (`name := "value"`), unquoted.
fn variable(justfile: &str, name: &str) -> Result<String, String> {
    let head = format!("{name} := ");
    justfile
        .lines()
        .find_map(|line| line.strip_prefix(&head))
        .map(|rest| rest.trim().trim_matches('"').to_string())
        .ok_or_else(|| format!("the justfile has no variable `{name} := \"…\"`"))
}

/// The text of the section `## title` of a changelog, up to the next `## `,
/// or nothing when it has no such section.
fn section<'a>(changelog: &'a str, title: &str) -> Vec<&'a str> {
    let head = format!("## {title}");
    changelog
        .lines()
        .skip_while(|line| line.trim_end() != head)
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .filter(|line| !line.trim().is_empty())
        .collect()
}

#[test]
fn the_semver_job_reads_the_next_bump_with_the_checker_contributing_installs() -> Result<(), String>
{
    let justfile = read("justfile")?;
    let bump = variable(&justfile, "next_bump")?;
    assert!(
        bump.is_empty() || bump == "minor",
        "`next_bump` in the justfile is empty or `minor`, not `{bump}`"
    );
    let changelog = read("CHANGELOG.md")?;
    assert!(
        bump.is_empty() || !section(&changelog, "Unreleased").is_empty(),
        "`next_bump` is `minor` while CHANGELOG.md's Unreleased section is empty: a release's \
         commit, which moves that section under its version, empties `next_bump` too, so the \
         version it bumps to is what `just semver` reads"
    );
    let workflow = read(".github/workflows/ci.yml")?;
    assert_eq!(
        setting(
            &workflow,
            "semver",
            &["steps", "-", "with", "persist-credentials"]
        )?,
        "false",
        "the semver job keeps no credentials in its checkout"
    );
    assert_eq!(
        setting(&workflow, "semver", &["permissions", "contents"])?,
        "read",
        "the semver job may only read the repository"
    );
    let tool = setting(&workflow, "semver", &["steps", "-", "with", "tool"])?;
    let version = tool
        .strip_prefix("cargo-semver-checks@")
        .filter(|version| full_version(version))
        .ok_or_else(|| {
            format!("the semver job installs `{tool}`, not cargo-semver-checks@MAJOR.MINOR.PATCH")
        })?;
    assert_eq!(
        installed(&read("CONTRIBUTING.md")?, "cargo-semver-checks"),
        [version],
        "CONTRIBUTING.md installs cargo-semver-checks once, at {version}, the version the semver \
         job does"
    );
    Ok(())
}

/// Whether `version` is a full version, `MAJOR.MINOR.PATCH`, and nothing
/// else.
fn full_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

/// Every version `doc` installs `tool` at, `cargo install --locked
/// tool@VERSION`, the version read to the white space or the end of the
/// line after it.
fn installed<'a>(doc: &'a str, tool: &str) -> Vec<&'a str> {
    let head = format!("cargo install --locked {tool}@");
    doc.lines()
        .flat_map(|line| line.match_indices(&head).map(move |(at, _)| &line[at..]))
        .map(|rest| {
            let version = &rest[head.len()..];
            version
                .split_once(char::is_whitespace)
                .map_or(version, |(version, _)| version)
        })
        .collect()
}

#[test]
fn a_variable_and_a_section_are_read_from_their_lines() -> Result<(), String> {
    let justfile = "x := \"1\"\nnext_bump := \"\"\nlast := \"minor\"\n";
    assert_eq!(variable(justfile, "next_bump")?, "");
    assert_eq!(variable(justfile, "last")?, "minor");
    assert!(variable(justfile, "next").is_err());
    let changelog = "# Changelog\n\nIntro.\n\n## Unreleased\n\n## 0.1.4 (2026-11-22)\n\nA patch.\n";
    assert!(section(changelog, "Unreleased").is_empty());
    assert_eq!(section(changelog, "0.1.4 (2026-11-22)"), ["A patch."]);
    assert!(section(changelog, "0.1.3").is_empty());
    let open = changelog.replace("## Unreleased\n", "## Unreleased\n\nA change.\n");
    assert_eq!(section(&open, "Unreleased"), ["A change."]);
    Ok(())
}

#[test]
fn a_tool_version_is_read_whole_and_full() {
    assert!(full_version("0.51.0"));
    for partial in [
        "", "0", "0.5", "0.51.", "0.51.0.1", "0.51.x", "v0.51.0", "0.51.0 ",
    ] {
        assert!(
            !full_version(partial),
            "{partial:?} is read as a full version"
        );
    }
    let doc =
        "```sh\ncargo install --locked t@0.51.0   # for x\ncargo install --locked t@0.51.01\n\
               cargo install --locked t@\ncargo install --locked other@1.0.0\n```\n";
    assert_eq!(installed(doc, "t"), ["0.51.0", "0.51.01", ""]);
    assert_eq!(installed(doc, "other"), ["1.0.0"]);
    assert!(installed(doc, "none").is_empty());
}

/// A workflow with two jobs, the first as ci.yml writes its `test` job.
const SAMPLE: &str = "\
env:
  test: x
jobs:
  test:
    name: test (${{ matrix.os }})
    strategy:
      fail-fast: false
      matrix:
        # The systems.
        os: [a, b]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: x@sha # v1
        with:
          key: \"k-${{ vars.K || '1' }}\"
  # A comment two spaces in does not end the job.
      - run: just test
        timeout-minutes: 5

  other:
    steps:
      - run: just other
";

#[test]
fn a_job_is_read_from_its_own_lines() -> Result<(), String> {
    assert_eq!(runs(SAMPLE, "test")?, ["just test"]);
    assert_eq!(runs(SAMPLE, "other")?, ["just other"]);
    assert_eq!(
        setting(SAMPLE, "test", &["name"])?,
        "test (${{ matrix.os }})"
    );
    assert_eq!(setting(SAMPLE, "test", &["runs-on"])?, "${{ matrix.os }}");
    assert_eq!(
        setting(SAMPLE, "test", &["steps", "-", "with", "key"])?,
        "k-${{ vars.K || '1' }}"
    );
    assert_eq!(systems(SAMPLE, "test")?, ["a", "b"]);
    assert!(runs(SAMPLE, "gone").is_err(), "a job removed is missed");
    assert!(systems(SAMPLE, "other").is_err(), "a job with no matrix");
    let one = SAMPLE.replace("[a, b]", "a");
    assert!(systems(&one, "test").is_err(), "a system not in a list");
    // Comments after `jobs:` and a job's head, and steps not indented under
    // `steps:`, are read.
    let commented = SAMPLE
        .replace("jobs:\n", "jobs: # all\n")
        .replace("  test:\n", "  test: # here\n");
    assert_eq!(runs(&commented, "test")?, ["just test"]);
    let flush =
        "    steps:\n    - run: just test\n      timeout-minutes: 5\n    - run: just lint\n";
    let flat = SAMPLE.replace(
        "    steps:\n      - uses: x@sha # v1\n        with:\n          key: \"k-${{ vars.K || '1' }}\"\n  # A comment two spaces in does not end the job.\n      - run: just test\n        timeout-minutes: 5\n",
        flush,
    );
    assert_ne!(flat, SAMPLE);
    assert_eq!(runs(&flat, "test")?, ["just test", "just lint"]);
    // The `test:` under `env:` is no job.
    let moved = SAMPLE.replace("jobs:\n  test:", "jobs:\n  tests:");
    assert!(runs(&moved, "test").is_err(), "a key outside `jobs:`");
    Ok(())
}

#[test]
fn a_form_that_could_hide_what_a_job_runs_is_refused() {
    let step = "      - run: just test\n";
    let forms = [
        (
            "matrix exclude",
            "        os: [a, b]\n        exclude:\n          - os: a\n",
        ),
        ("job if", "    runs-on: ${{ matrix.os }}\n    if: false\n"),
        ("step if", "      - run: just test\n        if: false\n"),
        (
            "continue-on-error",
            "      - run: just test\n        continue-on-error: true\n",
        ),
        (
            "working-directory",
            "      - run: just test\n        working-directory: x\n",
        ),
        (
            "flow mapping",
            "      - run: just test\n      - {run: just package}\n",
        ),
        (
            "quoted key",
            "      - run: just test\n      - \"run\": just package\n",
        ),
        ("block run", "      - run: |\n          just test\n"),
        (
            "continued value",
            "      - run: just test\n          lint\n",
        ),
        ("alias", "      - run: just test\n      - <<: *steps\n"),
        (
            "run off a step",
            "      - run: just test\n    defaults:\n      run: x\n",
        ),
        ("twice", "      - run: just test\n        run: just lint\n"),
        (
            "tab after the colon",
            "      - run: just test\n      - run:\tjust package\n",
        ),
        (
            "explicit key",
            "      - run: just test\n      - ? run\n        : just package\n",
        ),
        (
            "plain list item",
            "      - run: just test\n      - just package\n",
        ),
        ("shell", "      - run: just test\n        shell: echo {0}\n"),
        ("needs", "    runs-on: ${{ matrix.os }}\n    needs: other\n"),
    ];
    for (what, form) in forms {
        let anchor = if form.starts_with("        os:") {
            "        os: [a, b]\n"
        } else if form.starts_with("    runs-on:") {
            "    runs-on: ${{ matrix.os }}\n"
        } else {
            step
        };
        let workflow = SAMPLE.replacen(anchor, form, 1);
        assert_ne!(workflow, SAMPLE, "{what}: the form was not put in");
        let read = runs(&workflow, "test").and_then(|_| systems(&workflow, "test"));
        assert!(read.is_err(), "{what} is read: {read:?}");
    }
    // A run kept in another step's block is text, not a step.
    let hidden = SAMPLE.replace(
        step,
        "      - uses: y@sha\n        with:\n          script: |\n            - run: just test\n",
    );
    assert_eq!(runs(&hidden, "test"), Ok(Vec::new()));
}
