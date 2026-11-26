//! CI runs the gate `just verify` runs locally, in two jobs: the `verify`
//! job runs every recipe of it but `timing`, in its order, and the `timing`
//! job runs `just timing` alone. A recipe added to `verify` and not to CI
//! fails here. The `timing` job is a required check, and the comment above
//! it and CONTRIBUTING.md must say so. The `test` job runs `just test` alone, on Windows and on
//! macOS, and the `oldest-rust` job runs `just oldest-rust` alone, on Linux:
//! a job removed, a system dropped or another command fails here too. The
//! `grammars` job runs `just grammars --require bash --entries` alone, a
//! recipe `just verify` does not run: it starts bash, and is not part of the
//! gate; PowerShell is not run there yet, and bash is required. The two
//! recipes that need the network, `advisories` (the advisory database) and
//! `semver` (each crate's last release on crates.io), are not part of
//! `just verify` either, and each has a job of its own, on Linux, that runs
//! it alone. The semver job checks out with no credentials kept, may only
//! read the repository, and installs cargo-semver-checks at a full version,
//! `MAJOR.MINOR.PATCH`, the one CONTRIBUTING.md installs once and no other;
//! the justfile's `next_bump`, which it reads, is empty or `minor`, and
//! empty while CHANGELOG.md's Unreleased section is. The `fuzz` job of
//! fuzz.yml, a workflow of its own that runs weekly and by hand, never on a
//! push or a pull request, runs `just fuzz` alone for each fuzz target
//! `tools/fuzz/Cargo.toml` names, one job each, and its one `if:` is the
//! step that keeps what a failed run found as an artifact, never in the
//! log.
//!
//! The workflow is read line by line, as plain block YAML: each job under
//! `jobs:`, each key by where it sits, comments skipped. In the eight jobs
//! held here, some ways a job could run less than it shows are refused, never
//! read: the keys `if:` (but the fuzz job's one, above), `continue-on-error:`, `needs:`, `shell:`,
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
    parse(workflow, name, false)
}

/// The step that keeps what a failed fuzz run found: the one step of a held
/// job an `if:` may be on, this one.
const KEEPS_FOUND: &str = "${{ failure() }}";

/// [`job`], with `if: ${{ failure() }}` read rather than refused when
/// `failure_step` is set: [`fuzz_job`] holds where it is.
fn parse(workflow: &str, name: &str, failure_step: bool) -> Result<Vec<Entry>, String> {
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
        let kept = failure_step && key == "if" && plain(value) == KEEPS_FOUND;
        if REFUSED.contains(&key) && !kept {
            return refuse(
                line,
                "this key can keep the job from running what it shows, so it is refused here",
            );
        }
        let value = value.trim();
        if value.starts_with(['{', '&', '*', '!'])
            || value.starts_with('[') && key != "os" && key != "target"
        {
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
    matrix(workflow, name, "os")
}

/// The list `strategy.matrix.KEY: [a, b]` of the job `name`, in order.
fn matrix(workflow: &str, name: &str, key: &str) -> Result<Vec<String>, String> {
    let list = setting(workflow, name, &["strategy", "matrix", key])?;
    let inner = list
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| {
            format!("the job `{name}` names its matrix `{key}: [a, b]`, not `{key}: {list}`")
        })?;
    Ok(inner
        .split(',')
        .map(|item| item.trim().to_string())
        .collect())
}

/// The fuzz job's keys, with its one `if:` read: only on its last step,
/// which uses `actions/upload-artifact` and runs nothing; or why not.
fn fuzz_job(workflow: &str, name: &str) -> Result<Vec<Entry>, String> {
    let entries = parse(workflow, name, true)?;
    let step = |entry: &Entry| entry.path.get(1).cloned();
    let last = entries
        .iter()
        .filter(|entry| entry.path.first().is_some_and(|key| key == "steps"))
        .filter_map(step)
        .next_back();
    for entry in entries
        .iter()
        .filter(|entry| entry.path.last().is_some_and(|key| key == "if"))
    {
        let on_last = entry.at(&["steps", "-", "if"]) && step(entry) == last;
        let uploads = entries.iter().any(|other| {
            step(other) == step(entry)
                && other.at(&["steps", "-", "uses"])
                && other.value.starts_with("actions/upload-artifact@")
        });
        let runs = entries
            .iter()
            .any(|other| step(other) == step(entry) && other.at(&["steps", "-", "run"]));
        if !on_last || !uploads || runs {
            return Err(format!(
                "job `{name}`: `if: {KEEPS_FOUND}` is on its last step alone, which keeps what a \
                 failed run found with actions/upload-artifact and runs nothing: found it at `{}`",
                entry.path.join(".")
            ));
        }
    }
    Ok(entries)
}

/// The names of the keys right under the top-level key `top` of
/// `workflow` (its `on:` triggers), in order.
fn under_top(workflow: &str, top: &str) -> Vec<String> {
    let head = format!("{top}:");
    workflow
        .lines()
        .skip_while(|line| uncommented(line) != head)
        .skip(1)
        .take_while(|line| blank(line) || indent(line) > 0)
        .filter(|line| !blank(line) && indent(line) == 2)
        .filter_map(|line| {
            line.trim()
                .strip_suffix(':')
                .or_else(|| line.trim().split_once(": ").map(|(key, _)| key))
        })
        .map(str::to_string)
        .collect()
}

/// The names of the `[[bin]]` programs `manifest` names, in order.
fn programs(manifest: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
            continue;
        }
        if let Some(name) = in_bin
            .then(|| line.strip_prefix("name"))
            .flatten()
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        {
            found.push(name.trim().trim_matches('"').to_string());
        }
    }
    found
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

/// The comment right above the job `name` of `workflow`, its lines joined
/// by a space, without their `#`.
fn comment_above(workflow: &str, name: &str) -> Result<String, String> {
    let lines: Vec<&str> = workflow.lines().collect();
    let at = lines
        .iter()
        .position(|line| *line == format!("  {name}:"))
        .ok_or_else(|| format!("ci.yml has no job `{name}`"))?;
    let mut said: Vec<&str> = lines[..at]
        .iter()
        .rev()
        .map_while(|line| line.trim_start().strip_prefix('#'))
        .map(str::trim)
        .collect();
    said.reverse();
    Ok(said.join(" "))
}

/// `text` with every run of white space one space, so a phrase is found
/// wherever its lines wrap.
fn flowed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_timing_job_is_described_as_a_required_check() -> Result<(), String> {
    // A guard that hangs on a crafted line is a vulnerability (SECURITY.md),
    // so the check that would catch one stops a merge: the workflow and
    // CONTRIBUTING.md say so, and name the check the owner adds to the
    // ruleset on `main`.
    let comment = comment_above(&read(".github/workflows/ci.yml")?, "timing")?;
    assert!(
        comment.contains("Required: the ruleset on `main` requires its check, `timing`"),
        "the comment above the timing job of ci.yml must say it is required: {comment:?}"
    );
    assert!(
        !comment.to_lowercase().contains("advisory"),
        "the timing job is required, not advisory: {comment:?}"
    );
    let contributing = flowed(&read("CONTRIBUTING.md")?);
    for phrase in [
        "The `timing` job runs `just timing` alone, and it is required too",
        "the ruleset on `main` requires two checks, `verify` and `timing`",
        "add the check `timing` from GitHub Actions",
        "it merges only once CI's `verify` and `timing` jobs have passed on it",
    ] {
        assert!(
            contributing.contains(phrase),
            "CONTRIBUTING.md must say the timing job is required: {phrase:?}"
        );
    }
    assert!(
        !contributing.contains("a red `timing` run there is a time to look at"),
        "CONTRIBUTING.md must not call the timing job advisory"
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
fn ci_runs_just_grammars_alone_outside_the_gate() -> Result<(), String> {
    let justfile = read("justfile")?;
    let workflow = read(".github/workflows/ci.yml")?;
    // It takes the tool's flags, and depends on no other recipe.
    assert!(
        justfile.lines().any(|line| line == "grammars *flags:"),
        "the justfile has the recipe `grammars *flags:`, which runs its own commands"
    );
    for recipe in ["verify", "test"] {
        assert!(
            !dependencies(&justfile, recipe)?
                .iter()
                .any(|r| r == "grammars"),
            "`just {recipe}` must not run `grammars`: it starts the real shells"
        );
    }
    assert_eq!(
        runs(&workflow, "grammars")?,
        ["just grammars --require bash --entries"],
        "the grammars job of ci.yml must run `just grammars` alone, bash required and \
         PowerShell not run"
    );
    assert_eq!(
        setting(&workflow, "grammars", &["name"])?,
        "grammars",
        "the grammars job's check is named `grammars`"
    );
    assert_eq!(
        setting(&workflow, "grammars", &["runs-on"])?,
        "ubuntu-latest",
        "the grammars job runs on Linux, where bash and pwsh come with the runner"
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

#[test]
fn the_fuzz_workflow_runs_just_fuzz_for_each_target_weekly() -> Result<(), String> {
    let justfile = read("justfile")?;
    let workflow = read(".github/workflows/fuzz.yml")?;
    assert!(
        justfile
            .lines()
            .any(|line| line == "fuzz target seconds=\"300\" *flags:"),
        "the justfile has the recipe `fuzz target seconds=\"300\" *flags:`, which runs its own \
         commands"
    );
    for recipe in ["verify", "test"] {
        assert!(
            !dependencies(&justfile, recipe)?.iter().any(|r| r == "fuzz"),
            "`just {recipe}` must not run `fuzz`: it needs a nightly Rust and cargo-fuzz"
        );
    }
    // Weekly and by hand, never on a push or a pull request.
    assert_eq!(
        under_top(&workflow, "on"),
        ["schedule", "workflow_dispatch"],
        "fuzz.yml runs on a schedule and by hand alone"
    );
    let entries = fuzz_job(&workflow, "fuzz")?;
    let found: Vec<&str> = entries
        .iter()
        .filter(|entry| entry.at(&["steps", "-", "run"]))
        .map(|entry| entry.value.as_str())
        .collect();
    assert_eq!(
        found,
        ["just fuzz ${{ matrix.target }} 300"],
        "the fuzz job runs `just fuzz` alone, on its target, for five minutes"
    );
    assert_eq!(
        setting_of(&entries, &["name"]),
        Some("fuzz (${{ matrix.target }})"),
        "the fuzz job's checks are named `fuzz (<target>)`"
    );
    assert_eq!(
        setting_of(&entries, &["runs-on"]),
        Some("ubuntu-latest"),
        "the fuzz job runs on Linux"
    );
    // Every target of the tool, and only those, each in a job of its own.
    let manifest = read("tools/fuzz/Cargo.toml")?;
    let targets: Vec<String> = programs(&manifest)
        .into_iter()
        .filter(|name| name != "fuzz")
        .collect();
    assert!(targets.len() >= 9, "the fuzz targets: {targets:?}");
    let matrix = {
        let list = setting_of(&entries, &["strategy", "matrix", "target"]).unwrap_or_default();
        list.trim_matches(['[', ']'])
            .split(',')
            .map(|item| item.trim().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        matrix, targets,
        "the fuzz job runs every target of tools/fuzz/Cargo.toml, in its order"
    );
    // What a failed run found is kept as an artifact of the run, never
    // printed: the folder the runner keeps it in.
    assert_eq!(
        setting_of(&entries, &["steps", "-", "with", "path"]),
        Some("target/fuzz/found/${{ matrix.target }}"),
        "the fuzz job keeps the folder the runner keeps what it found in"
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

/// The value at `path` among `entries`.
fn setting_of<'a>(entries: &'a [Entry], path: &[&str]) -> Option<&'a str> {
    entries
        .iter()
        .find(|entry| entry.at(path))
        .map(|entry| entry.value.as_str())
}

/// A fuzz job as fuzz.yml writes it.
const FUZZ_SAMPLE: &str = "\
on:
  schedule:
    - cron: \"17 4 * * 1\"
  workflow_dispatch:
jobs:
  fuzz:
    strategy:
      matrix:
        target: [a, b]
    steps:
      - uses: x@sha
      - run: just fuzz ${{ matrix.target }} 300
      - name: Keep
        if: ${{ failure() }}
        uses: actions/upload-artifact@sha # v4
        with:
          path: target/fuzz/found/${{ matrix.target }}
";

#[test]
fn the_fuzz_job_keeps_what_it_found_in_its_last_step_alone() -> Result<(), String> {
    assert_eq!(
        under_top(FUZZ_SAMPLE, "on"),
        ["schedule", "workflow_dispatch"]
    );
    let entries = fuzz_job(FUZZ_SAMPLE, "fuzz")?;
    assert_eq!(
        setting_of(&entries, &["strategy", "matrix", "target"]),
        Some("[a, b]")
    );
    let unkept = FUZZ_SAMPLE.replacen("        if: ${{ failure() }}\n", "", 1);
    assert_eq!(matrix(&unkept, "fuzz", "target")?, ["a", "b"]);
    assert!(entries.iter().any(|entry| entry.at(&["steps", "-", "if"])));
    // Elsewhere an `if:` is still refused, in this job and in the others.
    assert!(
        job(FUZZ_SAMPLE, "fuzz").is_err(),
        "an `if:` in a job held by `job`"
    );
    let forms = [
        (
            "on the run",
            FUZZ_SAMPLE.replacen(
                "      - run: just fuzz ${{ matrix.target }} 300\n",
                "      - run: just fuzz ${{ matrix.target }} 300\n        if: ${{ failure() }}\n",
                1,
            ),
        ),
        (
            "another condition",
            FUZZ_SAMPLE.replacen("if: ${{ failure() }}", "if: ${{ always() }}", 1),
        ),
        (
            "on the job",
            FUZZ_SAMPLE.replacen(
                "    strategy:\n",
                "    if: ${{ failure() }}\n    strategy:\n",
                1,
            ),
        ),
        (
            "on a step that is not the last",
            FUZZ_SAMPLE.replacen(
                "      - uses: x@sha\n",
                "      - uses: actions/upload-artifact@sha\n        if: ${{ failure() }}\n",
                1,
            ),
        ),
        (
            "on a step that runs",
            FUZZ_SAMPLE.replacen(
                "        uses: actions/upload-artifact@sha # v4\n",
                "        run: just x\n",
                1,
            ),
        ),
    ];
    for (what, workflow) in forms {
        assert_ne!(workflow, FUZZ_SAMPLE, "{what}: the form was not put in");
        assert!(fuzz_job(&workflow, "fuzz").is_err(), "{what} is read");
    }
    let manifest = "[package]\nname = \"fuzz\"\n[[bin]]\nname = \"fuzz\"\npath = \"a\"\n\n[[bin]]\nname = \"x\"\n[dependencies]\nname = \"no\"\n";
    assert_eq!(programs(manifest), ["fuzz", "x"]);
    Ok(())
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
