//! Two Rust versions are named here, each in several places, and each must
//! be named the same everywhere it is.
//!
//! The pinned toolchain, `channel` in rust-toolchain.toml, is the one the
//! gate and CI build with: each workflow that installs Rust names it in its
//! `RUSTUP_TOOLCHAIN` variable and in the `toolchain:` input of each Rust
//! install step. Every workflow in `.github/workflows` is read. It is the
//! one toolchain file: none other is in a folder rustup reads one in when
//! cargo runs here (the root, the workspace's members and excluded folders,
//! and the folders between).
//!
//! The oldest the crates support, `rust-version` in Cargo.toml, which every
//! crate inherits, is at most the pinned one. The `oldest-rust` job of
//! ci.yml installs it and overrides `RUSTUP_TOOLCHAIN` with it, alone in its
//! own `env:`; no other job overrides the toolchain. A workflow is read line
//! by line, keys as `ci_jobs.rs` reads them; every line but a comment and a
//! `name:` is read for what could pick a Rust, whether a key reads it or
//! not: `RUSTUP_TOOLCHAIN` or a `toolchain` anywhere but in the keys above,
//! `cargo +…` and `rustc +…` (white space and joined lines made one), and
//! `rustup` but to add a component or a target or to show the toolchain.
//! The justfile names it in `oldest_rust`, which its `oldest-rust` recipe
//! builds and tests with; the README says the crates declare it, and
//! CONTRIBUTING.md how to install it. clippy.toml names no `msrv`, so clippy
//! reads `rust-version` too.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

use std::fs;
use std::path::Path;

/// The workflow that holds the job for the oldest supported Rust.
const CI: &str = ".github/workflows/ci.yml";

/// That job, the one that installs another Rust than the pinned one.
const OLDEST_JOB: &str = "oldest-rust";

/// The lines of the justfile's recipe of the same name, as written: what a
/// caller builds (default features, and the shell guard without them), then
/// the tests (every feature, and the shell guard's test without `inline`).
const OLDEST_RECIPE: [&str; 4] = [
    "cargo +{{oldest_rust}} build --workspace --locked",
    "cargo +{{oldest_rust}} build -p milo-guards-shell --no-default-features --locked",
    "cargo +{{oldest_rust}} test --workspace --all-features --locked",
    "cargo +{{oldest_rust}} test -p milo-guards-shell --no-default-features --test inline_off --locked",
];

/// Every workflow of the repository, by its path from the root.
fn workflows() -> Result<Vec<String>, String> {
    files(".github/workflows", &["yml", "yaml"])
}

/// The files in `folder` (from the root) with one of `extensions`, sorted.
fn files(folder: &str, extensions: &[&str]) -> Result<Vec<String>, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(folder);
    let entries =
        fs::read_dir(&path).map_err(|e| format!("cannot list {}: {e}", path.display()))?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", path.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let extension = Path::new(&name).extension().and_then(|e| e.to_str());
        if extension.is_some_and(|e| extensions.contains(&e)) {
            found.push(format!("{folder}/{name}"));
        }
    }
    found.sort();
    Ok(found)
}

/// Every crate of the workspace, by its folder from the root: the members
/// Cargo.toml names, each a folder that holds a `Cargo.toml`.
fn crates() -> Result<Vec<String>, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut found = Vec::new();
    for pattern in workspace_list(&read("Cargo.toml")?, "members") {
        for folder in workspace_folders(&root, &pattern)? {
            if fs::symlink_metadata(root.join(&folder).join("Cargo.toml")).is_ok() {
                found.push(folder);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// A file at the repository root, or a message saying which one is missing.
fn read(relative: &str) -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read {relative} ({e}): the Rust version is pinned there, so the file must exist at {}",
            path.display()
        )
    })
}

/// The quoted value of every `key = "value"` or `key: "value"` on a line of
/// `text` that starts with `key`, in order.
fn values(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim().strip_prefix(key))
        .filter_map(|rest| rest.trim_start().strip_prefix(['=', ':']))
        .filter_map(|rest| rest.split('#').next())
        .map(|rest| rest.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

/// The first of those, or a message saying the file has none.
fn value(text: &str, key: &str, file: &str) -> Result<String, String> {
    values(text, key)
        .into_iter()
        .next()
        .ok_or_else(|| format!("{file} has no line `{key} = \"…\"`"))
}

/// `1.99` for `1.99.1`.
fn major_minor(version: &str) -> String {
    version.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// The numbers of `version`, which must be `parts` of them: `[1, 99, 1]`
/// for `1.99.1`.
fn numbers(version: &str, parts: usize, what: &str) -> Result<Vec<u32>, String> {
    let numbers: Vec<u32> = version
        .split('.')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| format!("{what} is `{version}`, which is not a version"))?;
    if numbers.len() == parts {
        Ok(numbers)
    } else {
        Err(format!(
            "{what} is `{version}`: it is written with {parts} numbers"
        ))
    }
}

/// The pinned toolchain, a full version (major.minor.patch).
fn pinned() -> Result<String, String> {
    let pinned = value(
        &read("rust-toolchain.toml")?,
        "channel",
        "rust-toolchain.toml",
    )?;
    numbers(
        &pinned,
        3,
        "the channel rust-toolchain.toml pins (a full version, not a moving channel)",
    )?;
    Ok(pinned)
}

/// The oldest supported Rust, `rust-version` in Cargo.toml, as major.minor:
/// cargo reads it so, and every copy of it is spelled the same.
fn oldest() -> Result<String, String> {
    let oldest = value(&read("Cargo.toml")?, "rust-version", "Cargo.toml")?;
    numbers(&oldest, 2, "rust-version in Cargo.toml (major.minor)")?;
    Ok(oldest)
}

/// One key of a workflow: the keys above it, by indentation (the keys of an
/// item of a list sit at the column after its `- `), its own, and its value
/// without its comment and quotes.
#[derive(Debug)]
struct Key {
    above: Vec<String>,
    key: String,
    value: String,
}

impl Key {
    /// The job it is in, if it is in one.
    fn job(&self) -> Option<&str> {
        match self.above.as_slice() {
            [jobs, job, ..] if jobs == "jobs" => Some(job),
            _ => None,
        }
    }

    /// Whether the keys above it are `path`.
    fn under(&self, path: &[&str]) -> bool {
        self.above.len() == path.len() && self.above.iter().zip(path).all(|(a, b)| a == b)
    }
}

/// A line of a workflow, as it is read here.
#[derive(Debug)]
enum Line {
    /// Blank, or a comment.
    Blank,
    /// A key written bare (`run:`), where it sits.
    Key(Key),
    /// Anything else, which no key reads: a line of a block (`run: |`), a
    /// value continued from the line above, and a line whose key is not
    /// bare (a quoted key, a flow mapping, a plain list item). `label` when
    /// it goes on a `name:`, a step's or a job's label.
    Text { text: String, label: bool },
}

/// Whether `key` is written the one way a key is read here: bare, as
/// `ci_jobs.rs` reads one.
fn bare(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// `line` without a comment after it: a `#` at its start or after a space,
/// outside quotes. An unclosed quote keeps the rest of the line, so a line
/// is never cut shorter than it is.
fn uncommented(line: &str) -> &str {
    let mut quote = None;
    let mut previous = ' ';
    for (at, c) in line.char_indices() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' && previous.is_whitespace() => return &line[..at],
            None => {}
        }
        previous = c;
    }
    line
}

/// Every line of `workflow`, read as `ci_jobs.rs` reads a job: a key starts
/// at its own column, after any `- `; a key with a value on its line makes
/// every deeper line below it text (a block after `|` or `>`, a plain value
/// continued otherwise); a line whose key is not bare is text.
fn lines(workflow: &str) -> Vec<(&str, Line)> {
    let mut found = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    // A key whose value is on its line: its column, and whether it is a
    // `name:`.
    let mut open: Option<(usize, bool)> = None;
    for raw in workflow.lines() {
        let text = uncommented(raw);
        let mut content = text.trim_start_matches(' ');
        let mut column = text.len() - content.len();
        if let Some((at, label)) = open {
            if content.trim().is_empty() || column > at {
                let line = if content.trim().is_empty() {
                    Line::Blank
                } else {
                    Line::Text {
                        text: content.trim().to_string(),
                        label,
                    }
                };
                found.push((raw, line));
                continue;
            }
            open = None;
        }
        if content.trim().is_empty() {
            found.push((raw, Line::Blank));
            continue;
        }
        while let Some(rest) = content.strip_prefix("- ") {
            let item = rest.trim_start_matches(' ');
            column += content.len() - item.len();
            content = item;
        }
        let content = content.trim_end();
        let (key, value) = match content.split_once(": ") {
            Some((key, value)) => (key, value.trim()),
            None => content
                .strip_suffix(':')
                .map_or(("", content), |key| (key, "")),
        };
        if !bare(key) {
            found.push((
                raw,
                Line::Text {
                    text: content.to_string(),
                    label: false,
                },
            ));
            continue;
        }
        stack.retain(|(at, _)| *at < column);
        if !value.is_empty() {
            open = Some((column, key == "name"));
        }
        let key = key.to_string();
        found.push((
            raw,
            Line::Key(Key {
                above: stack.iter().map(|(_, key)| key.clone()).collect(),
                key: key.clone(),
                value: value.trim_matches(['"', '\'']).to_string(),
            }),
        ));
        stack.push((column, key));
    }
    found
}

/// How many steps of `workflow` install Rust: every line, a key or not,
/// that names the install action.
fn install_steps(workflow: &str) -> usize {
    workflow
        .lines()
        .filter(|line| uncommented(line).contains("dtolnay/rust-toolchain@"))
        .count()
}

/// What `rustup` may do in a step: add to the Rust the install step put in,
/// or show it. Anything else can install or select a Rust (`default`,
/// `override`, `toolchain`, `run`, `install`, `update`), which the install
/// step's `toolchain:` input and the job's `RUSTUP_TOOLCHAIN` do.
const RUSTUP_ALLOWED: [&str; 4] = [
    "rustup component add ",
    "rustup target add ",
    "rustup show",
    "rustup --version",
];

/// `text` with every run of white space one space, and a backslash before
/// a line break gone, so a command split over lines reads as one.
fn normalised(text: &str) -> String {
    text.replace("\\\n", " ")
        .split_whitespace()
        .filter(|word| *word != "\\")
        .collect::<Vec<_>>()
        .join(" ")
}

/// Why `text`, what a workflow could run, is refused, if it is: it picks a
/// Rust with `cargo +`, `rustc +` or a `rustup` that is not allowed.
fn refused_command(text: &str) -> Option<String> {
    let text = normalised(text);
    let around = |at: usize| {
        let from = text[..at]
            .char_indices()
            .rev()
            .nth(30)
            .map_or(0, |(i, _)| i);
        let to = text[at..]
            .char_indices()
            .nth(40)
            .map_or(text.len(), |(i, _)| at + i);
        text[from..to].to_string()
    };
    for picks in ["cargo +", "rustc +"] {
        if let Some(at) = text.find(picks) {
            return Some(format!(
                "`…{}…` picks a Rust of its own with `{picks}…`",
                around(at)
            ));
        }
    }
    let mut start = 0;
    while let Some(found) = text[start..].find("rustup") {
        let at = start + found;
        if !RUSTUP_ALLOWED
            .iter()
            .any(|allowed| text[at..].starts_with(allowed))
        {
            return Some(format!(
                "`…{}…` runs rustup other than to add a component or a target or to show the \
                 toolchain, which can install or select another Rust",
                around(at)
            ));
        }
        start = at + "rustup".len();
    }
    None
}

/// Whether `workflow`, the file `file`, names the pinned Rust everywhere but
/// in the oldest-rust job of ci.yml, which names the oldest supported one,
/// and nothing else picks a toolchain; or the first place it does not.
fn check_workflow(file: &str, workflow: &str, pinned: &str, oldest: &str) -> Result<(), String> {
    let installs = install_steps(workflow);
    let held = (file == CI).then_some(OLDEST_JOB);
    let lines = lines(workflow);
    // Everything a step could run, read whole: every line but a blank, a
    // comment and a label, whether a key reads it or not.
    let mut runnable = String::new();
    let mut keys = Vec::new();
    for (raw, line) in &lines {
        let label = match line {
            Line::Blank => continue,
            Line::Key(key) => {
                keys.push(key);
                key.key == "name"
            }
            Line::Text { label, .. } => *label,
        };
        if label {
            continue;
        }
        let text = uncommented(raw).trim();
        runnable.push_str(text);
        runnable.push('\n');
        let key = match line {
            Line::Key(key) => Some(key.key.as_str()),
            _ => None,
        };
        if text.contains("RUSTUP_TOOLCHAIN") && key != Some("RUSTUP_TOOLCHAIN") {
            return Err(format!(
                "{file}: `{text}` names RUSTUP_TOOLCHAIN other than as a bare key of an `env:`, \
                 where it is read"
            ));
        }
        let names_install = matches!(line, Line::Key(k) if k.key == "uses"
            && k.value.starts_with("dtolnay/rust-toolchain@"));
        if text.contains("toolchain") && key != Some("toolchain") && !names_install {
            return Err(format!(
                "{file}: `{text}` names a toolchain other than as the bare `toolchain:` input of \
                 an install step, where it is read"
            ));
        }
    }
    if let Some(why) = refused_command(&runnable) {
        return Err(format!(
            "{file}: {why}; a job's Rust is its RUSTUP_TOOLCHAIN and its install step's \
             `toolchain:` input"
        ));
    }
    let inputs: Vec<&&Key> = keys.iter().filter(|key| key.key == "toolchain").collect();
    if inputs.len() != installs {
        return Err(format!(
            "every Rust install step in {file} (dtolnay/rust-toolchain) needs a `toolchain:` \
             input, and only those do: found {} inputs and {installs} steps",
            inputs.len()
        ));
    }
    let mut global = Vec::new();
    let mut overrides = Vec::new();
    for key in keys.iter().filter(|key| key.key == "RUSTUP_TOOLCHAIN") {
        if key.under(&["env"]) {
            global.push(key.value.as_str());
        } else if held.is_some_and(|job| key.under(&["jobs", job, "env"])) {
            overrides.push(key.value.as_str());
        } else {
            return Err(format!(
                "{file} sets RUSTUP_TOOLCHAIN under `{}`: the workflow's `env:` names the pinned \
                 Rust, and only the `{OLDEST_JOB}` job of ci.yml overrides it, in its own `env:`",
                key.above.join(".")
            ));
        }
    }
    if installs == 0 && global.is_empty() && held.is_none() {
        return Ok(());
    }
    if global != [pinned] {
        return Err(format!(
            "{file} installs Rust, so its `env:` sets RUSTUP_TOOLCHAIN once, to `{pinned}` as \
             rust-toolchain.toml pins: found {global:?}"
        ));
    }
    let mut oldest_inputs = 0;
    for input in inputs {
        let (want, what) = if held.is_some() && input.job() == held {
            oldest_inputs += 1;
            (
                oldest,
                "the oldest supported Rust (rust-version in Cargo.toml)",
            )
        } else {
            (pinned, "the pinned Rust (rust-toolchain.toml)")
        };
        if input.value != want {
            return Err(format!(
                "a `toolchain:` input in {file}, in the job `{}`, installs `{}` but {what} is \
                 `{want}`",
                input.job().unwrap_or("none"),
                input.value
            ));
        }
    }
    if let Some(job) = held {
        if overrides != [oldest] || oldest_inputs != 1 {
            return Err(format!(
                "{file} has a job `{job}` that installs the oldest supported Rust, `{oldest}` \
                 (rust-version in Cargo.toml), with one install step and RUSTUP_TOOLCHAIN set to \
                 it in its own `env:`: found RUSTUP_TOOLCHAIN {overrides:?} and {oldest_inputs} \
                 install steps"
            ));
        }
        let env: Vec<&str> = keys
            .iter()
            .filter(|key| key.under(&["jobs", job, "env"]))
            .map(|key| key.key.as_str())
            .collect();
        if env != ["RUSTUP_TOOLCHAIN"] {
            return Err(format!(
                "the `env:` of the job `{job}` in {file} holds RUSTUP_TOOLCHAIN alone: found {env:?}"
            ));
        }
    }
    Ok(())
}

/// The value of the justfile variable `name` (`name := "value"`).
fn just_variable(justfile: &str, name: &str) -> Result<String, String> {
    let head = format!("{name} := ");
    justfile
        .lines()
        .find_map(|line| line.strip_prefix(&head))
        .map(|rest| rest.trim().trim_matches('"').to_string())
        .ok_or_else(|| format!("the justfile has no variable `{name} := \"…\"`"))
}

/// The command lines of the justfile recipe `recipe`, trimmed.
fn recipe_lines(justfile: &str, recipe: &str) -> Result<Vec<String>, String> {
    let head = format!("{recipe}:");
    let mut lines = justfile.lines();
    lines
        .by_ref()
        .find(|line| line.starts_with(&head))
        .ok_or_else(|| format!("the justfile has no recipe `{recipe}`"))?;
    Ok(lines
        .take_while(|line| line.starts_with([' ', '\t']))
        .map(|line| line.trim().to_string())
        .collect())
}

/// Every version a text names as `Rust 1.N` or `Rust 1.N.M`, in order.
fn rusts_named(text: &str) -> Vec<String> {
    text.match_indices("Rust ")
        .filter_map(|(at, word)| {
            let rest = &text[at + word.len()..];
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let version = version.trim_end_matches('.');
            (version.contains('.') && version.starts_with(|c: char| c.is_ascii_digit()))
                .then(|| version.to_string())
        })
        .collect()
}

#[test]
fn the_oldest_supported_rust_is_at_most_the_pinned_one() -> Result<(), String> {
    let pinned = pinned()?;
    let oldest = oldest()?;
    let pinned_release = numbers(&major_minor(&pinned), 2, "the pinned release")?;
    let oldest_release = numbers(&oldest, 2, "rust-version")?;
    assert!(
        oldest_release <= pinned_release,
        "rust-version in Cargo.toml (`{oldest}`) is above the pinned toolchain (`{pinned}`): \
         the gate would build with a Rust the crates do not support"
    );
    Ok(())
}

#[test]
fn every_crate_inherits_rust_version_from_the_workspace() -> Result<(), String> {
    let crates = crates()?;
    assert!(crates.len() >= 2, "the workspace's crates: {crates:?}");
    for folder in crates {
        let file = format!("{folder}/Cargo.toml");
        let manifest = read(&file)?;
        let lines: Vec<&str> = manifest
            .lines()
            .filter(|line| line.trim_start().starts_with("rust-version"))
            .map(str::trim)
            .collect();
        assert_eq!(
            lines,
            ["rust-version.workspace = true"],
            "{file} takes rust-version from the workspace, and names none of its own"
        );
    }
    Ok(())
}

#[test]
fn every_workflow_installs_the_pinned_rust_but_the_oldest_rust_job() -> Result<(), String> {
    let pinned = pinned()?;
    let oldest = oldest()?;
    let workflows = workflows()?;
    assert!(
        workflows.iter().any(|file| file == CI),
        "{CI} is read: {workflows:?}"
    );
    let mut installing = 0;
    for file in workflows {
        let workflow = read(&file)?;
        if install_steps(&workflow) > 0 {
            installing += 1;
        }
        check_workflow(&file, &workflow, &pinned, &oldest)?;
    }
    assert!(installing >= 2, "ci.yml and release.yml both install Rust");
    Ok(())
}

#[test]
fn the_justfile_builds_and_tests_with_the_oldest_supported_rust() -> Result<(), String> {
    let oldest = oldest()?;
    let justfile = read("justfile")?;
    assert_eq!(
        just_variable(&justfile, "oldest_rust")?,
        oldest,
        "`oldest_rust` in the justfile must be rust-version in Cargo.toml"
    );
    assert_eq!(
        recipe_lines(&justfile, OLDEST_JOB)?,
        OLDEST_RECIPE,
        "`just {OLDEST_JOB}` builds and tests the workspace with `oldest_rust`"
    );
    Ok(())
}

#[test]
fn the_docs_name_the_oldest_supported_rust() -> Result<(), String> {
    let pinned = pinned()?;
    let oldest = oldest()?;
    let readme = read("README.md")?;
    assert!(
        readme.contains(&format!("The crates declare Rust {oldest}")),
        "README.md says the crates declare Rust {oldest}, rust-version in Cargo.toml"
    );
    let contributing = read("CONTRIBUTING.md")?;
    assert!(
        contributing.contains(&format!(
            "rustup toolchain install {oldest} --profile minimal"
        )),
        "CONTRIBUTING.md says how to install Rust {oldest} for `just {OLDEST_JOB}`"
    );
    let mut docs = vec!["README.md".to_string(), "CONTRIBUTING.md".to_string()];
    for folder in crates()? {
        let readme = format!("{folder}/README.md");
        if Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&readme)
            .is_file()
        {
            docs.push(readme);
        }
    }
    for doc in docs {
        for named in rusts_named(&read(&doc)?) {
            assert!(
                named == oldest || named == pinned,
                "{doc} names Rust {named}: the Rust a doc names is the oldest supported, \
                 `{oldest}`, or the pinned one, `{pinned}`"
            );
        }
    }
    let clippy = read("clippy.toml")?;
    assert!(
        values(&clippy, "msrv").is_empty(),
        "clippy.toml names no `msrv`: clippy reads rust-version in Cargo.toml, the one place it is named"
    );
    Ok(())
}

#[test]
fn a_version_line_is_read_from_toml_and_yaml() -> Result<(), String> {
    let toml = "[toolchain]\nchannel = \"1.99.1\"  # pinned\ncomponents = [\"clippy\"]\n";
    assert_eq!(value(toml, "channel", "t")?, "1.99.1");
    let yaml = "env:\n  CARGO_TERM_COLOR: always\n  RUSTUP_TOOLCHAIN: \"1.99.1\"\n";
    assert_eq!(value(yaml, "RUSTUP_TOOLCHAIN", "y")?, "1.99.1");
    assert!(value(yaml, "channel", "y").is_err());
    let steps = "- uses: dtolnay/rust-toolchain@abc # master\n  with:\n    toolchain: \"1.99.1\"\n\
                 - uses: dtolnay/rust-toolchain@abc\n  with:\n    toolchain: 1.98.0 # old\n";
    assert_eq!(values(steps, "toolchain"), ["1.99.1", "1.98.0"]);
    assert_eq!(install_steps(steps), 2);
    assert_eq!(major_minor("1.99.1"), "1.99");
    assert_eq!(major_minor("1.99"), "1.99");
    assert_eq!(numbers("1.90", 2, "v")?, [1, 90]);
    assert!(numbers("1.90.0", 2, "v").is_err());
    assert!(numbers("stable", 3, "v").is_err());
    assert!(numbers("1.9x.1", 3, "v").is_err());
    assert!(numbers("1.9", 2, "v")? < numbers("1.10", 2, "v")?);
    let justfile = "x := \"1\"\noldest_rust := \"1.90\"\n\n# Doc.\noldest-rust:\n    cargo a\n    cargo b\n\nnext:\n    c\n";
    assert_eq!(just_variable(justfile, "oldest_rust")?, "1.90");
    assert!(just_variable(justfile, "oldest").is_err());
    assert_eq!(
        recipe_lines(justfile, "oldest-rust")?,
        ["cargo a", "cargo b"]
    );
    assert!(recipe_lines(justfile, "gone").is_err());
    assert_eq!(
        rusts_named("needs Rust 1.90 or newer. Rust 1.99.1. A Rust library, Rust 2."),
        ["1.90", "1.99.1"]
    );
    Ok(())
}

/// A workflow as ci.yml writes its jobs: one on the pinned Rust and the one
/// on the oldest supported Rust.
const SAMPLE: &str = "\
env:
  RUSTUP_TOOLCHAIN: \"1.99.1\"

jobs:
  verify:
    steps:
      - uses: dtolnay/rust-toolchain@abc # master
        with:
          toolchain: \"1.99.1\"
      - run: just verify

  oldest-rust:
    # RUSTUP_TOOLCHAIN in a comment is no override.
    env:
      RUSTUP_TOOLCHAIN: \"1.90\"
    steps:
      - name: Install
        uses: dtolnay/rust-toolchain@abc # master
        with:
          toolchain: \"1.90\"
      - run: just oldest-rust
";

#[test]
fn a_workflow_is_held_to_the_two_versions() {
    assert_eq!(check_workflow(CI, SAMPLE, "1.99.1", "1.90"), Ok(()));
    let read = lines(SAMPLE);
    let inputs: Vec<(Option<&str>, &str)> = read
        .iter()
        .filter_map(|(_, line)| match line {
            Line::Key(key) if key.key == "toolchain" => Some((key.job(), key.value.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        inputs,
        [(Some("verify"), "1.99.1"), (Some("oldest-rust"), "1.90")]
    );
    // The oldest-rust job is held in ci.yml alone.
    assert!(check_workflow("release.yml", SAMPLE, "1.99.1", "1.90").is_err());
    let forms = [
        ("the job removed", SAMPLE.split("  oldest-rust:").next().unwrap_or_default().to_string()),
        (
            "the job's override another version",
            SAMPLE.replacen("RUSTUP_TOOLCHAIN: \"1.90\"", "RUSTUP_TOOLCHAIN: \"1.95\"", 1),
        ),
        (
            "the job's input another version",
            SAMPLE.replacen("toolchain: \"1.90\"", "toolchain: \"1.95\"", 1),
        ),
        (
            "the job's override dropped",
            SAMPLE.replacen("    env:\n      RUSTUP_TOOLCHAIN: \"1.90\"\n", "", 1),
        ),
        (
            "the override on a step",
            SAMPLE.replacen(
                "    env:\n      RUSTUP_TOOLCHAIN: \"1.90\"\n",
                "",
                1,
            )
            .replacen(
                "      - run: just oldest-rust\n",
                "      - run: just oldest-rust\n        env:\n          RUSTUP_TOOLCHAIN: \"1.90\"\n",
                1,
            ),
        ),
        (
            "another job overriding",
            SAMPLE.replacen(
                "  verify:\n",
                "  verify:\n    env:\n      RUSTUP_TOOLCHAIN: \"1.90\"\n",
                1,
            ),
        ),
        (
            "another job installing the oldest",
            SAMPLE.replacen("toolchain: \"1.99.1\"", "toolchain: \"1.90\"", 1),
        ),
        (
            "the global variable another version",
            SAMPLE.replacen("RUSTUP_TOOLCHAIN: \"1.99.1\"", "RUSTUP_TOOLCHAIN: \"1.98.0\"", 1),
        ),
        (
            "a script setting it",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - run: echo RUSTUP_TOOLCHAIN=1.90 >> \"$GITHUB_ENV\"\n      - run: just verify\n",
                1,
            ),
        ),
        (
            "a command picking its own",
            SAMPLE.replacen("run: just verify", "run: cargo +1.90 test", 1),
        ),
        (
            "rustup picking one",
            SAMPLE.replacen("run: just verify", "run: rustup default 1.90", 1),
        ),
        (
            "an install step with no input",
            SAMPLE.replacen("        with:\n          toolchain: \"1.99.1\"\n", "", 1),
        ),
        (
            "Rust installed by another action",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - uses: actions-rust-lang/setup-rust-toolchain@abc\n        with:\n          toolchain: \"1.80\"\n      - run: just verify\n",
                1,
            ),
        ),
        (
            "another variable in the job's env",
            SAMPLE.replacen(
                "      RUSTUP_TOOLCHAIN: \"1.90\"\n",
                "      RUSTUP_TOOLCHAIN: \"1.90\"\n      CARGO: /bin/true\n",
                1,
            ),
        ),
        (
            "a script setting it after a quoted hash",
            SAMPLE.replacen(
                "run: just verify",
                "run: echo \"release #1\"; echo RUSTUP_TOOLCHAIN=1.90 >> $GITHUB_ENV",
                1,
            ),
        ),
        (
            "a block script picking one",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - run: |\n          set -e\n          rustup override set 1.90\n",
                1,
            ),
        ),
    ];
    let more = [
        (
            "an install step after a step name written as a block",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - name: >-\n          Install\n        uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: nightly\n      - run: just verify\n",
                1,
            ),
        ),
        (
            "a step env after a step name written as a block",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - name: >-\n          Verify\n        run: just verify\n        env:\n          RUSTUP_TOOLCHAIN: \"1.90\"\n",
                1,
            ),
        ),
        (
            "a plain run continued on the next line",
            SAMPLE.replacen("run: just verify\n", "run: just verify\n          && rustup default 1.90\n", 1),
        ),
        (
            "a quoted run key",
            SAMPLE.replacen("- run: just verify", "- \"run\": rustup default 1.90", 1),
        ),
        (
            "a flow mapping step",
            SAMPLE.replacen("- run: just verify", "- { run: rustup default 1.90 }", 1),
        ),
        (
            "a quoted toolchain input",
            SAMPLE.replacen("toolchain: \"1.99.1\"", "\"toolchain\": nightly", 1),
        ),
        (
            "a flow mapping env",
            SAMPLE.replacen("  verify:\n", "  verify:\n    env: { RUSTUP_TOOLCHAIN: \"1.90\" }\n", 1),
        ),
        (
            "two spaces after cargo",
            SAMPLE.replacen("run: just verify", "run: cargo  +1.90 test", 1),
        ),
        (
            "cargo and its toolchain on two lines of a block",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - run: >\n          cargo\n          +1.90 test\n",
                1,
            ),
        ),
        (
            "cargo and its toolchain split by a backslash",
            SAMPLE.replacen(
                "      - run: just verify\n",
                "      - run: |\n          cargo \\\n            +1.90 test\n",
                1,
            ),
        ),
        (
            "rustup in a block that is not a run",
            SAMPLE.replacen(
                "          toolchain: \"1.99.1\"\n",
                "          toolchain: \"1.99.1\"\n          script: |\n            rustup default x\n",
                1,
            ),
        ),
    ];
    for (what, workflow) in forms.into_iter().chain(more) {
        assert_ne!(workflow, SAMPLE, "{what}: the form was not put in");
        let checked = check_workflow(CI, &workflow, "1.99.1", "1.90");
        assert!(checked.is_err(), "{what} is not refused");
    }
    // What does not pick a Rust is read and let through.
    let allowed = [
        (
            "rustup in a step's name",
            SAMPLE.replacen(
                "      - name: Install\n",
                "      - name: Install with rustup and its proxies\n",
                1,
            ),
        ),
        (
            "a component added",
            SAMPLE.replacen(
                "run: just verify",
                "run: rustup component add clippy && just verify",
                1,
            ),
        ),
        (
            "the toolchain shown",
            SAMPLE.replacen("run: just verify", "run: rustup show", 1),
        ),
        (
            "a hash in a quoted string",
            SAMPLE.replacen("run: just verify", "run: echo \"release #1\" # a note", 1),
        ),
        (
            "a step's name folded over lines",
            SAMPLE.replacen(
                "      - name: Install\n",
                "      - name: >-\n          Install with rustup\n          and its toolchain\n",
                1,
            ),
        ),
    ];
    for (what, workflow) in allowed {
        assert_ne!(workflow, SAMPLE, "{what}: the form was not put in");
        assert_eq!(
            check_workflow(CI, &workflow, "1.99.1", "1.90"),
            Ok(()),
            "{what} is refused"
        );
    }
}

#[test]
fn a_line_is_read_without_its_comment_and_a_step_for_what_it_runs() {
    assert_eq!(uncommented("a: b # c"), "a: b ");
    assert_eq!(uncommented("# all"), "");
    assert_eq!(uncommented("echo \"a #1\" # c"), "echo \"a #1\" ");
    assert_eq!(uncommented("echo 'a #1'"), "echo 'a #1'");
    assert_eq!(uncommented("echo a#1"), "echo a#1");
    assert_eq!(uncommented("echo \"open #1"), "echo \"open #1");
    let read = lines(
        "steps:\n  - name: >-\n      rustup x\n    uses: y\n  - run: just a # b\n    \"run\": c\n  - run: |\n      one \"#2\"\n\n      # gone\n  - run: d\n      && e\n",
    );
    let read: Vec<String> = read
        .iter()
        .map(|(_, line)| match line {
            Line::Blank => "-".to_string(),
            Line::Key(key) => format!("{}.{}={}", key.above.join("."), key.key, key.value),
            Line::Text { text, label } => {
                format!("{}{text}", if *label { "label " } else { "text " })
            }
        })
        .collect();
    assert_eq!(
        read,
        [
            ".steps=",
            "steps.name=>-",
            "label rustup x",
            "steps.uses=y",
            "steps.run=just a",
            "text \"run\": c",
            "steps.run=|",
            "text one \"#2\"",
            "-",
            "-",
            "steps.run=d",
            "text && e",
        ]
    );
    assert_eq!(normalised("cargo  +1.90\ttest"), "cargo +1.90 test");
    assert_eq!(normalised("cargo \\\n  +1.90 test"), "cargo +1.90 test");
    assert_eq!(normalised("cargo \\\n+1.90"), "cargo +1.90");
    assert!(refused_command("rustup component add clippy").is_none());
    assert!(refused_command("rustup target add x && rustup show").is_none());
    assert!(refused_command("rustup show && rustup default 1.90").is_some());
    assert!(refused_command("rustup toolchain install 1.90").is_some());
    assert!(refused_command("cargo +1.90 test").is_some());
}

/// The quoted values of the list `key = [...]` in the `[workspace]` table of
/// `manifest`.
fn workspace_list(manifest: &str, key: &str) -> Vec<String> {
    let table: Vec<&str> = manifest
        .lines()
        .skip_while(|line| line.trim() != "[workspace]")
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .map(uncommented)
        .collect();
    let Some(at) = table.iter().position(|line| {
        line.trim()
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    }) else {
        return Vec::new();
    };
    let list = table[at..].join("\n");
    let inside = list
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map_or("", |(inside, _)| inside);
    inside
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Whether `path` is a folder, read without following a symlink.
fn real_folder(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// Whether `path` holds a `.git` entry: another checkout, never this one's.
fn holds_git(path: &Path) -> bool {
    fs::symlink_metadata(path.join(".git")).is_ok()
}

/// The folders, from the root, that a member or exclude `pattern` of the
/// workspace names: the folder itself, or each real folder a trailing `/*`
/// matches, but for one that holds another checkout.
fn workspace_folders(root: &Path, pattern: &str) -> Result<Vec<String>, String> {
    if pattern.contains(['?', '[', '{']) || pattern.trim_end_matches("/*").contains('*') {
        return Err(format!(
            "the workspace names `{pattern}`: this test reads a folder or `folder/*`"
        ));
    }
    let Some(parent) = pattern.strip_suffix("/*") else {
        let path = root.join(pattern);
        return Ok(if real_folder(&path) && !holds_git(&path) {
            vec![pattern.to_string()]
        } else {
            Vec::new()
        });
    };
    let path = root.join(parent);
    if !real_folder(&path) {
        return Ok(Vec::new());
    }
    let entries =
        fs::read_dir(&path).map_err(|e| format!("cannot list {}: {e}", path.display()))?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", path.display()))?;
        let is_folder = entry.file_type().is_ok_and(|kind| kind.is_dir());
        if is_folder && !holds_git(&entry.path()) {
            found.push(format!("{parent}/{}", entry.file_name().to_string_lossy()));
        }
    }
    Ok(found)
}

#[test]
fn rust_toolchain_toml_at_the_root_is_the_only_toolchain_file() -> Result<(), String> {
    // rustup reads a toolchain file in the folder cargo runs in and in each
    // folder above it: here, the root, each member or excluded folder of the
    // workspace, and the folders between them and the root. No other folder
    // is looked in, a symlink is not followed, and a folder that holds
    // another checkout is not this repository's.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = read("Cargo.toml")?;
    let patterns: Vec<String> = workspace_list(&manifest, "members")
        .into_iter()
        .chain(workspace_list(&manifest, "exclude"))
        .collect();
    assert!(
        patterns.iter().any(|pattern| pattern == "crates/core"),
        "the workspace's members are read from Cargo.toml: {patterns:?}"
    );
    let mut folders = std::collections::BTreeSet::from([String::new()]);
    for pattern in &patterns {
        for folder in workspace_folders(&root, pattern)? {
            let parts: Vec<&str> = folder.split('/').collect();
            for end in 1..=parts.len() {
                folders.insert(parts[..end].join("/"));
            }
        }
    }
    let mut found = Vec::new();
    for folder in &folders {
        for name in ["rust-toolchain", "rust-toolchain.toml"] {
            let file = if folder.is_empty() {
                name.to_string()
            } else {
                format!("{folder}/{name}")
            };
            if fs::symlink_metadata(root.join(&file)).is_ok() {
                found.push(file);
            }
        }
    }
    assert_eq!(
        found,
        ["rust-toolchain.toml"],
        "rustup reads a `rust-toolchain` file, or a `rust-toolchain.toml` in a folder cargo \
         runs in, before the root's: the one toolchain file is rust-toolchain.toml at the root \
         (looked for in {folders:?})"
    );
    Ok(())
}

#[test]
fn the_workspace_lists_are_read_from_their_table() {
    let manifest = "[workspace.lints.rust]\nx = 1\n\n[workspace]\nresolver = \"2\"\n# members = [\"no\"]\nmembers = [\n    \"crates/a\", # one\n    \"crates/b\",\n]\nexclude = [\"tools/*\"]\n\n[workspace.package]\nmembers = [\"no\"]\n";
    assert_eq!(
        workspace_list(manifest, "members"),
        ["crates/a", "crates/b"]
    );
    assert_eq!(workspace_list(manifest, "exclude"), ["tools/*"]);
    assert!(workspace_list(manifest, "default-members").is_empty());
}

#[test]
fn a_missing_file_says_what_it_is_for() {
    let message = read("no-such-file.toml").err().unwrap_or_default();
    assert!(message.contains("no-such-file.toml"), "{message}");
    assert!(message.contains("must exist"), "{message}");
}
