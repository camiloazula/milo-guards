//! The Rust version is named in four places, and they must agree: the
//! toolchain the repository pins, the oldest the crates declare they
//! build with, and the two ways CI names the one it installs: the
//! `RUSTUP_TOOLCHAIN` variable and the `toolchain:` input of each Rust
//! install step.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

use std::fs;
use std::path::Path;

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

#[test]
fn the_pinned_toolchain_the_minimum_and_ci_agree() -> Result<(), String> {
    let toolchain = value(
        &read("rust-toolchain.toml")?,
        "channel",
        "rust-toolchain.toml",
    )?;
    let minimum = value(&read("Cargo.toml")?, "rust-version", "Cargo.toml")?;
    let workflow = read(".github/workflows/ci.yml")?;
    let ci = value(&workflow, "RUSTUP_TOOLCHAIN", ".github/workflows/ci.yml")?;

    assert_eq!(
        toolchain.split('.').count(),
        3,
        "rust-toolchain.toml pins `{toolchain}`: pin a full version (major.minor.patch), not a moving channel"
    );
    assert_eq!(
        major_minor(&toolchain),
        minimum,
        "rust-version in Cargo.toml (`{minimum}`) must be the major.minor of the pinned toolchain (`{toolchain}`)"
    );
    assert_eq!(
        ci, toolchain,
        "CI installs `{ci}` (RUSTUP_TOOLCHAIN in ci.yml) but rust-toolchain.toml pins `{toolchain}`"
    );
    Ok(())
}

#[test]
fn every_rust_install_step_in_ci_installs_the_pinned_toolchain() -> Result<(), String> {
    let toolchain = value(
        &read("rust-toolchain.toml")?,
        "channel",
        "rust-toolchain.toml",
    )?;
    let workflow = read(".github/workflows/ci.yml")?;
    let inputs = values(&workflow, "toolchain");
    assert_eq!(
        inputs.len(),
        install_steps(&workflow),
        "every Rust install step in ci.yml needs a `toolchain:` input, and only those do: found {inputs:?}"
    );
    assert!(!inputs.is_empty(), "ci.yml installs no Rust");
    for input in inputs {
        assert_eq!(
            input, toolchain,
            "a `toolchain:` input in ci.yml installs `{input}` but rust-toolchain.toml pins `{toolchain}`"
        );
    }
    Ok(())
}

/// How many steps of `workflow` install Rust.
fn install_steps(workflow: &str) -> usize {
    workflow
        .lines()
        .filter(|line| line.contains("uses: dtolnay/rust-toolchain@"))
        .count()
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
    Ok(())
}

#[test]
fn a_missing_file_says_what_it_is_for() {
    let message = read("no-such-file.toml").err().unwrap_or_default();
    assert!(message.contains("no-such-file.toml"), "{message}");
    assert!(message.contains("must exist"), "{message}");
}
