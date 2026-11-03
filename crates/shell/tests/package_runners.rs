//! A package runner (`npx`, `npm exec`, `pnpm`, `pnpx`, `yarn`, `bunx`,
//! `bun`, `deno`, `dx`, `uv`, `uvx`, `pipx`, `corepack`, and the runners of
//! a project's environment: `poetry`, `pdm`, `hatch`, `conda`, `pixi`,
//! `rye`, `volta`, `mise`) runs the program it names, so
//! that program is judged, past every option of the runner that takes a
//! value; `bun` and `deno` run code given inline or read from their input; a
//! script a runner runs may be one the same line writes; and on Windows the
//! script given to npm or pnpm runs in cmd.
//!
//! The lines and their answers are in `tests/cases/package_runners.cases`;
//! here are the lines made from each runner's options that take a value, and
//! from runs of short options of growing length.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("package_runners");
}

/// Rows `<runner> <option> v <program line>`, one per option.
fn with_each(runner: &str, options: &[&str], line: &str, rule: Rule) -> Vec<(String, Rule)> {
    options
        .iter()
        .map(|option| (format!("{runner} {option} v {line}"), rule))
        .collect()
}

/// The risky rows as the `check` table takes them.
fn as_rows(rows: &[(String, Rule)]) -> Vec<(&str, Rule)> {
    rows.iter()
        .map(|(line, rule)| (line.as_str(), *rule))
        .collect()
}

/// Every setting of npm's config that is not a boolean, from its definitions,
/// and the shorthands that point at them.
const NPM_VALUE_OPTIONS: [&str; 56] = [
    "--access",
    "--auth-type",
    "--ca",
    "--cert",
    "--key",
    "--cidr",
    "--cpu",
    "--os",
    "--libc",
    "--depth",
    "--diff",
    "--diff-dst-prefix",
    "--diff-src-prefix",
    "--diff-unified",
    "--editor",
    "--git",
    "--heading",
    "--init-author-name",
    "--init-author-email",
    "--init-author-url",
    "--init-license",
    "--init-module",
    "--init-type",
    "--init-version",
    "--local-address",
    "--lockfile-version",
    "--logs-dir",
    "--logs-max",
    "--message",
    "-m",
    "--node-gyp",
    "--pack-destination",
    "--preid",
    "--replace-registry-host",
    "--save-prefix",
    "--sbom-format",
    "--sbom-type",
    "--searchexclude",
    "--searchlimit",
    "--searchopts",
    "--searchstaleness",
    "--tag-version-prefix",
    "--umask",
    "--user-agent",
    "--viewer",
    "--which",
    "--expect-result-count",
    "--min-release-age",
    "--allow-git",
    "--allow-file",
    "--allow-remote",
    "--allow-directory",
    "-L",
    "--registry",
    "--prefix",
    "-C",
];

/// A row for every option of each runner that takes a value, with a value
/// and then a delete tool (or inline code) after it.
fn value_option_rows() -> Vec<(String, Rule)> {
    let mut risky = Vec::new();
    // npm and npx: every setting that takes a value.
    for runner in ["npx", "npm exec", "npm x"] {
        risky.extend(with_each(
            runner,
            &NPM_VALUE_OPTIONS,
            "rimraf ~",
            Rule::Delete,
        ));
    }
    // pipx.
    for option in [
        "-i",
        "--index-url",
        "--fetch-python",
        "--backend",
        "--cooldown",
        "--python-args",
        "--with",
        "--spec",
        "--python",
        "--pip-args",
    ] {
        risky.push((format!("pipx run {option} x rimraf ~"), Rule::Delete));
    }
    // pnpm's own string and number settings.
    for option in [
        "--store-dir",
        "--virtual-store-dir",
        "--modules-dir",
        "--lockfile-dir",
        "--cache-dir",
        "--global-dir",
        "--state-dir",
        "--workspace-concurrency",
        "--network-concurrency",
        "--child-concurrency",
        "--test-pattern",
        "--changed-files-ignore-pattern",
        "--node-linker",
        "--package-import-method",
        "--resolution-mode",
        // pnpm reads npm's settings too.
        "--user-agent",
        "--fetch-retries",
        "--otp",
    ] {
        risky.push((format!("pnpm {option} x exec rimraf ~"), Rule::Delete));
        risky.push((format!("pnpm exec {option} x rimraf ~"), Rule::Delete));
        risky.push((format!("pnpm dlx {option} x rimraf ~"), Rule::Delete));
    }
    // yarn's global options.
    for option in [
        "--cache-folder",
        "--modules-folder",
        "--global-folder",
        "--link-folder",
        "--preferred-cache-folder",
        "--mutex",
        "--network-timeout",
        "--network-concurrency",
        "--registry",
        "--proxy",
        "--https-proxy",
        "--otp",
        "--use-yarnrc",
        "--cwd",
    ] {
        risky.push((format!("yarn {option} x exec rimraf ~"), Rule::Delete));
        risky.push((format!("yarn {option} x dlx rimraf ~"), Rule::Delete));
        risky.push((format!("yarn {option} x exec 'rm -rf ~'"), Rule::Delete));
    }
    // deno.
    for option in [
        "--preload",
        "--import",
        "--require",
        "--conditions",
        "--min-dep-age",
        "--minimum-dependency-age",
        "--cpu-prof-dir",
        "--cpu-prof-name",
        "--cpu-prof-interval",
        "--inspect-publish-uid",
    ] {
        risky.push((format!("deno run {option} p npm:rimraf ~"), Rule::Delete));
        risky.push((format!("deno {option} p npm:rimraf ~"), Rule::Delete));
        risky.push((format!("deno {option} p eval 'x'"), Rule::Unknown));
    }
    // The hidden options uv still takes a value for.
    for option in [
        "--python-preference",
        "--python-fetch",
        "--max-recursion-depth",
        "--preview-feature",
        "--preview-features",
        "--trusted-host",
    ] {
        risky.push((format!("uv run {option} x rm -rf ~"), Rule::Delete));
        risky.push((format!("uv tool run {option} x rimraf ~"), Rule::Delete));
        risky.push((format!("uvx {option} x rimraf ~"), Rule::Delete));
    }
    risky
}

/// A runner's option that takes a value takes the word after it, however
/// the option is spelt: every such option of each runner, one line each.
/// (The options spelt short, run together or not ASCII, and the words that
/// are no value, are cases.)
#[test]
fn a_package_runner_skips_every_option_that_takes_a_value() {
    let generated = value_option_rows();
    check(Shell::Posix, &posix(), &[], &as_rows(&generated));
}

#[test]
fn a_run_of_short_options_in_front_of_the_program_is_read_to_its_end() {
    // A bundle of `n` letters takes `n` steps: the limit grows with it.
    for letters in [63, 64, 65, 70, 200, 1000] {
        let bundle = "y".repeat(letters);
        let risky: Vec<(String, Rule)> = [
            format!("npx -{bundle} rimraf ~"),
            format!("npm exec -{bundle} rimraf ~"),
            format!("npm x -{bundle} rimraf ~"),
            format!("npx -{bundle}c 'rm -rf ~'"),
            format!("npm -{bundle}c 'rm -rf ~' exec"),
        ]
        .into_iter()
        .map(|line| (line, Rule::Delete))
        .collect();
        check(
            Shell::Posix,
            &posix(),
            &[
                &format!("npx -{bundle} prettier --check ."),
                &format!("npm exec -{bundle} prettier --check ."),
            ],
            &as_rows(&risky),
        );
    }
}
