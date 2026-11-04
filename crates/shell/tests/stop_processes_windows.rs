//! Stopping processes in PowerShell and cmd. `Stop-Process`, `taskkill`,
//! `tskill`, `wmic`, a method such as `.Kill()` and WMI's `Terminate` stop a
//! process safely only when the guard reads which one for sure: a name that
//! is not the system's, a `Get-Process` listing of those, or an id written
//! out in digits other than 0 and 1. A name, a filter or a listing that picks
//! every process or one the system needs (`explorer`, `svchost`, the
//! compositor, the remote login) is `stop_system`; an id, a variable, another
//! cmdlet's listing, a filter or a `-match` pattern the guard cannot read may
//! be any process and is `stop_unknown`.
//!
//! The lines and their answers are in
//! `tests/cases/stop_processes_windows.cases`; here are the listings nested
//! deep, every form of a `-match` pattern, made from a list of patterns, and
//! the timed test.

mod common;

use common::{assert_linear, at, check, took, windows};
use milo_guards_shell::{classify, Rule, Shell};
use std::time::Duration;

#[test]
fn every_case_holds() {
    common::cases::check("stop_processes_windows");
}

/// `ps || Stop-Process -Id (Get-Process | Stop-Process -Id ×n x )×n`: a
/// listing in the arguments of a `Stop-Process`, `n` deep.
fn listing_chain(n: usize) -> String {
    format!(
        "ps || Stop-Process -Id {}x{}",
        "(Get-Process | Stop-Process -Id ".repeat(n),
        ")".repeat(n)
    )
}

/// A listing nested deep is still found, and one nested deeper than the
/// guard reads is not safe. (The lines with no listing in them are cases.)
#[test]
fn a_nested_listing_is_one_finding_and_a_command_with_none_is_not_one() {
    let windows = windows();
    let line = listing_chain(40);
    let findings = classify(&line, Shell::PowerShell, &windows);
    let stops: Vec<_> = findings
        .findings()
        .iter()
        .filter(|finding| finding.rule == Rule::StopUnknown)
        .collect();
    assert!(!stops.is_empty(), "{line}");
    for line in [
        listing_chain(100),
        format!(
            "Stop-Process -InputObject {}x{}",
            "(Get-Process ".repeat(300),
            ")".repeat(300)
        ),
    ] {
        assert!(
            !classify(&line, Shell::PowerShell, &windows).is_safe(),
            "{} bytes",
            line.len()
        );
    }
}

/// The forms a `-match` pattern is stopped through, one line each.
fn match_lines(pattern: &str) -> Vec<String> {
    vec![
        format!("Get-Process | Where-Object {{ $_.Name -match '{pattern}' }} | Stop-Process"),
        format!("Get-Process | Where-Object Name -match '{pattern}' | Stop-Process"),
        format!("Get-Process | ? {{ $_.ProcessName -match '{pattern}' }} | kill"),
        format!("Get-Process | Where-Object {{ $_.Name -match '{pattern}' }} | % Kill"),
        format!(
            "Get-Process | Where-Object {{ $_.Name -match '{pattern}' }} | ForEach-Object {{ $_.Kill() }}"
        ),
    ]
}

/// Every form of each pattern breaks `rule`.
fn all_risky(patterns: &[&str], rule: Rule) {
    let lines: Vec<String> = patterns.iter().flat_map(|p| match_lines(p)).collect();
    let risky: Vec<(&str, Rule)> = lines.iter().map(|line| (line.as_str(), rule)).collect();
    check(Shell::PowerShell, &windows(), &[], &risky);
}

#[test]
fn every_form_of_a_dotnet_match_pattern_is_judged_alike() {
    all_risky(
        &[
            // A process name never holds a folder, so a `/` in a .NET
            // expression ends nothing; the quantifier after it still applies
            // to what it follows.
            "/?explorer",
            "/*explorer",
            "exp/?lorer",
            "svc/*host",
            "/{0}lsass",
            "sm/*ss",
            "smss/{0,}",
            // .NET accepts `^*x` and `$?x`: the anchor may be absent, so they
            // match like `x`.
            "^*explorer",
            "^?explorer",
            "^+explorer",
            "^{0,1}svchost",
            "${0}explorer",
            "$?explorer",
            "explorer$*",
            "lsass$?",
        ],
        Rule::StopSystem,
    );
    // `[.`, `[=` and `[:` that does not close with `word:]` are a plain `[`
    // to .NET, which closes the set at the next `]`; `[a-z-[0]]` is a set
    // minus another. The POSIX reading skips or splits them differently, so
    // the guard cannot say which processes they pick.
    all_risky(
        &[
            "zz[[.]|.|.]]",
            "zz[[=]|.|=]]",
            "zz[[:]|.|:]]",
            "q[[:]|^|:]]",
            "e[a-z-[0]]",
            "s[a-z-[0-9]]",
            "ex[a-z-[q]]+",
            "sm[a-z-[x]]s",
            "w[a-z-[x]]nlogon",
            "w[^0-9-[x]]nlogon",
        ],
        Rule::StopUnknown,
    );
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_process_rules_read_long_patterns_and_pipelines_in_linear_time() {
    // Each line, the shell, the head, the part repeated, the tail and the
    // count a line of 64 KB holds (`at`): at 16 KB a quarter of them, which
    // must take about a quarter of the time, not a sixteenth. In a long
    // pipeline most of the time is the parser's, not the rules'.
    let windows = windows();
    for (shell, head, part, tail, count) in [
        (
            Shell::PowerShell,
            "Stop-Process -Name '",
            "*",
            "zz'",
            60_000,
        ),
        (Shell::Cmd, "taskkill /IM ", "*?", "q", 30_000),
        (Shell::PowerShell, "Stop-Process -Name '", "[", "'", 60_000),
        (
            Shell::PowerShell,
            "Stop-Process -Name '",
            "[a]",
            "'",
            20_000,
        ),
        (Shell::PowerShell, "gps", "|kill", "", 12_000),
        (
            Shell::PowerShell,
            "Get-Process",
            " | Stop-Process",
            "",
            4_000,
        ),
    ] {
        let line = |size| format!("{head}{}{tail}", part.repeat(at(count, size)));
        assert!(line(64 * 1024).len() <= 64 * 1024, "{head}{part}");
        assert_linear(&format!("{head}{part}…{tail}"), shell, &windows, line);
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn the_process_rules_read_few_wildcards_and_nested_listings_quickly() {
    // A few wildcards, as many as made a matcher that backtracks take
    // seconds, and listings written inside the arguments of a
    // `Stop-Process`, nested: each is read once, and nothing below another
    // command is read again. Their time is set by a count or a depth, not by
    // the length, so each is held to a fixed bound, which an optimized build
    // here takes a fiftieth of or less. Most of the time of a deep listing is
    // the parser's, so its bound is looser.
    let windows = windows();
    let slow = Duration::from_millis(500);
    let wildcards = [
        (
            Shell::PowerShell,
            format!("Stop-Process -Name '{}zz'", "*".repeat(26)),
        ),
        (Shell::Cmd, format!("taskkill /IM {}q", "*".repeat(30))),
    ];
    let listings = [
        (Shell::PowerShell, listing_chain(50)),
        (Shell::PowerShell, listing_chain(300)),
        (Shell::PowerShell, listing_chain(1_600)),
        (
            Shell::PowerShell,
            format!(
                "Stop-Process -InputObject {}x{}",
                "(Get-Process ".repeat(2_000),
                ")".repeat(2_000)
            ),
        ),
        (
            Shell::PowerShell,
            format!(
                "Stop-Process -InputObject {}x{}",
                "(Get-Process | ".repeat(1_600),
                ")".repeat(1_600)
            ),
        ),
    ];
    let limits = wildcards
        .iter()
        .map(|row| (row, slow))
        .chain(listings.iter().map(|row| (row, slow * 8)));
    for ((shell, line), limit) in limits {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(line, *shell, &windows);
        assert!(took < limit, "{shell:?} {} bytes took {took:?}", line.len());
    }
}
