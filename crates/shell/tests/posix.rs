//! POSIX shell lines and what each rule finds in them: deletes and writes
//! beyond the workspace, disks, git work that cannot come back, permissions,
//! root and the system, what runs unseen, nested shells, traps, what a
//! finding says, device paths, macOS paths, and what cannot be read. Which
//! names a wildcard matches is in `posix_wildcards.rs`, protected paths in
//! `protected.rs`, and the everyday lines that stay safe in the front door's
//! `tests/everyday.rs`.
//!
//! The lines and their answers are in `tests/cases/posix.cases`; here are
//! what a finding names as its target, the lines nested past the depth
//! limit, and how a shell is known by its program.

mod common;

use common::{assert_linear, classify, filled, posix, rules};
use milo_guards_shell::{Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("posix");
}

#[test]
fn a_trap_finding_names_its_action_as_written() {
    let paths = posix();
    // A locale-translated action is reported as the whole word.
    let assessment = classify("trap $\"rm -rf ~\" EXIT", Shell::Posix, &paths);
    let [finding] = assessment.findings() else {
        panic!("one finding");
    };
    assert_eq!(finding.target.as_deref(), Some("$\"rm -rf ~\""));
    let assessment = classify("trap 'rm -rf ~' EXIT", Shell::Posix, &paths);
    let [finding] = assessment.findings() else {
        panic!("one finding");
    };
    assert_eq!(finding.target.as_deref(), Some("~"));
    // An expansion in a double-quoted action is a placeholder in the text
    // the action is read from, which a finding never shows: it names the
    // action as written.
    for line in [
        "trap \"rm -rf $d\" EXIT",
        "trap \"rm -rf $d/x\" EXIT",
        "trap \"$x\" EXIT",
        "trap \"echo hi > $f\" EXIT",
        "trap 'a'\"$x\" EXIT",
    ] {
        for finding in classify(line, Shell::Posix, &paths).findings() {
            let target = finding.target.as_deref().unwrap_or_default();
            assert!(!target.contains("__v"), "{line}: {finding:?}");
            assert!(line.contains(target), "{line}: {finding:?}");
        }
    }
    // A trap nested past the depth limit is unreadable, not safe.
    let mut line = "rm -rf ~".to_string();
    for _ in 0..12 {
        line = format!("trap '{}' EXIT", line.replace('\'', "'\\''"));
    }
    assert!(!classify(&line, Shell::Posix, &paths).is_safe());
}

#[test]
fn a_finding_says_what_and_where() {
    let assessment = classify("rm -rf ~ && git push --force", Shell::Posix, &posix());
    let findings = assessment.findings();
    assert_eq!(findings.len(), 2, "{findings:?}");
    assert_eq!(findings[0].rule, Rule::Delete);
    assert_eq!(findings[0].reason, "deletes your home directory");
    assert_eq!(findings[0].target.as_deref(), Some("~"));
    assert_eq!(findings[1].rule, Rule::GitRemote);
    assert_eq!(
        findings[1].reason,
        "rewrites or deletes branches on the remote"
    );

    let sudo = classify("sudo rm -rf /", Shell::Posix, &posix());
    let reasons: Vec<&str> = sudo
        .findings()
        .iter()
        .map(|finding| finding.reason.as_str())
        .collect();
    assert_eq!(reasons, ["runs as root", "deletes the root of the disk"]);
}

#[test]
fn a_line_nested_past_the_depth_limit_is_unreadable() {
    let deep = (0..12).fold("echo hi".to_string(), |inner, _| {
        format!("sh -c {}", shell_quote(&inner))
    });
    assert!(
        rules(&deep, Shell::Posix, &posix()).contains(&Rule::Unreadable),
        "{deep}"
    );
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// `Shell::for_program` reads `$SHELL` or a program path.
#[test]
fn a_shell_is_known_by_its_program() {
    assert_eq!(Shell::for_program("/bin/zsh"), Some(Shell::Posix));
    assert_eq!(Shell::for_program("bash"), Some(Shell::Posix));
    assert_eq!(Shell::for_program("pwsh"), Some(Shell::PowerShell));
    assert_eq!(
        Shell::for_program("C:\\Windows\\System32\\cmd.exe"),
        Some(Shell::Cmd)
    );
    assert_eq!(Shell::for_program("/usr/local/bin/fish"), None);
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn values_only_known_when_they_run_are_read_in_linear_time() {
    // Each value that may split into words is read once: as an output of
    // `dd`, an operand an option's value adds, and an option that destroys
    // or changes a setting.
    let (shell, paths) = (Shell::Posix, posix());
    for (head, part, tail) in [
        ("dd if=a ", "of=$x bs=$b ", ""),
        ("tar -cf x.tar ", "--exclude $e -C $d ", "--remove-files"),
        ("zip -m x.zip ", "-b $t ", "src"),
        ("shred ", "-n $n ", "x"),
        ("mv ", "-S $x ", "a b"),
        ("git push ", "$f ", "origin main"),
        ("docker image prune ", "$f ", ""),
        ("terraform apply ", "$f ", ""),
        ("iptables ", "-s $ip ", ""),
    ] {
        assert_linear(&format!("{head}{part}…"), shell, &paths, |size| {
            format!(
                "{head}{}{tail}",
                filled(part, size, head.len() + tail.len())
            )
        });
    }
}
