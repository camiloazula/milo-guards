//! The time the shell guard takes over the worst lines it is given. These
//! are timed, so they run one at a time (`SERIAL`), and in a binary of their
//! own, after the heavy tests of `limits.rs`: a clock read while other tests
//! hammer the cores measures the machine, not the guard.

mod common;
mod noise;

use std::sync::{Mutex, MutexGuard, PoisonError};

use common::{disagreements, posix};
use milo_guards_shell::{classify, effect, Rule, Shell};
use noise::{lossy, paths_for, Lcg, SHELLS, WIDE_PIECES};

/// Held for the whole of a timed test, so no two are timed at once.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn wide_random_lines_never_panic_and_stay_quick() {
    let _serial = serial();
    // The time a turn can wait for one line, with room for the debug build
    // `just verify` runs: lines this short take microseconds.
    const WORST: std::time::Duration = std::time::Duration::from_millis(500);
    let mut random = Lcg(0x5eed);
    let mut worst = (std::time::Duration::ZERO, String::new());
    let (mut unreadable, mut lines) = (0, 0);
    for number in 0..4_500 {
        let length = random.next() % 32;
        let pieces: Vec<&str> = (0..length)
            .map(|_| WIDE_PIECES[random.next() % WIDE_PIECES.len()])
            .collect();
        let mut line = pieces.join(if random.next().is_multiple_of(3) {
            ""
        } else {
            " "
        });
        // A third of the lines are cut, or have stray bytes joined on.
        if number % 3 == 0 {
            line = lossy(&line, &mut random);
        }
        for shell in SHELLS {
            let paths = paths_for(shell);
            let started = std::time::Instant::now();
            let assessment = classify(&line, shell, &paths);
            let took = started.elapsed();
            if took > worst.0 {
                worst = (took, line.clone());
            }
            let _ = effect(&line, shell, &paths);
            let wrong = disagreements(shell, &paths, [line.as_str()]);
            assert!(wrong.is_empty(), "{shell:?}: {wrong:?}");
            lines += 1;
            unreadable += usize::from(
                assessment
                    .findings()
                    .iter()
                    .any(|finding| finding.rule == Rule::Unreadable),
            );
        }
    }
    assert!(worst.0 < WORST, "{:?} for {:?}", worst.0, worst.1);
    // The set really is noise: most of it cannot be read.
    assert!(unreadable * 3 > lines, "only {unreadable} of {lines}");
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch an explosion"
)]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn finds_in_finds_are_read_in_time_whatever_their_arguments_weigh() {
    let _serial = serial();
    // The work of `find -exec` is the bytes it builds, not the arguments it
    // hands on: a few arguments of many `{}` each, or one big one, made the
    // same blow-up through a budget counted in arguments. The bound is for
    // the debug build `just verify` runs.
    const LIMIT: std::time::Duration = std::time::Duration::from_secs(2);
    let levels = |places: &str, each: usize, last: &str| {
        let mut line = format!("find {places}");
        for _ in 0..each {
            line += "-exec find . . . . . . . . ";
        }
        line + last
    };
    let lines = [
        // One place of a thousand bytes, four levels of eight places, and an
        // argument of a thousand `{}`: a megabyte for each of 4,096 runs.
        (
            "levels of long arguments",
            levels(
                &format!("{} ", "a".repeat(1_000)),
                4,
                &format!("-exec echo {} \\;", "{}".repeat(1_000)),
            ),
        ),
        // One place of 25,000 bytes and one argument of 17,000 `{}`: 425 MB.
        (
            "one huge argument",
            format!(
                "find {} -exec echo {} \\;",
                "a".repeat(25_000),
                "{}".repeat(17_000)
            ),
        ),
        // The same, with twelve levels in front.
        (
            "one huge argument, deeper",
            format!(
                "find {} {}-exec echo {} \\;",
                "a".repeat(25_000),
                "-exec find . ".repeat(12),
                "{}".repeat(17_000)
            ),
        ),
        // Eight places and seven levels, then a script of 55 KB.
        (
            "a script at the bottom",
            format!(
                "find . . . . . . . . {}-exec sh -c 'echo {}' \\;",
                "-exec find . . . . . . . . ".repeat(6),
                "a".repeat(55_000)
            ),
        ),
    ];
    for (what, line) in &lines {
        assert!(line.len() <= 64 * 1024, "{what}: {}", line.len());
        let started = std::time::Instant::now();
        let assessment = classify(line, Shell::Posix, &posix());
        let took = started.elapsed();
        assert!(took < LIMIT, "{what}: {took:?}");
        assert!(
            assessment
                .findings()
                .iter()
                .any(|finding| finding.rule == Rule::Unreadable),
            "{what}"
        );
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_line_at_the_length_limit_is_read_in_time() {
    let _serial = serial();
    // Longest line there is, in the shapes a real or a broken line takes.
    // The bound is for the debug build `just verify` runs; a release build
    // takes a tenth of it or less.
    const LIMIT: std::time::Duration = std::time::Duration::from_secs(2);
    let fit = |unit: &str, head: &str, tail: &str| {
        let count = (64 * 1024 - head.len() - tail.len()) / unit.len();
        format!("{head}{}{tail}", unit.repeat(count))
    };
    let nested = |open: &str| {
        let count = (64 * 1024 - 4) / (open.len() + 1);
        format!("{}echo{}", open.repeat(count), ")".repeat(count))
    };
    // The separator that ends a command in `shell`: `;` is one in POSIX shell
    // and PowerShell, and a space in cmd, where `&` is.
    let chain = |shell: Shell| match shell {
        Shell::Cmd => "echo x & ",
        _ => "echo x; ",
    };
    let shapes = |shell: Shell| {
        [
            ("a chain", fit(chain(shell), "", "")),
            ("a pipeline", fit("echo x | ", "", "cat")),
            ("a conjunction", fit("echo x && ", "", "echo")),
            ("one word", fit("a", "echo ", "")),
            ("a quote left open", fit("a", "echo '", "")),
            ("a string", fit("a", "echo \"", "\"")),
            ("redirects", fit("echo >a; ", "", "")),
            ("brackets", fit("[", "echo ", "")),
            ("substitutions left open", fit("$(", "echo ", "")),
            ("parentheses nested", nested("(")),
            ("substitutions nested", nested("$(")),
            ("blocks left open", fit("if x; then ", "", "")),
            ("loops left open", fit("for i in a b; do ", "", "")),
            ("here-documents left open", fit("cat <<EOF; ", "", "")),
        ]
    };
    let mut slowest = (std::time::Duration::ZERO, String::new());
    for shell in SHELLS {
        let paths = paths_for(shell);
        for (what, line) in &shapes(shell) {
            assert!(line.len() <= 64 * 1024, "{what}: {}", line.len());
            let started = std::time::Instant::now();
            let _ = classify(line, shell, &paths);
            let _ = effect(line, shell, &paths);
            let took = started.elapsed();
            if took > slowest.0 {
                slowest = (took, format!("{what} in {shell:?}"));
            }
        }
    }
    assert!(slowest.0 < LIMIT, "{:?} for {}", slowest.0, slowest.1);
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn cmd_commands_read_again_are_read_in_time() {
    let _serial = serial();
    // cmd's `ver && if …`, `i^f`, `f^or`, `ca^ll` and `call call` are each
    // read again as a statement of their own, and each holds the rest of the
    // line: repeated, the line would be read once for each. The bound is for
    // the debug build `just verify` runs.
    const LIMIT: std::time::Duration = std::time::Duration::from_secs(2);
    let fit = |unit: &str| {
        let tail = "rd /s /q C:\\";
        let count = (64 * 1024 - tail.len()) / unit.len();
        format!("{}{tail}", unit.repeat(count))
    };
    let nested = |open: &str| {
        let count = 390;
        format!("{}rd /s /q C:\\{}", open.repeat(count), ")".repeat(count))
    };
    let lines = [
        fit("ver && if a "),
        fit("i^f a "),
        fit("f^or %%i in (a) do "),
        fit("ca^ll "),
        fit("call "),
        nested("ver && if a ("),
        nested("i^f a ("),
    ];
    let paths = paths_for(Shell::Cmd);
    for line in &lines {
        let started = std::time::Instant::now();
        let assessment = classify(line, Shell::Cmd, &paths);
        let took = started.elapsed();
        assert!(took < LIMIT, "{took:?} for {:?}", &line[..40]);
        assert!(!assessment.is_safe(), "{:?}", &line[..40]);
    }
}
