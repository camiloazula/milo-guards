//! Whatever the text, classifying it ends, never panics, and never calls
//! a line it could not read safe; and the same for `effect`, which never
//! calls such a line reads-only.

mod common;

use common::{disagreements, posix, windows};
use milo_guards_shell::{classify, effect, Effect, Rule, Shell};

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
            // The same noise through `effect`, which must also agree with
            // `classify` on every line: one it flags does not only read.
            let _ = effect(&line, shell, &paths);
            let wrong = disagreements(shell, &paths, [line.as_str()]);
            assert!(wrong.is_empty(), "{shell:?}: {wrong:?}");
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
    assert_eq!(effect(&long, Shell::Posix, &posix()), Effect::Unknown);
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
        // `effect` reads the same tree. Past the depth limit (400) is
        // enough for it, and quicker than 30,000 levels: cmd's grammar alone
        // takes seconds to parse those in a debug build.
        let shallow = open.repeat(2_000) + "echo" + &close.repeat(2_000);
        assert_eq!(
            effect(&shallow, shell, &paths),
            Effect::Unknown,
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
    assert_eq!(effect(&line, Shell::Posix, &posix()), Effect::Unknown);
    // A few reads of a short script are fine.
    assert!(classify("eval eval eval : hi", Shell::Posix, &posix()).is_safe());
}

// What follows widens the random lines, says what each may be called, times
// the longest, and pins the limits.

/// More syntax than `PIECES`: quotes and substitutions left open, here-
/// documents with no end, here-strings, control and Unicode edge characters,
/// PowerShell and cmd metacharacters, the keywords that open a block, and
/// a few plain words.
const WIDE_PIECES: [&str; 76] = [
    // Left open.
    "'",
    "\"",
    "`",
    "$(",
    "$((",
    "${",
    "$'",
    "@(",
    "@{",
    "<(",
    ">(",
    "(",
    "((",
    "{",
    "[",
    "[[",
    // Closing with nothing to close.
    ")",
    "))",
    "}",
    "]",
    "]]",
    ";;",
    "esac",
    "fi",
    "done",
    "'@",
    "\"@",
    // Here-documents and here-strings, with no end.
    "<<EOF",
    "<<-EOF",
    "<<'EOF'",
    "<<<",
    "@'",
    "@\"",
    "<#",
    // Blocks that open.
    "if",
    "then",
    "case x in",
    "for x in",
    "while",
    "function f {",
    "f() {",
    "ForEach-Object {",
    "|%",
    // Operators, alone or doubled.
    "|",
    "||",
    "&",
    "&&",
    ";",
    ">",
    ">>",
    "<",
    "2>&1",
    "\n",
    "\r\n",
    // The edges of text.
    "\0",
    "\\",
    "\u{feff}",
    "\u{fffd}",
    "\u{2028}",
    "é",
    // Variables and escapes of the other shells.
    "%X%",
    "%~dp0",
    "!X!",
    "^",
    "^&",
    "$_",
    "$env:X",
    // What they run.
    "rm -rf /",
    "Remove-Item -Recurse",
    "cmd /c",
    "powershell -c",
    "sh -c",
    "Invoke-Expression",
    "echo",
    "ls",
    "pwd",
];

const SHELLS: [Shell; 3] = [Shell::Posix, Shell::PowerShell, Shell::Cmd];

fn paths_for(shell: Shell) -> milo_guards_shell::Paths {
    if shell == Shell::Posix {
        posix()
    } else {
        windows()
    }
}

/// A line cut where it may split a character, with bytes no text holds
/// joined on, read back the way `String::from_utf8_lossy` does.
fn lossy(line: &str, random: &mut Lcg) -> String {
    let mut bytes = line.as_bytes().to_vec();
    if !bytes.is_empty() && random.next().is_multiple_of(2) {
        bytes.truncate(random.next() % bytes.len());
    }
    for _ in 0..random.next() % 3 {
        bytes.push([0xff, 0xfe, 0xc3, 0xe2, 0x80, 0xf0, 0x00][random.next() % 7]);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a stall"
)]
fn wide_random_lines_never_panic_and_stay_quick() {
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

/// How a delete is written in `shell`.
fn delete_in(shell: Shell) -> &'static str {
    match shell {
        Shell::PowerShell => "Remove-Item -Recurse -Force C:\\",
        Shell::Cmd => "rd /s /q C:\\",
        _ => "rm -rf /",
    }
}

#[test]
fn a_delete_among_plain_words_and_separators_is_never_safe() {
    // A line of plain words, separators and one delete: nothing in it can
    // make the delete inert (no quote, no comment, no here-document), so a
    // safe verdict is a false one, whatever else the line holds.
    const WORDS: [&str; 7] = ["echo", "ls", "pwd", ":", "é", "\u{fffd}", "~"];
    // What ends a command in each shell: `;` is a separator in POSIX shell
    // and PowerShell, and a space in cmd.
    let separators = |shell: Shell| -> Vec<&'static str> {
        let mut all = vec!["\n", "\r\n", "&&", "||", "|", " & "];
        if shell != Shell::Cmd {
            all.push(";");
        }
        all
    };
    let mut random = Lcg(11);
    let mut wrong = Vec::new();
    for _ in 0..3_000 {
        for shell in SHELLS {
            let separators = separators(shell);
            let before = random.next() % 4;
            let after = random.next() % 4;
            let mut line = String::new();
            for _ in 0..before {
                for _ in 0..=random.next() % 3 {
                    line += WORDS[random.next() % WORDS.len()];
                    line += " ";
                }
                line += separators[random.next() % separators.len()];
                line += " ";
            }
            line += delete_in(shell);
            for _ in 0..after {
                line += " ";
                line += separators[random.next() % separators.len()];
                line += " ";
                line += WORDS[random.next() % WORDS.len()];
            }
            if classify(&line, shell, &paths_for(shell)).is_safe() {
                wrong.push(format!("{shell:?}: {line:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "called safe:\n{}", wrong.join("\n"));
}

/// What `shell` reads as a plain word, where another shell reads syntax: the
/// pieces an unfinished line may end in that are not unfinished there. cmd
/// has no single quotes, backticks, `$(`, `${` or braces; PowerShell's grammar
/// reads a `<<` as a plain word (PowerShell itself refuses the line, so
/// nothing runs). The list is kept apart from the guard, so a safe
/// verdict for a line that ends in one of these is not mistaken for a false
/// one.
fn literal_in(shell: Shell) -> &'static [&'static str] {
    match shell {
        Shell::PowerShell => &["<<EOF", "<<-EOF", "<<'EOF'"],
        Shell::Cmd => &[
            "'", "`", "$(", "$((", "${", "$'", "(", "((", "<<EOF", "<<-EOF", "<<'EOF'",
        ],
        _ => &[],
    }
}

#[test]
fn a_line_left_open_is_risky_unless_its_shell_reads_the_end_as_plain() {
    // Plain words, then a quote, a substitution, a bracket or a here-
    // document left open (or an operator with nothing after it), then more
    // plain words: the shell has not been given a whole line.
    const WORDS: [&str; 5] = ["echo", "ls", "pwd", "é", "~"];
    const OPEN: [&str; 17] = [
        "'", "\"", "`", "$(", "$((", "${", "$'", "(", "((", "<<EOF", "<<-EOF", "<<'EOF'", "\0",
        "|", "&&", "||", ">",
    ];
    let mut random = Lcg(23);
    let mut wrong = Vec::new();
    for _ in 0..1_500 {
        let open = OPEN[random.next() % OPEN.len()];
        let mut line = String::new();
        for _ in 0..=random.next() % 3 {
            line += WORDS[random.next() % WORDS.len()];
            line += " ";
        }
        line += open;
        // An operator ends the line; the others may be followed by words.
        if !matches!(open, "|" | "&&" | "||" | ">") {
            for _ in 0..random.next() % 3 {
                line += " ";
                line += WORDS[random.next() % WORDS.len()];
            }
        }
        for shell in SHELLS {
            if !literal_in(shell).contains(&open)
                && classify(&line, shell, &paths_for(shell)).is_safe()
            {
                wrong.push(format!("{shell:?}: {line:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "called safe:\n{}", wrong.join("\n"));
}

#[test]
fn a_line_left_open_or_broken_is_risky() {
    let everywhere = [
        "echo \"abc",
        "{ echo",
        "[[ x",
        "echo ||",
        "echo &&",
        "echo |",
        "|",
        "&&",
        "echo \0",
        "echo >",
        "echo <",
        "if x",
        "for x in",
        "echo 'a\nrm -rf /",
        "cat <<EOF\nrm -rf /",
    ];
    // cmd has no `'`, backtick, `$(` or `${`: they are plain words there.
    let posix_and_powershell = [
        "echo 'abc",
        "echo $(echo",
        "echo `ls",
        "echo ${x",
        "echo (",
        "echo )",
        "echo $(",
        "echo $((1",
    ];
    let posix_only = [
        "echo \\",
        "case x",
        ";",
        "echo <<EOF",
        "echo x <<'EOF'\nrm -rf /",
    ];
    let mut wrong = Vec::new();
    for (shell, lines) in [
        (
            Shell::Posix,
            [&everywhere[..], &posix_and_powershell, &posix_only].concat(),
        ),
        (
            Shell::PowerShell,
            [&everywhere[..], &posix_and_powershell].concat(),
        ),
        (Shell::Cmd, everywhere.to_vec()),
    ] {
        for line in lines {
            if classify(line, shell, &paths_for(shell)).is_safe() {
                wrong.push(format!("{shell:?}: {line:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "called safe:\n{}", wrong.join("\n"));
    // And the lines a shell reads as plain words are safe there: the lists
    // above are what the grammars say, not a guess.
    for (shell, line) in [
        (Shell::Cmd, "echo 'abc"),
        (Shell::Cmd, "echo `ls"),
        (Shell::Cmd, "echo $(echo"),
        (Shell::Cmd, "echo ${x"),
        (Shell::Cmd, "echo ("),
        (Shell::PowerShell, "echo <<EOF"),
        (Shell::PowerShell, "echo \\"),
        (Shell::Posix, "echo }"),
        (Shell::Posix, "echo x <<'EOF'\nrm -rf /\nEOF"),
    ] {
        assert!(
            classify(line, shell, &paths_for(shell)).is_safe(),
            "{shell:?}: {line:?}"
        );
    }
}

/// The largest `n` in `1..limit` that `reads` accepts, found by halving the
/// range, and checked from both sides: `reads` takes `1` and not `limit`,
/// and takes the edge but not one past it.
fn edge(limit: usize, reads: impl Fn(usize) -> bool) -> usize {
    assert!(reads(1), "even 1 is not read");
    assert!(!reads(limit), "{limit} is read: the limit is further off");
    let (mut low, mut high) = (1, limit);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if reads(middle) {
            low = middle;
        } else {
            high = middle;
        }
    }
    assert!(reads(low) && !reads(low + 1));
    low
}

fn unreadable(line: &str, shell: Shell) -> bool {
    let paths = if shell == Shell::Posix {
        posix()
    } else {
        windows()
    };
    classify(line, shell, &paths)
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable)
}

/// Whether `line` is unreadable for the reason `why` names (a part of the
/// reason the finding gives): a limit is pinned by its own reason, so the
/// line need not read once the limit is not in the way.
fn stopped_by(line: &str, shell: Shell, why: &str) -> bool {
    classify(line, shell, &paths_for(shell))
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable && finding.reason.contains(why))
}

#[test]
fn the_longest_line_that_reads_is_the_limit() {
    // `MAX_LEN` in `unit.rs`: a line of 64 KiB reads, a byte more does not.
    for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
        let found = edge(70_000, |n| {
            !unreadable(&format!("echo {}", "a".repeat(n.saturating_sub(5))), shell)
        });
        assert_eq!(found, 64 * 1024, "{shell:?}");
    }
}

#[test]
fn the_deepest_nesting_that_reads_is_the_limit() {
    // `MAX_TREE_DEPTH` in `unit.rs` is 400 levels of the parse tree; how many
    // brackets that is depends on how many levels the grammar gives each.
    // The edges are found by measuring and then held: a change to the limit,
    // or to how deep a grammar nests, moves one and fails here.
    for (shell, open, close, expected) in [
        (Shell::Posix, "(", ")", 400),
        (Shell::Posix, "$(", ")", 132),
        (Shell::Posix, "((", "))", 200),
        (Shell::Posix, "{ ", "; }", 397),
        (Shell::PowerShell, "(", ")", 32),
        (Shell::PowerShell, "$(", ")", 30),
        (Shell::PowerShell, "@(", ")", 30),
        (Shell::PowerShell, "{ ", " }", 26),
        (Shell::Cmd, "(", ")", 398),
    ] {
        let found = edge(1_000, |n| {
            !unreadable(&(open.repeat(n) + "echo" + &close.repeat(n)), shell)
        });
        assert_eq!(found, expected, "{shell:?} {open}");
    }
}

/// `text` as the script of `sh -c "…"`, with its backslashes and double
/// quotes escaped.
fn shell_around(text: &str) -> String {
    format!(
        "sh -c \"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

/// Whether `line`, which hides `rm -rf /` at its centre, is read as far as
/// the delete: it is when the line is risky as a delete and not unreadable.
fn reads_the_delete(line: &str) -> bool {
    let assessment = classify(line, Shell::Posix, &posix());
    let rules: Vec<Rule> = assessment
        .findings()
        .iter()
        .map(|finding| finding.rule)
        .collect();
    rules.contains(&Rule::Delete) && !rules.contains(&Rule::Unreadable)
}

#[test]
fn the_most_shells_in_shells_that_read_is_the_limit() {
    // `MAX_DEPTH` in `unit.rs`: eight shells started inside shells read, the
    // ninth is too deep.
    let found = edge(12, |n| {
        let mut line = "rm -rf /".to_string();
        for _ in 0..n {
            line = shell_around(&line);
        }
        reads_the_delete(&line)
    });
    // `edge` counts from one shell; the line with none is the plain delete.
    assert!(reads_the_delete("rm -rf /"));
    assert_eq!(found, 8);
}

#[test]
fn the_most_here_documents_started_on_a_line_that_read_is_the_limit() {
    // `MAX_HEREDOCS` in `unit.rs`: the bash grammar holds every here-document
    // started on a line until the line ends, and takes time that grows with
    // the square of how many, so a POSIX script is counted before it is
    // parsed. The edge is found by the reason the limit gives.
    let why = "too many here-documents";
    let found = edge(2_000, |n| {
        !stopped_by(&"cat <<A; ".repeat(n), Shell::Posix, why)
    });
    assert_eq!(found, 256);
    // A line continued with a backslash is one line.
    let found = edge(2_000, |n| {
        !stopped_by(&"cat <<A; \\\n".repeat(n), Shell::Posix, why)
    });
    assert_eq!(found, 256);
    // Here-strings are not here-documents, and here-documents on lines of
    // their own, closed or not, cost no more than the text: neither counts.
    for line in [
        "cat <<< a; ".repeat(2_000),
        "cat <<EOF\n".repeat(2_000),
        "cat <<EOF\nx\nEOF\n".repeat(2_000),
    ] {
        assert!(!stopped_by(&line, Shell::Posix, why), "{}", &line[..20]);
    }
    // And only a POSIX shell has them: `<<` is no more than a word, or a
    // shift, in the others.
    for shell in [Shell::PowerShell, Shell::Cmd] {
        assert!(!stopped_by(&"cat <<A; ".repeat(2_000), shell, why));
    }
}

#[test]
fn the_most_brackets_opened_that_read_is_the_limit() {
    // `MAX_TREE_DEPTH` in `unit.rs` is also the count of `(` with none
    // closed, taken before parsing and blind to quoting. In a string the
    // grammar sees no nesting, so the count alone is measured: the edge is
    // the same in every shell.
    for shell in SHELLS {
        let found = edge(1_000, |n| {
            !stopped_by(&format!("echo \"{}\"", "(".repeat(n)), shell, "too deeply")
        });
        assert_eq!(found, 400, "{shell:?}");
        // A bracket closed in between is not one still open.
        let closed = format!("echo \"{}\"", "() ".repeat(2_000));
        assert!(!stopped_by(&closed, shell, "too deeply"), "{shell:?}");
    }
}

#[test]
fn the_most_ands_and_pipes_in_cmd_that_read_is_the_limit() {
    // `MAX_CMD_SEPARATORS` in `unit.rs`: cmd's grammar nests a chain a level
    // for each `&` or `|` and takes time that grows with the square of them,
    // so each is counted before parsing (`&&` and `||` once). Inside a
    // string, where they separate nothing, the count alone is measured.
    let why = "too many commands";
    for separator in ["& ", "| ", "&& ", "|| "] {
        let found = edge(1_000, |n| {
            !stopped_by(
                &format!("echo \"{}\"", separator.repeat(n)),
                Shell::Cmd,
                why,
            )
        });
        assert_eq!(found, 400, "{separator}");
    }
    // The two are counted apart, and the others do not count them.
    assert!(!stopped_by(
        &format!("echo \"{}\"", "& | ".repeat(400)),
        Shell::Cmd,
        why
    ));
    for shell in [Shell::Posix, Shell::PowerShell] {
        assert!(!stopped_by(
            &format!("echo \"{}\"", "& ".repeat(2_000)),
            shell,
            why
        ));
    }
    // A real chain is unreadable at the grammar's own depth, a little short
    // of the count, so the count never turns a line that reads away.
    for separator in [" & ", " | ", " && ", " || "] {
        let found = edge(3_000, |n| {
            !unreadable(
                &format!("echo x{}", format!("{separator}echo x").repeat(n)),
                Shell::Cmd,
            )
        });
        assert_eq!(found, 397, "{separator}");
    }
}

#[test]
fn the_most_wrappers_in_front_of_a_program_that_read_is_the_limit() {
    // `MAX_WRAPPERS` in `launch.rs`: fifteen wrappers and the program read;
    // with a sixteenth the line is too wrapped.
    for wrapper in [
        "sudo", "env", "nohup", "nice", "command", "time", "exec", "xargs",
    ] {
        let found = edge(40, |n| {
            reads_the_delete(&format!("{}rm -rf /", format!("{wrapper} ").repeat(n)))
        });
        assert_eq!(found, 15, "{wrapper}");
    }
}

#[test]
fn the_most_finds_in_finds_that_read_is_the_limit() {
    // `find -exec find -exec …`: each is a wrapper, and is read as deep as
    // the wrappers are, sixteen of them.
    let found = edge(40, |n| {
        reads_the_delete(&format!("{}rm -rf x \\;", "find . -exec ".repeat(n)))
    });
    assert_eq!(found, 16);
}

#[test]
fn finds_in_finds_cost_what_the_line_is_long_not_what_it_multiplies_to() {
    // Each `find` runs its program once for each place it searches, and the
    // program is a `find` that does the same: eight places and sixteen levels
    // are eight to the sixteenth reads if every one is made. Past a budget
    // the line is unreadable instead.
    let wide = "find a a a a a a a a -exec ".repeat(16) + "rm -rf x \\;";
    // And as deep as the line is long: this overflowed the stack once.
    let deep = "find . -exec ".repeat(5_000) + "rm -rf x \\;";
    for line in [wide, deep] {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        assert!(unreadable(&line, Shell::Posix));
        assert_ne!(effect(&line, Shell::Posix, &posix()), Effect::ReadsOnly);
    }
}

#[test]
fn the_most_work_find_exec_may_do_is_counted_in_bytes_and_is_the_limit() {
    // `MAX_EXEC_WORK` in `find.rs`: every place `find` searches runs the
    // program once, with the bytes of its arguments, `{}` replaced by the
    // place. Here each of the places (`a`) costs the bytes of `echo` and
    // five hundred `{}`, and the edge is where the budget (1 MiB) runs out.
    let why = "runs too many programs";
    let line = |places: usize| {
        format!(
            "find {}-exec echo {}\\;",
            "a ".repeat(places),
            "{} ".repeat(500)
        )
    };
    let found = edge(2_000, |n| !stopped_by(&line(n), Shell::Posix, why));
    assert_eq!(found, 522);
    // One argument of a thousand `{}` is fewer arguments and more bytes, so
    // fewer places fit: the bytes count, not the arguments.
    let heavy = |places: usize| {
        format!(
            "find {}-exec echo {}\\;",
            "a ".repeat(places),
            "{}".repeat(1_000)
        )
    };
    assert!(!stopped_by(&heavy(348), Shell::Posix, why));
    assert!(stopped_by(&heavy(349), Shell::Posix, why));
    // Everyday finds are far under it.
    for line in [
        "find . -name '*.o' -exec rm {} \\;",
        "find src tests docs -type f -name '*.rs' -exec grep -l foo {} +",
        "find . -exec find . -exec echo {} \\; \\;",
    ] {
        assert!(!stopped_by(line, Shell::Posix, why), "{line}");
    }
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch an explosion"
)]
fn finds_in_finds_are_read_in_time_whatever_their_arguments_weigh() {
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
fn a_line_at_the_length_limit_is_read_in_time() {
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
