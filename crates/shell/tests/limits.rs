//! The limits the shell guard keeps, found by searching for the edge of each
//! and held there. Each search reads a great many long lines, so these live
//! in a binary of their own: cargo runs test binaries one after another, so
//! nothing here loads the machine while the timed tests of `robust.rs` and
//! `timing.rs` run.

mod common;
mod noise;

use common::{posix, windows};
use milo_guards_shell::{classify, effect, Effect, Rule, Shell};
use noise::{paths_for, Lcg, SHELLS};

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
    // Here-strings are not here-documents, and here-documents after a command
    // on lines of their own, closed or not, cost no more than the text:
    // neither counts. (With no command before the `<<` the grammar is slow,
    // which no count reaches; see "slow noise" in `docs/design/shell.md`.)
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
