//! Whatever the text, classifying it ends, never panics, and never calls
//! a line it could not read safe; and the same for `effect`, which never
//! calls such a line reads-only, and for `explain` and the tree it draws,
//! which do more work than `classify` and are held to the same limits. The
//! counts that guard the grammars' time stop a line too long, too nested or
//! too tangled to read, and do not take everyday lines that hold a lot of
//! `<<` or `&` for tangled ones. The time those lines take, `explain` and its
//! tree included, is in `tests/timing.rs`.

mod common;
mod noise;

use common::lines::{
    deep_traps, dotglob_loops, input_redirects_over_many_units, long_alias, nested_outputs,
    open_bracket_shapes, open_brackets, variable_chain, wide_traps, wrapper_shapes, EXTENDED_GLOB,
    OUTPUT_SHAPES, PACKAGE_RUNNERS, VARIABLE_COPIES,
};
use common::{check, disagreements, posix, windows};
use milo_guards_shell::{classify, effect, explain, Effect, Paths, Rule, Shell};
use noise::{paths_for, wide_lines, Lcg, SHELLS};

/// Whether `explain` finds `line` unreadable, its tree drawn and saying so.
fn explained_unreadable(line: &str, shell: Shell, paths: &Paths) -> bool {
    let explanation = explain(line, shell, paths);
    let tree = explanation.to_string();
    explanation
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable)
        && tree.contains(Rule::Unreadable.name())
}

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

#[test]
fn every_case_holds() {
    common::cases::check("robust");
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
#[allow(
    clippy::disallowed_methods,
    reason = "the guard starts no thread; this test reads each shell on one, to be done sooner"
)]
fn wide_random_lines_never_panic() {
    // Wider noise than `random_lines_never_panic`, a third of it cut or with
    // stray bytes joined on: `classify` and `effect` agree on every line, and
    // the set really is noise, as most of it cannot be read. Each shell reads
    // the set on a thread of its own, as a debug build takes a while over
    // it. Its time is in `tests/timing.rs`.
    let lines = wide_lines();
    let unreadable: usize = std::thread::scope(|scope| {
        let each = SHELLS.map(|shell| {
            let lines = &lines;
            scope.spawn(move || {
                let paths = paths_for(shell);
                let mut unreadable = 0;
                for line in lines {
                    let assessment = classify(line, shell, &paths);
                    let _ = effect(line, shell, &paths);
                    let wrong = disagreements(shell, &paths, [line.as_str()]);
                    assert!(wrong.is_empty(), "{shell:?}: {wrong:?}");
                    unreadable += usize::from(
                        assessment
                            .findings()
                            .iter()
                            .any(|finding| finding.rule == Rule::Unreadable),
                    );
                }
                unreadable
            })
        });
        each.into_iter()
            .map(|shell| {
                shell
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .sum()
    });
    let read = lines.len() * SHELLS.len();
    assert!(unreadable * 3 > read, "only {unreadable} of {read}");
}

#[test]
fn a_line_too_long_or_too_nested_is_not_read() {
    let long = "echo x; ".repeat(10_000);
    assert!(classify(&long, Shell::Posix, &posix())
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable));
    assert_eq!(effect(&long, Shell::Posix, &posix()), Effect::Unknown);
    assert!(explained_unreadable(&long, Shell::Posix, &posix()));
    // Every `(` row is stopped before it is parsed, by the count of open
    // `(`; the walk's own depth limit is tested on lines without one, in
    // `nesting_the_count_of_open_parens_cannot_see_is_stopped_by_the_walk`.
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
        assert!(
            explained_unreadable(&nested, shell, &paths),
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
fn nesting_the_count_of_open_parens_cannot_see_is_stopped_by_the_walk() {
    // `a_line_too_long_or_too_nested_is_not_read` nests with `(`, which the
    // count before parsing stops, so the walk's own depth limit, and its
    // freedom from recursion, would go untested there. These lines hold no
    // `(`: braces in a POSIX shell, script blocks in PowerShell. Each is deep
    // enough to overflow a stack that recursed, and reaches the walk.
    let braces = "{ ".repeat(13_000) + "echo" + &"; }".repeat(13_000);
    let blocks = "{".repeat(30_000) + "echo" + &"}".repeat(30_000);
    for (line, shell) in [(&braces, Shell::Posix), (&blocks, Shell::PowerShell)] {
        let paths = if shell == Shell::Posix {
            posix()
        } else {
            windows()
        };
        check(shell, &paths, &[], &[(line, Rule::Unreadable)]);
        assert_eq!(effect(line, shell, &paths), Effect::Unknown, "{shell:?}");
        assert!(explained_unreadable(line, shell, &paths), "{shell:?}");
    }
}

#[test]
#[allow(
    clippy::disallowed_types,
    reason = "the guard starts no thread; this test starts one for the stack it is given"
)]
fn the_longest_chains_are_read_on_a_small_stack() {
    // The POSIX grammar makes the left side of each `&&` and `||` a list of
    // its own (`a && b && c` is `(a && b) && c`), so a chain at the length
    // limit is thousands of levels deep, and a walk that recursed into them
    // overflowed the stack of a debug build: an abort, which no caller can
    // catch. The walk of each grammar nests as deep as the tree, to the
    // depth limit, so its frame is kept small, and what reads a chain apart
    // from the walk reads it in a loop. Each chain is read on a thread with
    // a test thread's 2 MiB stack, in every shell, whatever stack the test
    // runner gives its own.
    let fit = |head: &str, unit: &str, tail: &str| {
        let room = 64 * 1024 - head.len() - tail.len();
        head.to_string() + &unit.repeat(room / unit.len()) + tail
    };
    let chains = [
        fit("", "echo x && ", "echo"),
        fit("", "echo x || ", "echo"),
        fit("", "cd a && echo x || ", "echo"),
        fit("", "echo x; ", "echo"),
        fit("", "echo x | ", "cat"),
        fit("", "echo x & ", "echo"),
        // An arithmetic assignment nests to the right, a level for each `=`,
        // and its operands are read whole for a `GLOBIGNORE` among them.
        fit("((", "x=", "1))"),
        fit("echo $((", "x=", "1))"),
        fit("((", "x+=", "1))"),
        // Lists in subshells, as deep as the count of open `(` lets a line be.
        "(echo x && ".repeat(199) + "echo" + &")".repeat(199),
        // PowerShell nests a chain of members, and of operators, a level
        // for each.
        "$x".to_string() + &".a()".repeat(16_000),
        "'a'".to_string() + &" -replace 'a', 'b'".repeat(3_000),
    ];
    let read = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
                let paths = if shell == Shell::Posix {
                    posix()
                } else {
                    windows()
                };
                for chain in &chains {
                    let _ = classify(chain, shell, &paths);
                    let _ = effect(chain, shell, &paths);
                    let _ = explain(chain, shell, &paths).to_string();
                }
            }
            // Past the depth limit, a chain is unreadable.
            for chain in &chains[..3] {
                assert!(
                    explained_unreadable(chain, Shell::Posix, &posix()),
                    "{}",
                    &chain[..20]
                );
            }
        })
        .expect("a thread for the chains")
        .join();
    assert!(read.is_ok());
}

/// Source with a stream operator on each line, written into a file by a
/// here-document or a PowerShell here-string.
fn cpp_lines() -> String {
    let mut lines = String::new();
    for n in 1..=130 {
        lines.extend(["std::cout << \"line ", &n.to_string(), "\" << std::endl;\n"]);
    }
    lines
}

#[test]
fn here_documents_are_read_in_any_number_unless_too_many_wait_on_one_line() {
    // Each line of the body holds two `<<`, none of them a here-document;
    // 130 of them are more than the limit on here-documents, counted over
    // the text.
    let heredoc = format!("cat > main.cpp <<'EOF'\n{}EOF\n", cpp_lines());
    // And a body with a delimiter of another shape, or an indented one.
    let tabbed = format!("cat > main.cpp <<-EOF\n{}\tEOF\n", cpp_lines());
    let quoted = format!("cat > main.cpp <<\"END\"\n{}END\n", cpp_lines());
    // Three hundred, each closed: here-documents after a command, on lines
    // of their own, are read in linear time, so any number of them are fine.
    let closed = "cat <<EOF\nx\nEOF\n".repeat(300);
    let many = "cat <<EOF\nx\nEOF\n".repeat(4_000);
    // And here-strings, of any number.
    let strings = "cat <<< a; ".repeat(1_000);
    // Too many here-documents started on one line are not read: the grammar
    // takes time that grows with the square of how many wait for the end of
    // the line, closed or not.
    let waiting = "cat <<EOF; ".repeat(300) + "\nEOF\n";
    let continued = "cat <<EOF; \\\n".repeat(300) + "\nEOF\n";
    for line in [&waiting, &continued] {
        assert!(explained_unreadable(line, Shell::Posix, &posix()));
    }
    check(
        Shell::Posix,
        &posix(),
        &[&heredoc, &tabbed, &quoted, &closed, &many, &strings],
        &[(&waiting, Rule::Unreadable), (&continued, Rule::Unreadable)],
    );
}

#[test]
fn a_file_of_stream_operators_written_by_a_here_string_is_safe_in_powershell() {
    // PowerShell has no here-documents: `<<` in the text of a here-string is
    // text.
    let here_string = format!("Set-Content main.cpp @'\n{}'@\n", cpp_lines());
    check(Shell::PowerShell, &windows(), &[&here_string], &[]);
}

#[test]
fn a_long_chain_in_cmd_is_not_read_and_one_that_reads_is() {
    // `&` and `|` are counted before parsing: past the grammar's own depth a
    // chain is unreadable anyway, so a shorter one is read as before.
    let long = "echo x & ".repeat(5_000);
    let longer_pipeline = "echo x | ".repeat(5_000) + "cat";
    let short = "echo x & ".repeat(300) + "echo y";
    let shorter_pipeline = "echo x | ".repeat(300) + "cat";
    let both = "echo x & echo y | ".repeat(150) + "echo z";
    for line in [&long, &longer_pipeline] {
        assert!(explained_unreadable(line, Shell::Cmd, &windows()));
    }
    check(
        Shell::Cmd,
        &windows(),
        &[&short, &shorter_pipeline, &both],
        &[
            (&long, Rule::Unreadable),
            (&longer_pipeline, Rule::Unreadable),
        ],
    );
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
    assert!(explained_unreadable(&line, Shell::Posix, &posix()));
    // A few reads of a short script are fine (in robust.cases).
}

#[test]
fn a_long_run_of_open_brackets_is_read_as_plain_characters_or_unreadable() {
    // In cmd and POSIX shell a long name of brackets is read as a short one
    // is: plain characters. PowerShell's grammar nests at each `[`, so past
    // the deepest nesting the line is unreadable, never safe.
    for (shell, head, tail, paths) in open_bracket_shapes() {
        let rules = |size| {
            classify(&open_brackets(head, tail, size), shell, &paths)
                .findings()
                .iter()
                .map(|finding| finding.rule)
                .collect::<Vec<_>>()
        };
        let long = rules(64 * 1024);
        if shell == Shell::PowerShell {
            assert_eq!(long, [Rule::Unreadable], "{shell:?} {head}");
        } else {
            assert_eq!(long, rules(64), "{shell:?} {head}");
        }
    }
}

#[test]
fn nested_loops_that_may_turn_on_dotglob_judge_hidden_names_in_each() {
    assert_eq!(
        classify(&dotglob_loops(64 * 1024), Shell::Posix, &posix())
            .findings()
            .iter()
            .map(|finding| finding.rule)
            .collect::<Vec<_>>(),
        [Rule::Delete]
    );
}

#[test]
fn a_trap_in_a_substitution_in_a_trap_is_not_safe() {
    let wide = wide_traps(64 * 1024);
    assert!(wide.len() <= 64 * 1024, "{}", wide.len());
    for line in [deep_traps(), wide] {
        assert!(!classify(&line, Shell::Posix, &posix()).is_safe());
    }
}

#[test]
fn a_package_runner_read_two_ways_many_times_is_not_safe() {
    // `bun -F x --package run` reads two ways, and each leads to another
    // `bun`: the readings share the wrappers a line may have and the forks
    // it may make, so the work does not double at each group, never
    // recurses without a bound, and a line past them is unreadable.
    for group in PACKAGE_RUNNERS {
        for count in [16, 20, 40, 600, 2_000] {
            let line = format!("{}rm -rf ~", group.repeat(count));
            assert!(line.len() <= 64 * 1024, "{}", line.len());
            assert!(
                !classify(&line, Shell::Posix, &posix()).is_safe(),
                "{count} x {group:?}"
            );
            assert!(!matches!(
                effect(&line, Shell::Posix, &posix()),
                Effect::ReadsOnly(_)
            ));
        }
    }
    // Past the wrappers a line may have, it is too wrapped, as for any other
    // runner.
    let line = format!("{}rm -rf ~", "bun -F x run ".repeat(40));
    assert!(classify(&line, Shell::Posix, &posix())
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unreadable));
}

#[test]
fn words_zsh_reads_another_way_many_times_are_not_safe() {
    // With `extendedglob` on, a command with a word zsh reads another way is
    // judged both ways: each is a fork, counted against the line's, and a
    // loop body makes the line be read again, once. A line past the forks is
    // unreadable.
    for count in [16, 33, 800] {
        for (head, tail) in EXTENDED_GLOB {
            let line = format!("{head}{}rm -rf .gi#t; {tail}", "ls a#b; ".repeat(count));
            assert!(line.len() <= 64 * 1024, "{}", line.len());
            let assessment = classify(&line, Shell::Posix, &posix());
            assert!(!assessment.is_safe(), "{count} {head:?}");
            if count > 32 {
                assert!(
                    assessment
                        .findings()
                        .iter()
                        .any(|finding| finding.rule == Rule::Unreadable),
                    "{count} {head:?}"
                );
            }
        }
    }
}

#[test]
fn a_wrapper_given_its_folder_or_its_options_many_times_is_not_safe() {
    for (shell, (head, part, tail), paths) in wrapper_shapes() {
        for count in [16, 2_000] {
            let line = format!("{head}{}{tail}", part.repeat(count));
            assert!(line.len() <= 64 * 1024, "{}", line.len());
            assert!(
                !classify(&line, shell, &paths).is_safe(),
                "{count} x {head}{part} in {shell:?}"
            );
        }
    }
}

#[test]
fn a_long_alias_used_many_times_with_words_is_not_safe() {
    // Each use with words runs the alias's last command with them, so the
    // words it takes from the alias are counted: past as many as the
    // longest line holds, a use is not expanded and the line is unreadable.
    let paths = posix();
    let line = long_alias(64 * 1024);
    let assessment = classify(&line, Shell::Posix, &paths);
    assert!(!assessment.is_safe());
    assert!(
        explained_unreadable(&line, Shell::Posix, &paths),
        "{assessment:?}"
    );
}

#[test]
fn a_long_chain_of_variable_copies_sends_the_secret() {
    let line = variable_chain(VARIABLE_COPIES);
    assert!(
        line.len() > 50_000 && line.len() <= 64 * 1024,
        "{}",
        line.len()
    );
    assert!(classify(&line, Shell::Posix, &posix())
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::SendSecret));
}

#[test]
fn input_redirects_over_many_units_are_read_and_the_secret_one_holds_is_sent() {
    // Each redirect is read once for the whole group it covers, not once for
    // each unit in it (the time is in `timing.rs`); the last line has a
    // variable that holds a secret, named in a here-document and sent.
    let lines = input_redirects_over_many_units();
    for line in &lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let _ = classify(line, Shell::Posix, &posix());
    }
    let sent = lines
        .last()
        .map(|line| classify(line, Shell::Posix, &posix()));
    assert!(sent.is_some_and(|assessment| assessment
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::SendSecret)));
}

#[test]
fn a_wrapper_that_names_its_output_many_times_is_not_safe() {
    // Each output option is a write of its own, read once; `script` reads
    // its options among its operands, both ways `-F` reads; and a command
    // `strace -o '|…'` pipes to is a script of its own, nested no deeper than
    // any other. (`-o '|ls'` writes nowhere.)
    for count in [16, 2_000] {
        let numbered = (0..count).fold(String::new(), |words, i| words + &format!("-O a{i} "));
        let lines = OUTPUT_SHAPES
            .iter()
            .filter(|(_, part, _)| !part.contains("'|ls'"))
            .map(|(head, part, tail)| format!("{head}{}{tail}", part.repeat(count)))
            // Each value its own file.
            .chain([format!("script -c ls -O /etc/passwd {numbered}")]);
        for line in lines {
            assert!(line.len() <= 64 * 1024, "{}", line.len());
            assert!(
                !classify(&line, Shell::Posix, &posix()).is_safe(),
                "{count} x {}",
                &line[..20]
            );
        }
    }
    for size in [1024, 64 * 1024] {
        let line = nested_outputs(size);
        assert!(!classify(&line, Shell::Posix, &posix()).is_safe(), "{size}");
    }
}
