//! The names and modules the inline reader follows, and those it does not:
//! a module under another name, default values, a module handed on as a
//! value, `with` and destructuring with a rest, every way JavaScript reaches a
//! module, names read in their NFKC form or written with an escape, names
//! bound in a class body or more than once, keys that are not plain names,
//! names literal `exec` and `eval` code binds or uses, a dotted `__import__`,
//! the value of `eval`, node's `module`, awaited imports of a computed value,
//! assignments to a module or a builtin prototype, escapes the reader does not
//! decode, and chains of names held to a bound.
//!
//! The lines and their answers are in `tests/cases/inline_names.cases`; here
//! are the chains of names and the lines of many strings the tests make. The
//! time a chain takes is in `tests/timing.rs`.

mod common;

use common::lines::{chain, doubled_names};
use common::{check, posix};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("inline_names");
}

#[test]
fn names_each_set_to_twice_the_one_before_are_not_read() {
    for (line, rule) in &doubled_names() {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        // Not read, so not safe: a name that went over the limit is no path
        // the guard knows.
        let rules: Vec<Rule> = classify(line, Shell::Posix, &posix())
            .findings()
            .iter()
            .map(|finding| finding.rule)
            .collect();
        assert!(rules.contains(rule), "{rules:?}: {line}");
    }
    // Under the limit the strings are still put back, so the key is found
    // at the end of a chain.
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // A here-document is never read whole: unknown.
            (
                &chain(
                    "python3",
                    6,
                    |at| match at {
                        0 => "a0 = 'a'".to_string(),
                        _ => format!("a{at} = a{p} + 'b'", p = at - 1),
                    },
                    "print(open(a5).read())",
                ),
                Rule::Unknown,
            ),
            (
                &chain(
                    "python3",
                    6,
                    |at| match at {
                        0 => "a0 = '/home/me/.ssh/'".to_string(),
                        _ => format!("a{at} = a{p}", p = at - 1),
                    },
                    "print(open(a5 + 'id_rsa').read())",
                ),
                Rule::ReadSecret,
            ),
            (
                &chain(
                    "node",
                    6,
                    |at| match at {
                        0 => "const a0 = '/home/me/.ssh/';".to_string(),
                        _ => format!("const a{at} = a{p};", p = at - 1),
                    },
                    "require('fs').readFileSync(a5 + 'id_rsa');",
                ),
                Rule::ReadSecret,
            ),
        ],
    );
}

/// The lines made of many strings; the names that hold one or two are in
/// `tests/cases/inline_names.cases`.
#[test]
fn a_name_that_holds_more_than_the_reader_keeps_is_not_read_as_any_string() {
    // 65 strings written out, the key last: every one is read, as `cat` of
    // each is.
    let paths: Vec<String> = (0..65).map(|at| format!("'a{at}.txt'")).collect();
    let many = format!("{}, '/home/me/.ssh/id_rsa'", paths.join(", "));
    let many_js = format!("{}, '/home/me/.ssh/id_rsa'", paths.join(", "));
    // A thousand, in a line well under the length limit.
    let thousands: Vec<String> = (0..1000).map(|at| format!("'a{at}'")).collect();
    let thousands = format!("{}, '/home/me/.ssh/id_rsa'", thousands.join(","));
    let safe_thousands: Vec<String> = (0..1000).map(|at| format!("'a{at}'")).collect();
    let safe_thousands = safe_thousands.join(",");
    // A name set to more strings, in all, than the reader holds is a path it
    // does not read: not safe, as the key may be any of them. Strings made
    // of one long string each pile up past the budget.
    let long = "d".repeat(1000);
    let derived: Vec<String> = (0..400)
        .map(|at| format!("p{at} = base + '{at}'"))
        .collect();
    let derived = derived.join("\n");
    let script = format!("base = '/home/me/work/repo/{long}'\n{derived}\n");
    // Read again and again, a name with a thousand strings is not read in
    // full each time: past a count of reads the code is not followed.
    let strings: Vec<String> = (0..1000).map(|at| format!("'b{at}'")).collect();
    let reads = "print(open(k).read())\n".repeat(200);
    let nine_names = format!(
        "python3 - <<'PY'\n{}\nprint(open({}).read())\nPY",
        (0..9)
            .map(|at| format!("for n{at} in ['x{at}', 'y{at}']: pass"))
            .collect::<Vec<_>>()
            .join("\n"),
        (0..9)
            .map(|at| format!("n{at}"))
            .collect::<Vec<_>>()
            .join(" + ")
    );
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            // Loops, here-documents and a `require` are not read whole by the
            // strict gate: unknown.
            (
                &format!("python3 -c \"for k in [{}]: print(open(k).read())\"", paths.join(", ")),
                Rule::Unknown,
            ),
            (
                &format!("python3 - <<'PY'\nfor k in [{safe_thousands}]:\n    print(open(k).read())\nPY"),
                Rule::Unknown,
            ),
            (
                &format!(
                    "node - <<'JS'\nfor (const k of [{safe_thousands}]) require('fs').readFileSync(k);\nJS"
                ),
                Rule::Unknown,
            ),
            (
                &format!("python3 -c \"for k in [{many}]: print(open(k).read())\""),
                Rule::ReadSecret,
            ),
            (
                &format!("python3 - <<'PY'\nfor k in [{thousands}]:\n    print(open(k).read())\nPY"),
                Rule::ReadSecret,
            ),
            (
                &format!(
                    "node - <<'JS'\nfor (const k of [{many_js}]) require('fs').readFileSync(k);\nJS"
                ),
                Rule::ReadSecret,
            ),
            (
                &format!(
                    "node - <<'JS'\nfor (const k of [{thousands}]) require('fs').readFileSync(k);\nJS"
                ),
                Rule::ReadSecret,
            ),
            // More strings than the reader holds (a here-document is never
            // read whole: unknown).
            (
                &format!("python3 - <<'PY'\n{script}print(open(p0).read())\nPY"),
                Rule::Unknown,
            ),
            (
                &format!("python3 - <<'PY'\n{script}print(open(p399).read())\nPY"),
                Rule::Unknown,
            ),
            (
                &format!(
                    "python3 - <<'PY'\nfor k in [{}]:\n    pass\n{reads}PY",
                    strings.join(",")
                ),
                Rule::Unknown,
            ),
            // More choices than the reader goes through (9 names of 2
            // strings are 512) are a path it does not read.
            (&nine_names, Rule::Unknown),
        ],
    );
}
