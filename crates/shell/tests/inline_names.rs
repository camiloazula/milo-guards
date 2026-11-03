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
//! are the chains of names and the lines of many strings the tests make, and
//! the time a chain takes.

mod common;

use common::{check, posix, took};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("inline_names");
}

/// A script that sets `levels` names, each by `line(at)` from the one before,
/// and then runs `last`.
fn chain(interpreter: &str, levels: usize, line: impl Fn(usize) -> String, last: &str) -> String {
    let (start, prelude, end) = if interpreter == "python3" {
        (
            "python3 - <<'PY'",
            "import os\nfrom pathlib import Path\n",
            "PY",
        )
    } else {
        ("node - <<'JS'", "const path = require('path');\n", "JS")
    };
    let mut text = format!("{start}\n{prelude}");
    for at in 0..levels {
        text.push_str(&line(at));
        text.push('\n');
    }
    text.push_str(last);
    text.push('\n');
    text.push_str(end);
    text
}

#[test]
fn names_each_set_to_twice_the_one_before_are_read_in_bounded_time() {
    // A name put back as its string, when the next name is set, doubled the
    // string at every line: 30 lines took seconds and 36 ran out of memory.
    // A string is cut at a length now, and the name that went over it is a
    // path the guard does not read.
    let base = "xy";
    let mut lines: Vec<(String, Rule)> = Vec::new();
    let python: Vec<Box<dyn Fn(usize) -> String>> = vec![
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = a{p} + a{p}", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = f'{{a{p}}}{{a{p}}}'", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = os.path.join(a{p}, a{p})", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = Path(a{p}) / a{p}", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = ''.join([a{p}, a{p}])", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("a0 = '{base}'"),
            _ => format!("a{at} = Path(a{p}).joinpath(a{p})", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => "a0 = '/home/me/.ssh/id_rsa'".to_string(),
            _ => format!("a{at} = a{p} + a{p}", p = at - 1),
        }),
    ];
    for line in python {
        for levels in [30, 40, 100] {
            let read = format!("print(open(a{}).read())", levels - 1);
            lines.push((chain("python3", levels, &line, &read), Rule::Unknown));
        }
    }
    let javascript: Vec<Box<dyn Fn(usize) -> String>> = vec![
        Box::new(|at| match at {
            0 => format!("const a0 = '{base}';"),
            _ => format!("const a{at} = a{p} + a{p};", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("const a0 = '{base}';"),
            _ => format!("const a{at} = `${{a{p}}}${{a{p}}}`;", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => format!("const a0 = '{base}';"),
            _ => format!("const a{at} = path.join(a{p}, a{p});", p = at - 1),
        }),
        Box::new(|at| match at {
            0 => "const a0 = '/home/me/.ssh/id_rsa';".to_string(),
            _ => format!("const a{at} = [a{p}, a{p}].join('');", p = at - 1),
        }),
    ];
    for line in javascript {
        for levels in [30, 40, 100] {
            let read = format!("require('fs').readFileSync(a{});", levels - 1);
            lines.push((chain("node", levels, &line, &read), Rule::Unknown));
        }
    }
    // One long string used thousands of times in one expression: built a
    // piece at a time, it is cut at the limit, not built.
    let long = "y".repeat(3000);
    let python_args = vec!["a"; 12_000].join(", ");
    let python_template = "{a}".repeat(12_000);
    let javascript_template = "${a}".repeat(10_000);
    for body in [
        format!("import os\na = '{long}'\nk = os.path.join({python_args})\nopen(k)"),
        format!("a = '{long}'\nk = f'{python_template}'\nopen(k)"),
        format!("a = '{long}'\nk = ''.join([{python_args}])\nopen(k)"),
        format!("a = '{long}'\nk = Path({python_args})\nopen(k)"),
    ] {
        lines.push((format!("python3 - <<'PY'\n{body}\nPY"), Rule::Unknown));
    }
    for body in [
        format!(
            "const path = require('path');\nconst a = '{long}';\nconst k = path.join({python_args});\nrequire('fs').readFileSync(k);"
        ),
        format!(
            "const a = '{long}';\nconst k = `{javascript_template}`;\nrequire('fs').readFileSync(k);"
        ),
        format!(
            "const a = '{long}';\nconst k = [{python_args}].join('');\nrequire('fs').readFileSync(k);"
        ),
    ] {
        lines.push((format!("node - <<'JS'\n{body}\nJS"), Rule::Unknown));
    }
    for (line, rule) in &lines {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        let took = took(line, Shell::Posix, &posix());
        assert!(
            took < std::time::Duration::from_secs(2),
            "{} bytes took {took:?}: {line}",
            line.len()
        );
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
