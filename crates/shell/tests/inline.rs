//! Inline code: Python and JavaScript given with `-c`, `-e`, `eval` or a
//! here-document are read, and what they delete, write and run is judged
//! like the same shell command: a finding names the path and why, a path is
//! read as the shell reads it, code that starts code is read to a limit, and
//! long code is read in linear time.
//!
//! The lines and their answers are in `tests/cases/inline.cases`; here are
//! the path a finding names, the code nested past the limit, and the timed
//! test.

mod common;

use common::inline::nest;
use common::{posix, rules, took};
use milo_guards_shell::{classify, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("inline");
}

#[test]
fn a_finding_names_the_path_and_why() {
    let paths = posix();
    let judge = |line: &str| classify(line, Shell::Posix, &paths).findings().to_vec();

    let home = judge("python3 -c \"import shutil,os; shutil.rmtree(os.path.expanduser('~'))\"");
    assert_eq!(home.len(), 1, "{home:?}");
    assert_eq!(home[0].rule, Rule::Delete);
    assert_eq!(home[0].reason, "deletes your home directory");
    assert_eq!(home[0].target.as_deref(), Some("~"));

    let here = judge("python3 - <<'PY'\nimport shutil\nshutil.rmtree('/home/me')\nPY");
    assert_eq!(here.len(), 1, "{here:?}");
    assert_eq!(here[0].reason, "deletes your home directory");
    assert_eq!(here[0].target.as_deref(), Some("/home/me"));

    let unknown = judge("python3 -c \"exec(input())\"");
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0].rule, Rule::Unknown);
    assert_eq!(unknown[0].reason, "runs code the guard does not read");
    assert_eq!(unknown[0].target.as_deref(), Some("exec(input())"));
}

#[test]
fn code_that_starts_code_is_read_to_a_limit() {
    let paths = posix();
    // Python that runs `python3 -c` that runs Python, each inside the last.
    let mut line = "rm -rf /tmp/x".to_string();
    for level in 1..=12 {
        line = nest(&line);
        let found = rules(&line, Shell::Posix, &paths);
        if level <= 3 {
            // Read through, so not unreadable; the `import os` of each level
            // is not read whole by the strict gate, so it is unknown.
            assert!(
                found.iter().all(|rule| *rule == Rule::Unknown),
                "level {level} is read: {found:?}"
            );
        }
    }
    let found = rules(&line, Shell::Posix, &paths);
    assert!(
        found.contains(&Rule::Unreadable),
        "nested past the limit: {found:?}"
    );

    let deep = format!(
        "python3 -c \"import os; os.remove({}1{})\"",
        "(".repeat(2000),
        ")".repeat(2000)
    );
    let found = rules(&deep, Shell::Posix, &paths);
    assert!(!found.is_empty(), "too deep to read must be risky");

    let deep = format!(
        "node -e \"require('fs').rmSync({}1{})\"",
        "(".repeat(2000),
        ")".repeat(2000)
    );
    let found = rules(&deep, Shell::Posix, &paths);
    assert!(!found.is_empty(), "too deep to read must be risky");
}

/// Long inline code, and the chain of members in it, if any. Reading inline
/// code asked the tree for each name's parent, which walks it from the root,
/// and built a dotted name again from each member of it: a chain of 30,000
/// members (60 KB, under the limit) took a minute.
fn long_code() -> (Vec<String>, String) {
    let chain = ".b".repeat(30_000);
    let calls = format!("{}{}", "f(".repeat(10_000), ")".repeat(10_000));
    // Chains just under the depth limit, many of them: every one is read.
    let chains = format!("x = a{}\n", ".b".repeat(390)).repeat(80);
    // Calls nested just under the limit on every line, many of them.
    let nested = format!("f({}\n", "f(".repeat(380) + &")".repeat(381)).repeat(50);
    let mut rows = Vec::new();
    for (interpreter, end) in [("python3", "PY"), ("node", "JS")] {
        for body in [
            format!("x = a{chain}"),
            calls.clone(),
            chains.clone(),
            nested.clone(),
        ] {
            rows.push(format!("{interpreter} - <<'{end}'\n{body}\n{end}"));
        }
    }
    (rows, chain)
}

#[test]
fn long_inline_code_is_read_unless_it_nests_too_deep() {
    let (rows, chain) = long_code();
    for line in rows {
        assert!(line.len() <= 64 * 1024, "{}", line.len());
        // What nests too deeply to read is not safe, and the rest is read.
        // The body of a quoted here-document is a literal to the shell, so
        // the shell's count of open parentheses does not see it: the reader
        // of the code does, and calls nested past what it reads are code it
        // does not read.
        let assessment = classify(&line, Shell::Posix, &posix());
        let deep = assessment
            .findings()
            .iter()
            .any(|finding| finding.rule == Rule::Unreadable);
        assert_eq!(deep, line.contains(&chain), "{:?}", &line[..20]);
        if line.contains(&"f(".repeat(500)) {
            assert!(!assessment.is_safe(), "{:?}", &line[..20]);
        }
    }
}

#[test]
#[cfg_attr(
    any(coverage, debug_assertions),
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn long_inline_code_is_read_in_linear_time() {
    for line in long_code().0 {
        let took = took(&line, Shell::Posix, &posix());
        assert!(
            took < std::time::Duration::from_secs(2),
            "{:?} took {took:?}",
            &line[..20]
        );
    }
}
