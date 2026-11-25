//! Whatever the code, judging it ends, never panics, gives the same answer
//! twice, and never calls code it cannot read safe: code too long, nested
//! too deeply or running code too deeply is unreadable.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test reads the code reader's case files"
)]

mod common;

use common::{posix, windows};
use milo_guards_script::Language::{self, JavaScript, Python};
use milo_guards_script::{judge, Assessment, Rule, MAX_LEN};

/// Pieces of Python syntax, joined at random into code no parser expects.
const PYTHON: [&str; 46] = [
    "import os\n",
    "import shutil, sys, subprocess\n",
    "from os import remove as rm\n",
    "os.remove(",
    "shutil.rmtree(",
    "os.chdir(",
    "open(",
    "print(",
    "subprocess.run([",
    "os.system(",
    "exec(",
    "eval(",
    "'/home/me'",
    "'~/.ssh/id_rsa'",
    "'..'",
    "'w'",
    "\"x\"",
    "f\"{x}\"",
    "x = ",
    "x",
    "+",
    ", ",
    ")",
    "]",
    "[",
    "{",
    "}",
    ":",
    "\n",
    "\n    ",
    "\t",
    "if 1:",
    "def f():",
    "for i in x:",
    "lambda: ",
    "# c\n",
    "\\\n",
    "\"\"\"",
    "'''",
    "\u{0}",
    "\u{ff3f}",
    "é",
    "\r",
    "\u{2028}",
    "*",
    "~",
];

/// Pieces of JavaScript syntax.
const JAVASCRIPT: [&str; 46] = [
    "require('fs')",
    "require('child_process')",
    "import('x')",
    "import x from 'y'\n",
    ".rmSync(",
    ".writeFileSync(",
    ".readFileSync(",
    ".execSync(",
    "process.chdir(",
    "console.log(",
    "process.env",
    "process.kill(",
    "Deno.remove(",
    "Bun.write(",
    "'/home/me'",
    "'~/.ssh/id_rsa'",
    "'..'",
    "`x${y}`",
    "\"x\"",
    "const x = ",
    "let y = ",
    "x",
    "+",
    ", ",
    ")",
    "]",
    "[",
    "{",
    "}",
    "=>",
    ";",
    "\n",
    "/* c */",
    "// c\n",
    "function f() {",
    "if (1) ",
    "for (;;) ",
    "new ",
    "...",
    "await ",
    "\u{0}",
    "\u{ff43}",
    "é",
    "\r",
    "\u{2028}",
    "#!/usr/bin/env node\n",
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

fn noise(random: &mut Lcg, pieces: &[&str]) -> String {
    let length = random.next() % 24;
    (0..length)
        .map(|_| pieces[random.next() % pieces.len()])
        .collect()
}

fn rules(assessment: &Assessment) -> Vec<Rule> {
    assessment
        .findings()
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

#[test]
fn random_code_never_panics_and_gets_the_same_answer_twice() {
    for (language, pieces, seed) in [(Python, &PYTHON[..], 7), (JavaScript, &JAVASCRIPT[..], 11)] {
        let mut random = Lcg(seed);
        for paths in [posix(), windows()] {
            for _ in 0..3_000 {
                let code = noise(&mut random, pieces);
                let first = judge(language, &code, &paths);
                assert_eq!(first, judge(language, &code, &paths), "{code:?}");
                // A risky answer always says why.
                if let Assessment::Risky(findings) = &first {
                    assert!(!findings.is_empty(), "{code:?}");
                }
            }
        }
    }
}

#[test]
fn random_code_that_is_safe_is_read_whole() {
    // Safe code is code the reader understands: never code with a control
    // character other than a line feed or a tab, or a line separator.
    for (language, pieces, seed) in [(Python, &PYTHON[..], 13), (JavaScript, &JAVASCRIPT[..], 17)] {
        let mut random = Lcg(seed);
        for _ in 0..4_000 {
            let code = noise(&mut random, pieces);
            if judge(language, &code, &posix()).is_safe() {
                assert!(
                    !code.chars().any(|c| {
                        (c.is_control() && !matches!(c, '\n' | '\t'))
                            || matches!(c, '\u{2028}' | '\u{2029}')
                    }),
                    "{language:?} {code:?}"
                );
            }
        }
    }
}

/// Code that would be safe, made longer than the limit.
fn long(language: Language) -> String {
    match language {
        Python => format!("x = '{}'\nprint(x)", "a".repeat(MAX_LEN)),
        JavaScript => format!("let x = '{}'; console.log(x)", "a".repeat(MAX_LEN)),
    }
}

#[test]
fn code_longer_than_the_limit_is_unreadable_and_never_safe() {
    for language in [Python, JavaScript] {
        let code = long(language);
        assert!(code.len() > MAX_LEN);
        let assessment = judge(language, &code, &posix());
        assert_eq!(rules(&assessment), [Rule::Unreadable], "{language:?}");
        assert_eq!(assessment.findings()[0].reason, "is too long to read");
        // The finding does not carry code that long.
        assert_eq!(assessment.findings()[0].target, None);
        // At the limit it is read.
        let at_the_limit = match language {
            Python => format!("x = '{}'\nprint(x)", "a".repeat(MAX_LEN - 20)),
            JavaScript => format!("let x = '{}'; console.log(x)", "a".repeat(MAX_LEN - 30)),
        };
        assert!(at_the_limit.len() <= MAX_LEN);
        assert!(
            judge(language, &at_the_limit, &posix()).is_safe(),
            "{language:?}"
        );
    }
}

/// Shapes of code that nest `depth` deep in each language, each followed by
/// a write of a startup file that the reader only reads if it walks past the
/// deep part.
fn deep(language: Language, depth: usize) -> Vec<String> {
    match language {
        Python => vec![
            format!("print({}1{})", "(".repeat(depth), ")".repeat(depth)),
            format!(
                "x = 1\nx{}.b()\nopen('/home/me/.bashrc', 'w')",
                ".a".repeat(depth)
            ),
            format!(
                "x = {}1{}\nopen('/home/me/.bashrc', 'w')",
                "[".repeat(depth),
                "]".repeat(depth)
            ),
            format!("x = {}1\nopen('/home/me/.bashrc', 'w')", "-".repeat(depth)),
        ],
        JavaScript => vec![
            format!("console.log({}1{})", "(".repeat(depth), ")".repeat(depth)),
            format!("let x = 1\nconsole.log(x{})", ".length".repeat(depth)),
            format!(
                "let x = {}1{}\nconsole.log(x)",
                "[".repeat(depth),
                "]".repeat(depth)
            ),
            format!("let x = {}1\nconsole.log(x)", "-".repeat(depth)),
        ],
    }
}

#[test]
fn code_nested_too_deeply_is_unreadable_and_never_safe() {
    for language in [Python, JavaScript] {
        let mut unreadable = 0;
        for depth in [2_000, 20_000] {
            for code in deep(language, depth) {
                let assessment = judge(language, &code, &posix());
                assert!(!assessment.is_safe(), "{language:?} {depth}");
                // What the reader does not walk in full is unreadable.
                if milo_guards_code::read(language, &code).deep {
                    unreadable += 1;
                    assert!(
                        rules(&assessment).contains(&Rule::Unreadable),
                        "{language:?} {depth}: {assessment:?}"
                    );
                }
            }
        }
        // Some shapes are past the reader's walk, or the check is empty.
        assert!(unreadable > 0, "{language:?}");
        // Code of a sensible depth is read as any other.
        assert!(judge(language, &deep(language, 20)[0], &posix()).is_safe());
    }
}

/// Code that runs code that runs code, `depth` deep, the innermost a delete
/// of the home directory.
fn running(language: Language, depth: usize) -> String {
    let mut code = match language {
        Python => "import shutil; shutil.rmtree('/home/me')".to_string(),
        JavaScript => "require('fs').rmSync('/home/me')".to_string(),
    };
    for _ in 0..depth {
        let quoted = code.replace('\\', "\\\\").replace('"', "\\\"");
        code = match language {
            Python => format!("exec(\"{quoted}\")"),
            JavaScript => format!("eval(\"{quoted}\")"),
        };
    }
    code
}

#[test]
fn code_that_runs_code_too_deeply_is_unreadable_and_never_safe() {
    for language in [Python, JavaScript] {
        // Within the limit, the delete at the bottom is found.
        let assessment = judge(language, &running(language, 3), &posix());
        assert!(
            rules(&assessment).contains(&Rule::Delete),
            "{language:?}: {assessment:?}"
        );
        // Past it, the code is unreadable, for running code too deeply (the
        // reader stops at the same depth and says the code is too deep), and
        // the delete at the bottom is not read.
        let assessment = judge(language, &running(language, 12), &posix());
        let reasons: Vec<&str> = assessment
            .findings()
            .iter()
            .filter(|finding| finding.rule == Rule::Unreadable)
            .map(|finding| finding.reason.as_str())
            .collect();
        assert!(
            reasons.iter().any(|reason| {
                matches!(
                    *reason,
                    "runs code inside code too deeply to read" | "nests too deeply to read"
                )
            }),
            "{language:?}: {assessment:?}"
        );
        assert!(
            !rules(&assessment).contains(&Rule::Delete),
            "{language:?}: {assessment:?}"
        );
    }
}

#[test]
fn code_that_runs_much_code_ends_and_is_never_safe() {
    // A long literal run many times over, and many literals each run.
    for language in [Python, JavaScript] {
        let piece = match language {
            Python => format!("exec('x = 1 # {}')\n", "y".repeat(2_000)),
            JavaScript => format!("eval('let x = 1 // {}');\n", "y".repeat(2_000)),
        };
        let code = piece.repeat(MAX_LEN / piece.len());
        assert!(code.len() <= MAX_LEN);
        assert!(!judge(language, &code, &posix()).is_safe(), "{language:?}");
    }
}

/// The code of every `python` and `javascript` case of the code reader's
/// case files.
fn reader_cases() -> Vec<(Language, String)> {
    let folder = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../code/tests/cases");
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return found;
    };
    let mut files: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    files.sort();
    for file in files
        .iter()
        .filter(|file| file.extension().is_some_and(|ext| ext == "cases"))
    {
        let Ok(source) = std::fs::read_to_string(file) else {
            continue;
        };
        let Ok(records) = common::cases::format::parse(&file.display().to_string(), &source) else {
            continue;
        };
        for record in records {
            let Some(code) = record.text else { continue };
            let language = match common::cases::format::head(&record.words) {
                Some(("python" | "python2", None)) => Python,
                Some(("javascript", None)) => JavaScript,
                _ => continue,
            };
            found.push((language, code));
        }
    }
    found
}

#[test]
fn every_case_of_the_code_reader_is_judged() {
    // The reader's own cases, each in its own language and in the other, on
    // each machine: none panics, an answer is the same twice, and code is
    // safe only where the reader reads it whole. The agreement with the
    // shell guard is the front door's (`crates/guards/tests/agree_code.rs`).
    let cases = reader_cases();
    assert!(
        cases.len() > 200,
        "only {} cases of the code reader",
        cases.len()
    );
    for (language, code) in &cases {
        let other = match language {
            Python => JavaScript,
            JavaScript => Python,
        };
        for language in [*language, other] {
            for paths in [posix(), windows()] {
                let first = judge(language, code, &paths);
                assert_eq!(first, judge(language, code, &paths), "{code:?}");
                if first.is_safe() {
                    assert_ne!(
                        milo_guards_code::understand(language, code),
                        milo_guards_code::Understanding::NotUnderstood,
                        "{language:?} {code:?}"
                    );
                }
            }
        }
    }
}
