//! Whatever the code, reading it ends, never panics, gives the same answer
//! twice, and never takes code it cannot read for understood.

mod common;

use common::shown;
use milo_guards_code::Language::{self, JavaScript, Python};
use milo_guards_code::{read, understand, Act, Understanding, MAX_LEN};

/// Pieces of Python syntax, joined at random into code no parser expects.
const PYTHON: [&str; 44] = [
    "import os\n",
    "import shutil, sys, json, re\n",
    "from os import remove as rm\n",
    "os.remove(",
    "shutil.rmtree(",
    "open(",
    "print(",
    "subprocess.run([",
    "exec(",
    "eval(",
    "'/home/me'",
    "'~'",
    "'../x'",
    "\"x\"",
    "f\"{x}\"",
    "b'x'",
    "x = ",
    "x",
    "n",
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
];

/// Pieces of JavaScript syntax.
const JAVASCRIPT: [&str; 44] = [
    "require('fs')",
    "require('child_process')",
    "import('x')",
    "import x from 'y'\n",
    ".rmSync(",
    ".writeFileSync(",
    ".execSync(",
    "console.log(",
    "process.env",
    "process.kill(",
    "Deno.remove(",
    "Bun.write(",
    "'/home/me'",
    "'~'",
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
    "async ",
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

/// What code that is understood may do to a file: open one.
fn opens_only(act: &Act) -> bool {
    matches!(act, Act::Read(_) | Act::Write(_) | Act::Opaque(_))
}

#[test]
fn random_code_never_panics_and_reads_the_same_twice() {
    for (language, pieces, seed) in [(Python, &PYTHON[..], 7), (JavaScript, &JAVASCRIPT[..], 11)] {
        let mut random = Lcg(seed);
        for _ in 0..4_000 {
            let code = noise(&mut random, pieces);
            let first = read(language, &code);
            let second = read(language, &code);
            assert_eq!(shown(&first.acts), shown(&second.acts), "{code:?}");
            assert_eq!(first.deep, second.deep, "{code:?}");
            assert_eq!(
                understand(language, &code),
                understand(language, &code),
                "{code:?}"
            );
        }
    }
}

#[test]
fn understood_code_only_ever_opens_a_file() {
    for (language, pieces, seed) in [(Python, &PYTHON[..], 13), (JavaScript, &JAVASCRIPT[..], 17)] {
        let mut random = Lcg(seed);
        let mut understood = 0;
        for _ in 0..6_000 {
            let code = noise(&mut random, pieces);
            if let Understanding::Understood { imports } = understand(language, &code) {
                understood += 1;
                // Only Python loads a module when it runs without an import.
                assert_eq!(imports, language == Python, "{code:?}");
                // No control character and no line separator is understood.
                assert!(
                    !code.chars().any(|c| {
                        (c.is_control() && !matches!(c, '\n' | '\t'))
                            || matches!(c, '\u{2028}' | '\u{2029}')
                    }),
                    "{code:?}"
                );
                let acts = read(language, &code).acts;
                assert!(acts.iter().all(opens_only), "{code:?}: {}", shown(&acts));
            }
        }
        // The noise does hit the subset now and then, or the check is empty.
        assert!(understood > 0, "no random code was understood");
    }
}

/// Code nested `depth` deep in each language.
fn nested(language: Language, depth: usize) -> String {
    match language {
        Python => format!("print({}1{})", "(".repeat(depth), ")".repeat(depth)),
        JavaScript => format!("console.log({}1{})", "(".repeat(depth), ")".repeat(depth)),
    }
}

#[test]
fn code_nested_very_deeply_ends() {
    for language in [Python, JavaScript] {
        // The tree is walked without recursion, so no depth overflows the
        // stack; what the reader does not walk in full it says (`deep`).
        for depth in [2_000, 20_000] {
            let code = nested(language, depth);
            let _ = read(language, &code);
            assert_eq!(
                understand(language, &code),
                Understanding::NotUnderstood,
                "{language:?} {depth}"
            );
        }
        // Nested code of a sensible depth is read as any other.
        assert_ne!(
            understand(language, &nested(language, 20)),
            Understanding::NotUnderstood,
            "{language:?}"
        );
    }
}

#[test]
fn long_code_and_strings_that_grow_end() {
    for language in [Python, JavaScript] {
        let long = match language {
            Python => format!("x = '{}'\nprint(x)", "a".repeat(MAX_LEN * 4)),
            JavaScript => format!("let x = '{}'; console.log(x)", "a".repeat(MAX_LEN * 4)),
        };
        let _ = read(language, &long);
        let _ = understand(language, &long);
        // A name set to a string built from itself doubles with each line; a
        // path read from it is bounded, not a gigabyte.
        let doubling = match language {
            Python => format!("a = '/home/me/'\n{}open(a)", "a = a + a\n".repeat(60)),
            JavaScript => format!(
                "let a = '/home/me/'; {}require('fs').readFileSync(a)",
                "a = a + a; ".repeat(60)
            ),
        };
        let reading = read(language, &doubling);
        // The read is of a path the reader does not know, never of a string
        // of that length.
        for act in &reading.acts {
            if let Act::Read(arg) = act {
                assert!(arg.text().len() <= MAX_LEN, "{language:?}");
            }
        }
    }
}

#[test]
fn many_names_and_calls_end() {
    // A line of names set to several strings each, read together.
    let python: String = (0..200)
        .map(|n| format!("n{n} = 'a'\nn{n} = 'b'\n"))
        .chain(std::iter::once(format!(
            "open({})\n",
            (0..200)
                .map(|n| format!("n{n}"))
                .collect::<Vec<_>>()
                .join(" + ")
        )))
        .collect();
    let _ = read(Python, &python);
    let javascript: String = (0..200)
        .map(|n| format!("let n{n} = 'a'; n{n} = 'b';\n"))
        .chain(std::iter::once(format!(
            "require('fs').readFileSync({});\n",
            (0..200)
                .map(|n| format!("n{n}"))
                .collect::<Vec<_>>()
                .join(" + ")
        )))
        .collect();
    let _ = read(JavaScript, &javascript);
}

/// Shapes of code that nest `depth` deep, each followed by a statement the
/// reader only reads if it walks past the deep part: a write, in Python.
fn deep_then_write(language: Language, depth: usize) -> Vec<String> {
    match language {
        Python => vec![
            format!(
                "x = 1\nx{}.b()\nopen('/home/me/.bashrc', 'w')",
                ".a".repeat(depth)
            ),
            format!(
                "print({}1{})\nopen('/home/me/.bashrc', 'w')",
                "(".repeat(depth),
                ")".repeat(depth)
            ),
            format!(
                "x = {}1{}\nopen('/home/me/.bashrc', 'w')",
                "[".repeat(depth),
                "]".repeat(depth)
            ),
            format!(
                "x = {}\nopen('/home/me/.bashrc', 'w')",
                "-".repeat(depth) + "1"
            ),
        ],
        JavaScript => vec![
            format!(
                "console.log({}1{})\nconsole.log(2)",
                "(".repeat(depth),
                ")".repeat(depth)
            ),
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
fn code_the_reader_does_not_walk_whole_is_not_understood() {
    for language in [Python, JavaScript] {
        for depth in [10, 100, 199, 200, 201, 300, 399, 400, 401, 450, 800, 2_000] {
            for code in deep_then_write(language, depth) {
                if read(language, &code).deep {
                    assert_eq!(
                        understand(language, &code),
                        Understanding::NotUnderstood,
                        "{language:?}, {depth} deep: {}",
                        &code[..code.len().min(80)]
                    );
                }
            }
        }
        // Some of the deepest shapes are past the reader's walk, so the check
        // is not empty; one it walks whole still finds the write after it.
        let deepest = deep_then_write(language, 2_000);
        assert!(
            deepest.iter().any(|code| read(language, code).deep),
            "{language:?}"
        );
        if language == Python {
            for code in &deepest {
                let reading = read(language, code);
                assert!(
                    reading.deep || !reading.acts.is_empty(),
                    "{}",
                    &code[..code.len().min(80)]
                );
            }
        }
    }
}
