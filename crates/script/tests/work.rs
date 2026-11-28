//! The work judging code costs, held to a count, not to the clock: how many
//! times an act is judged, how many moves the places the code is judged
//! from are built of, and how many bytes of paths are joined, and the work
//! of the parses the guard asks of the code reader for code it stops on. A
//! count is the same on every machine, so this runs in every build. It reads
//! the counts through the crate's `testing` feature, and the reader's
//! through the reader's, which only their own tests turn on.

use milo_guards_core::testing::posix;
use milo_guards_script::testing::{work, MAX_ACT_BYTES, MAX_JOINED, MAX_PLACES};
use milo_guards_script::{Language, Rule, MAX_LEN};

/// The most times one act is judged: from each place, and from each folder
/// a move that may have failed left the code in there.
const PER_ACT: usize = MAX_PLACES * (MAX_PLACES + 1);

/// `os.chdir('a')` repeated `count` times, then a delete.
fn chdirs(count: usize) -> String {
    format!(
        "import os\n{}os.remove('/home/me/x')\n",
        "os.chdir('a')\n".repeat(count)
    )
}

#[test]
fn many_chdirs_build_no_more_places_than_the_limit() {
    let mut largest = 0;
    let mut count = 1;
    while chdirs(count).len() <= MAX_LEN {
        let code = chdirs(count);
        let cost = work(Language::Python, &code, &posix());
        // Past the limit the code is judged from two places, where it
        // started and anywhere, whatever the number of moves.
        if 2 * count > MAX_PLACES {
            assert_eq!(cost.place_moves, 1, "{count} moves");
        } else {
            assert!(
                cost.place_moves <= MAX_PLACES * MAX_PLACES,
                "{count} moves: {cost:?}"
            );
        }
        // Each act is judged from each place, and from each folder a move
        // that may have failed left the code in.
        assert!(cost.judged <= PER_ACT, "{count} moves: {cost:?}");
        let rules: Vec<Rule> = cost.answer.findings().iter().map(|f| f.rule).collect();
        assert!(rules.contains(&Rule::Delete), "{count} moves: {rules:?}");
        largest = largest.max(cost.place_moves);
        count = if count < 16 { count + 1 } else { count * 2 };
    }
    // The longest code was read, and the count stayed within the limit.
    assert!(count > 100, "{count}");
    assert!(largest <= MAX_PLACES * MAX_PLACES, "{largest}");
}

#[test]
fn many_acts_are_each_judged_a_bounded_number_of_times() {
    // Acts after a few moves: each act costs the places, never more.
    for acts in [10, 100, 1_000] {
        let code = format!(
            "import os\nos.chdir('/tmp')\nos.chdir('sub')\n{}",
            "os.remove('x')\n".repeat(acts)
        );
        let cost = work(Language::Python, &code, &posix());
        assert!(cost.judged <= acts * PER_ACT, "{acts}: {cost:?}");
        assert!(
            cost.place_moves <= MAX_PLACES * MAX_PLACES,
            "{acts}: {cost:?}"
        );
    }
}

/// The name of a long folder.
const LONG: &str = "d";

/// Nine moves to a long folder, named once, then `count` deletes: the code
/// is within the length limit, and the folder it moves to is not.
fn long_moves(count: usize) -> String {
    let folder = LONG.repeat(500);
    format!(
        "import os\nd = '{folder}'\n{}{}",
        "os.chdir(d)\n".repeat(9),
        "os.remove(\"x\")\n".repeat(count)
    )
}

#[test]
fn the_bytes_of_paths_joined_for_an_act_are_bounded() {
    // However long the folders are, each act joins at most a fixed number
    // of bytes, so the work grows with the number of acts, not with the
    // length of the folders times it.
    let mut last = None;
    for count in [10, 100] {
        let code = long_moves(count);
        assert!(code.len() <= MAX_LEN, "{count}");
        let cost = work(Language::Python, &code, &posix());
        assert!(
            cost.joined_bytes <= count * MAX_ACT_BYTES,
            "{count}: {}",
            cost.joined_bytes
        );
        if let Some((before, joined)) = last {
            // Ten times the acts join no more than that times the
            // bytes, and a little: linear, not quadratic.
            let times = count / before;
            assert!(
                cost.joined_bytes <= times * joined + MAX_ACT_BYTES,
                "{count}"
            );
        }
        last = Some((count, cost.joined_bytes));
        // A folder spelled past the longest path is one only known when it
        // runs: a delete there is of a path only known when it runs.
        let rules: Vec<Rule> = cost.answer.findings().iter().map(|f| f.rule).collect();
        assert!(!cost.answer.is_safe(), "{count}: {rules:?}");
    }
    const { assert!(9 * 501 > MAX_JOINED) };
}

/// The rules of the code's answer.
fn rules_of(code: &str) -> Vec<Rule> {
    work(Language::Python, code, &posix())
        .answer
        .findings()
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

/// The reasons of the code's `delete` findings.
fn deletes(code: &str) -> Vec<String> {
    work(Language::Python, code, &posix())
        .answer
        .findings()
        .iter()
        .filter(|finding| finding.rule == Rule::Delete)
        .map(|finding| finding.reason.clone())
        .collect()
}

#[test]
fn a_path_joined_past_the_bound_is_only_known_when_it_runs() {
    // Two moves to long folders in the workspace: the folder is under the
    // bound, and a long name joined to it is past it. Read as the bare name
    // from where the code started, it would be a harmless file of the
    // workspace; it is a path only known when it runs.
    let folder = "d".repeat(MAX_JOINED / 2 - 8);
    let name = "x".repeat(64);
    let code = format!("import os\nf = '{folder}'\nos.chdir(f)\nos.chdir(f)\nos.remove('{name}')");
    assert!(code.len() <= MAX_LEN, "{}", code.len());
    assert!(
        2 * folder.len() < MAX_JOINED,
        "the folder is under the bound"
    );
    assert!(
        2 * folder.len() + 2 + name.len() > MAX_JOINED,
        "the path is past it"
    );
    assert!(
        deletes(&code)
            .iter()
            .any(|reason| reason == "deletes a path only known when it runs"),
        "{:?}",
        rules_of(&code)
    );
}

#[test]
fn a_folder_moved_to_past_the_bound_is_only_known_when_it_runs() {
    // Three moves whose folder, together, is past the bound: from there a
    // short name is a path only known when it runs, not a known one.
    let folder = "d".repeat(MAX_JOINED / 3 + 8);
    let code =
        format!("import os\nf = '{folder}'\nos.chdir(f)\nos.chdir(f)\nos.chdir(f)\nos.remove('x')");
    assert!(code.len() <= MAX_LEN, "{}", code.len());
    assert!(
        deletes(&code)
            .iter()
            .any(|reason| reason == "deletes a path only known when it runs"),
        "{:?}",
        rules_of(&code)
    );
    // A program run from there moves to a folder only known when it runs,
    // never to the long folder spelled out.
    let code = format!(
        "import os\nf = '{folder}'\nos.chdir(f)\nos.chdir(f)\nos.chdir(f)\nos.system('ls')"
    );
    let answer = work(Language::Python, &code, &posix()).answer;
    let targets: Vec<&str> = answer
        .findings()
        .iter()
        .filter(|finding| finding.rule == Rule::RunProgram)
        .filter_map(|finding| finding.target.as_deref())
        .collect();
    assert!(
        targets.contains(&"cd -- \"$UNKNOWN\" && sh -c ls"),
        "{targets:?}"
    );
    assert!(
        targets.iter().all(|target| target.len() < MAX_JOINED),
        "{targets:?}"
    );
}

#[test]
fn the_bytes_joined_are_counted_again_for_each_act() {
    // One move to a long folder in the workspace, then many deletes there:
    // each act joins a few kilobytes, well within its own budget, and all of
    // them together far past one act's. Every delete is in the workspace.
    let folder = "d".repeat(2_000);
    let code = format!(
        "import os\nos.chdir('{folder}')\n{}",
        "os.remove('x')\n".repeat(40)
    );
    let cost = work(Language::Python, &code, &posix());
    assert!(cost.joined_bytes > MAX_ACT_BYTES, "{}", cost.joined_bytes);
    assert!(deletes(&code).is_empty(), "{:?}", rules_of(&code));
}

/// `unit` repeated between `head` and `tail` to fill `size` bytes.
fn fit(head: &str, unit: &str, tail: &str, size: usize) -> String {
    let count = (size - head.len() - tail.len()) / unit.len();
    format!("{head}{}{tail}", unit.repeat(count))
}

/// The code the reader does not read, as `(what, language, head, unit,
/// tail, the size in KB from which it is not read)`: code that meets an
/// error, stopped where the recovery starts (a recovery that goes round the
/// same tokens with no end, after statements and with a long name at its
/// end; recoveries that wrap an error never closed; a lexer that goes over
/// the same comments again after an error), and code the reader stops on,
/// past the work it may do for it (Python read two ways at once that never
/// part; a chain of calls named again from each link). Each took seconds,
/// or did not end.
const STOPPED: [(&str, Language, &str, &str, &str, usize); 13] = [
    (
        "a round after statements",
        Language::JavaScript,
        "",
        "x;\n",
        "c(.c(''.(X%'''\"';c(=",
        1,
    ),
    (
        "a round with a long name",
        Language::JavaScript,
        "c(.c(''.(X%'''\"';",
        "c",
        "(=",
        1,
    ),
    (
        "an error wrapped",
        Language::JavaScript,
        "in ",
        "%c=>; ",
        "",
        1,
    ),
    (
        "an error wrapped",
        Language::JavaScript,
        ">",
        "%|&c=",
        "",
        2,
    ),
    ("an error wrapped", Language::Python, "", "if:X@*\\", "", 2),
    (
        "two ways that never part",
        Language::Python,
        "",
        "+*a",
        "",
        2,
    ),
    (
        "comments after an error",
        Language::Python,
        "!=]0x ]",
        "\n#",
        "",
        16,
    ),
    (
        "comments after an error",
        Language::JavaScript,
        "/*xfrom  @catch",
        "@/*== ",
        "",
        16,
    ),
    ("a chain of calls", Language::JavaScript, "x", "()", "", 8),
    ("a chain of calls", Language::Python, "x", "()", "", 8),
    // Ruby: code that meets an error, and the shapes that cost most of the
    // grammar's two ways, read whole (a chain of members, a call and an
    // index told from a space, command calls in command calls).
    (
        "an error after statements",
        Language::Ruby,
        "",
        "x\n",
        "x = (\n",
        1,
    ),
    ("a chain of members", Language::Ruby, "x", ".a", "", 64),
    (
        "two ways that never part",
        Language::Ruby,
        "",
        "a [b];",
        "",
        64,
    ),
];

/// The bounds of the one budget the readings of code of `len` bytes share,
/// written out as the reader's `tests/parse_budget.rs` writes them, with
/// what a count may go past one before it is seen.
fn within_budget(len: usize, work: milo_guards_code::testing::Work, at: &str) {
    let bounds = [
        ("reports", work.reports, len / 6 + 64 + 1),
        ("quiet", work.quiet, 64 + 1),
        ("tangled", work.tangled, 384 + 16),
        ("selected", work.selected, 1024 + 4096),
        ("handed", work.handed, len * 64 + (24 << 20) + 259 * 12),
        ("walked", work.walked, len * 16 + (64 << 10) + len),
    ];
    for (what, count, most) in bounds {
        assert!(count <= most, "{at}: {what} {count}, over {most}: {work:?}");
    }
}

#[test]
fn code_the_reader_stops_on_is_unreadable_after_bounded_work() {
    use milo_guards_core::testing::windows;
    for (what, language, head, unit, tail, from) in STOPPED {
        // Each size to the length limit, 3 KiB; a shape the reader stops on
        // only past it is not read for its length.
        for kb in [1, 2, 3] {
            let code = fit(head, unit, tail, (kb * 1024).min(MAX_LEN));
            let at = format!("{what} ({language:?}), {kb} KB");
            for paths in [posix(), windows()] {
                let cost = work(language, &code, &paths);
                let reader = cost.reader.unwrap_or_else(|| panic!("{at}: not read"));
                // Every reading the guard makes of the code, and of the code
                // inside it, within the one budget.
                within_budget(code.len(), reader, &at);
                assert!(!cost.answer.is_safe(), "{at}");
                let not_read = reader.stopped || reader.errors > 0;
                if kb >= from {
                    assert!(not_read, "{at}: {reader:?}");
                }
                if not_read {
                    let unreadable: Vec<&str> = cost
                        .answer
                        .findings()
                        .iter()
                        .filter(|f| f.rule == Rule::Unreadable)
                        .map(|f| f.reason.as_str())
                        .collect();
                    // `does not parse` for code that meets an error; `takes
                    // too long to read` for code the reader stops on, unless
                    // it was found to nest too deeply first.
                    assert!(
                        unreadable.iter().any(|why| matches!(
                            *why,
                            "takes too long to read"
                                | "does not parse"
                                | "nests too deeply to read"
                        )),
                        "{at}: {:?}",
                        cost.answer
                    );
                }
            }
        }
    }
}

#[test]
fn code_inside_code_is_read_within_the_budget_of_the_code() {
    // The code `eval` and `exec` run, nested four deep, is read within the
    // one budget of the whole: nesting does not multiply the work.
    use milo_guards_core::testing::windows;
    let rows: [(Language, &str, String); 4] = [
        (
            Language::JavaScript,
            "eval",
            fit("/*xfrom  @catch", "@/*== ", "", MAX_LEN / 4),
        ),
        (
            Language::Python,
            "exec",
            fit("!=]0x ]", "\n#", "", MAX_LEN / 4),
        ),
        (
            Language::Python,
            "exec",
            "print(1); x = [1, 2, 3]\n".repeat(MAX_LEN / 4 / 24),
        ),
        (Language::Ruby, "eval", fit("x", ".a", "", MAX_LEN / 4)),
    ];
    for (language, runs, code) in rows {
        let mut code = code;
        for depth in 0..=4 {
            if code.len() > MAX_LEN {
                break;
            }
            let at = format!("{language:?} {depth} deep");
            for paths in [posix(), windows()] {
                let cost = work(language, &code, &paths);
                let reader = cost.reader.unwrap_or_else(|| panic!("{at}: not read"));
                within_budget(code.len(), reader, &at);
                // Code that runs code is not read whole.
                if depth > 0 || reader.stopped {
                    assert!(!cost.answer.is_safe(), "{at}");
                }
            }
            code = format!("{runs}({code:?})");
        }
    }
}

#[test]
fn pieces_of_code_each_read_whole_are_held_together() {
    // Python that runs piece after piece of code tree-sitter reads two ways
    // at once (versions merged at each token, built at the end way by way):
    // each piece has stars where Python allows none, which the stars
    // counted on the bytes of the code around them see into, so the code
    // is not read before any piece is parsed. Both are held to the reports
    // of the code.
    use milo_guards_core::testing::windows;
    for (unit, count, pieces) in [("+*a", 200, 4), ("if/*a", 100, 5)] {
        let code = (0..pieces)
            .map(|piece| format!("exec('{}#{piece}')", unit.repeat(count)))
            .collect::<Vec<_>>()
            .join("\n");
        let at = format!("{pieces} pieces of {unit:?}");
        assert!(code.len() <= MAX_LEN, "{at}");
        for paths in [posix(), windows()] {
            let cost = work(Language::Python, &code, &paths);
            let reader = cost.reader.unwrap_or_else(|| panic!("{at}: not read"));
            within_budget(code.len(), reader, &at);
            assert!(reader.stopped && reader.reports == 0, "{at}: {reader:?}");
            assert!(!cost.answer.is_safe(), "{at}");
        }
    }
}
