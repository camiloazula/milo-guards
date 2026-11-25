//! The work judging code costs, held to a count, not to the clock: how many
//! times an act is judged, how many moves the places the code is judged
//! from are built of, and how many bytes of paths are joined. A count is the same on every machine, so this runs in
//! every build. It reads the counts through the crate's `testing` feature,
//! which only its own tests turn on.

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
    assert!(count > 1_000, "{count}");
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

/// Six moves to long folders, then `count` deletes.
fn long_moves(count: usize) -> String {
    let moves: String = (0..6)
        .map(|at| format!("os.chdir('{}')\n", format!("d{at}").repeat(700)))
        .collect::<Vec<_>>()
        .concat();
    format!("import os\n{moves}{}", "os.remove(\"x\")\n".repeat(count))
}

#[test]
fn the_bytes_of_paths_joined_for_an_act_are_bounded() {
    // However long the folders are, each act joins at most a fixed number
    // of bytes, so the work grows with the number of acts, not with the
    // length of the folders times it.
    let mut last = None;
    for count in [40, 400] {
        let code = long_moves(count);
        assert!(code.len() <= MAX_LEN, "{count}");
        let cost = work(Language::Python, &code, &posix());
        assert!(
            cost.joined_bytes <= count * MAX_ACT_BYTES,
            "{count}: {}",
            cost.joined_bytes
        );
        if let Some((before, joined)) = last {
            // Ten or three times the acts join no more than that times the
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
    const { assert!(6 * 1_400 > MAX_JOINED) };
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
    let code =
        format!("import os\nos.chdir('{folder}')\nos.chdir('{folder}')\nos.remove('{name}')");
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
    let code = format!(
        "import os\nos.chdir('{folder}')\nos.chdir('{folder}')\nos.chdir('{folder}')\nos.remove('x')"
    );
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
        "import os\nos.chdir('{folder}')\nos.chdir('{folder}')\nos.chdir('{folder}')\nos.system('ls')"
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
