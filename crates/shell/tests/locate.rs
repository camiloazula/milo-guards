//! Where in the line each finding is, as `locate` says: its cases in
//! `tests/cases/locate.cases` (a word as written, a redirect, nested code,
//! the line as the caller passed it, a word that reads the same as the
//! target but is not what the rule judged), and what a case line cannot
//! hold: that the range of every finding of every case of every case file
//! moves with what is put in front of its line, byte for byte, also when
//! what is put in front holds the very word a finding covers. Every case of
//! every case file is also held to `locate`'s agreement with `classify` and
//! to ranges that read as their targets, in `tests/common` (`misplaced`).

mod common;

use common::cases::format;
use milo_guards_shell::{locate, Covers, Located, Rule, Shell};

#[test]
fn every_case_holds() {
    common::cases::check("locate");
}

/// What may be put in front of a line of `shell` without changing what it
/// finds: white space, and a command that does nothing with a word of
/// characters of two, three and four bytes.
fn fronts(shell: Shell) -> [&'static str; 2] {
    match shell {
        Shell::Posix => ["  \t ", ": 'é€𝄞' ; "],
        Shell::PowerShell => ["  \t ", "$null = 'é€𝄞'; "],
        _ => ["  \t ", "echo é€𝄞 & "],
    }
}

/// What is wrong with `moved` (see [`moved_wrong`]), holding only the
/// findings that cover their target to it unless `all`.
fn moved_wrong_of(
    at: &[Located],
    moved: &[Located],
    front: &str,
    len: usize,
    all: bool,
) -> Option<String> {
    if all {
        return moved_wrong(at, moved, front, len);
    }
    let (at, moved): (Vec<Located>, Vec<Located>) = at
        .iter()
        .zip(moved)
        .filter(|(at, _)| at.covers == Covers::Target)
        .map(|(at, moved)| (at.clone(), moved.clone()))
        .unzip();
    moved_wrong(&at, &moved, front, len)
}

/// Whether `at` and `moved`, what `locate` gives a line and the line with
/// something put in front, give the same findings.
fn same_findings(at: &[Located], moved: &[Located]) -> bool {
    at.len() == moved.len()
        && at
            .iter()
            .zip(moved)
            .all(|(at, moved)| at.finding == moved.finding)
}

/// What is wrong with `moved`, what `locate` gives a line with `front` put
/// in front of it, against `at`, what it gives the line, `len` bytes long,
/// when they give the same findings: each is at the same bytes, `front.len()`
/// on, and covers the same; a range of the whole line may be of the whole
/// new line, and one that covers the line is.
fn moved_wrong(at: &[Located], moved: &[Located], front: &str, len: usize) -> Option<String> {
    at.iter().zip(moved).find_map(|(at, moved)| {
        let want = if at.covers == Covers::Line {
            0..front.len() + len
        } else {
            at.range.start + front.len()..at.range.end + front.len()
        };
        // A part placed at the whole line (a script the guard read from no
        // one word) is placed at the whole of the new one.
        let whole = at.range == (0..len) && moved.range == (0..front.len() + len);
        // A front the line's grammar cannot read on with it (a value as a
        // later stage of a PowerShell pipeline) may leave a word as no more
        // than the part that holds the target: still the same word.
        let widened = at.covers == Covers::Target && moved.covers == Covers::Part;
        ((moved.range != want && !whole) || (moved.covers != at.covers && !widened)).then(|| {
            format!(
                "{:?} was at {:?} ({:?}), and is at {:?} ({:?})",
                at.finding, at.range, at.covers, moved.range, moved.covers
            )
        })
    })
}

/// A command that prints `word`, the word a finding covers, quoted so that
/// nothing in it runs or expands, to put in front of a line of `shell`: it
/// reads the same as the target, so a range the guard found by searching
/// for a word that reads as the target would move to it. Each with whether
/// it leaves the line's statements as they were (`;`), so that every range
/// moves with it; after `&&` or `|` the line is grouped with it, and only a
/// target's range is held to move.
fn fronts_with(shell: Shell, word: &str) -> Vec<(String, bool)> {
    match shell {
        Shell::Posix => {
            let quoted = format!("'{}'", word.replace('\'', r"'\''"));
            vec![
                (format!("echo {quoted} ; "), true),
                (format!("echo {quoted} && "), false),
                (format!("echo {quoted} | "), false),
            ]
        }
        Shell::PowerShell => {
            let quoted = format!("'{}'", word.replace('\'', "''"));
            vec![
                (format!("Write-Output {quoted}; "), true),
                (format!("Write-Output {quoted} | "), false),
            ]
        }
        _ => vec![
            (format!("echo {word} & "), true),
            (format!("echo {word} | "), false),
        ],
    }
}

#[test]
fn every_range_moves_with_what_is_put_in_front_of_its_line() {
    let mut wrong = Vec::new();
    let mut moved = 0;
    for name in format::names() {
        for case in common::cases::load(&name) {
            let at = locate(&case.line, case.shell, &case.paths);
            if at.is_empty() {
                continue;
            }
            // The words the findings cover, each once.
            let mut words: Vec<&str> = at
                .iter()
                .filter(|at| at.covers == Covers::Target)
                .filter_map(|at| case.line.get(at.range.clone()))
                .filter(|word| !word.contains(['\n', '\r']))
                .collect();
            words.sort_unstable();
            words.dedup();
            // A front that is risky on its own may give a finding of the
            // line first (`echo $((x))`): only harmless ones are put in.
            let harmless = |(front, _): &(String, bool)| {
                let alone = front.trim_end_matches([' ', ';', '&', '|']);
                locate(alone, case.shell, &case.paths).is_empty()
            };
            let fronts: Vec<(String, bool)> = fronts(case.shell)
                .iter()
                .map(|front| (front.to_string(), true))
                .chain(
                    words
                        .iter()
                        .flat_map(|word| fronts_with(case.shell, word))
                        .filter(harmless),
                )
                .collect();
            for (front, all) in &fronts {
                let line = format!("{front}{}", case.line);
                let shifted = locate(&line, case.shell, &case.paths);
                if !same_findings(&at, &shifted) {
                    continue;
                }
                moved += 1;
                if let Some(why) = moved_wrong_of(&at, &shifted, front, case.line.len(), *all) {
                    wrong.push(format!("{}: {front:?} in front: {why}", case.at));
                }
            }
        }
    }
    assert!(moved > 20_000, "only {moved} lines moved");
    assert!(
        wrong.is_empty(),
        "{} ranges did not move:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn a_line_too_long_to_read_is_located_at_the_whole_line() {
    for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
        let line = "echo x; ".repeat(10_000);
        let paths = if shell == Shell::Posix {
            common::posix()
        } else {
            common::windows()
        };
        let found = locate(&line, shell, &paths);
        let unreadable = found
            .iter()
            .find(|at| at.finding.rule == Rule::Unreadable)
            .map(|at| (at.range.clone(), at.covers));
        assert_eq!(unreadable, Some((0..line.len(), Covers::Line)), "{shell:?}");
    }
}

#[test]
fn every_finding_of_an_empty_line_is_at_its_start() {
    for shell in [Shell::Posix, Shell::PowerShell, Shell::Cmd] {
        let paths = common::posix();
        assert!(locate("", shell, &paths)
            .iter()
            .all(|at| at.range == (0..0) && at.covers == Covers::Line));
    }
}
