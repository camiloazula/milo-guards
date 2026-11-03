//! What the reader of inline code found, in the shell's own terms: a delete
//! is `rm -rf PATH`, a move `mv`, a command line a script `sh -c` reads, a
//! literal argument list a unit. The code itself is read by
//! `milo-guards-code`; nothing here knows a language.

use milo_guards_code::{self as reader, Act, Language};

use super::{shorten, Code};
use crate::launch;
use crate::said::Said;
use crate::unit::{self, Arg, Split, Unit};
use crate::{Finding, Rule, Shell};

/// A value of the code as the shell's rules take an argument.
fn arg(value: reader::Arg) -> Arg {
    match value {
        reader::Arg::Known(text) => Arg::Known(text),
        reader::Arg::Unknown(text) => Arg::Unknown(text),
        // A path somewhere in a folder reads as a word with an expansion at
        // its end: `'/home/me/.ssh/id_' + n` as `~/.ssh/$n` is.
        reader::Arg::Below { folder, source } => Arg::Template {
            text: format!("{folder}{}", crate::posix::OPAQUE),
            source: source.into(),
            runs: false,
        },
    }
}

/// Why a program started with an environment the code sets is `unknown`.
const ENVIRONED: &str = "starts a program with an environment set in the code";

/// Read `pieces` of code in `language`, run `depth` levels deep, from the
/// directory the interpreter is told to work in, and add what they do to the
/// split.
pub(crate) fn apply_all(split: &mut Split, language: Language, code: &Code, depth: usize) {
    let outer = split.dir_snapshot();
    match &code.dir {
        Some(dir @ Arg::Known(_)) => run(split, "cd", vec![flag("--"), dir.clone()], depth),
        Some(other) => split.problem(
            Rule::Unknown,
            "runs code from a directory only known when it runs",
            Some(other.text()),
        ),
        None => {}
    }
    if code.input {
        split.problem(
            Rule::Unknown,
            "reads code from its input after its own",
            None,
        );
    }
    for piece in &code.pieces {
        match piece {
            Arg::Known(text) => apply(split, language, text, depth, false),
            other => split.problem(
                Rule::Unknown,
                "runs code only known when it runs",
                Some(other.text()),
            ),
        }
    }
    // Nothing found is only safe for code read whole: written whole on the
    // line, with no option and no environment around the interpreter, and
    // nothing in it outside the subset (see `milo_guards_code::understand`).
    let read = match code.pieces.as_slice() {
        [Arg::Known(text)] if code.plain && !split.environment_set() => {
            let understood = if code.python2 {
                reader::understand_python2(text)
            } else {
                reader::understand(language, text)
            };
            match understood {
                reader::Understanding::NotUnderstood => None,
                reader::Understanding::Understood { imports } => Some(imports),
            }
        }
        _ => None,
    };
    match read {
        None => split.unread_code(code.pieces.first().map_or("", Arg::text)),
        // Python code looks in the folder it runs in first (an import, but
        // also a traceback or a codec), so it is only read whole there when
        // that folder is the workspace's, which is judged with the
        // directories.
        Some(true) => split.imports(code.pieces.first().map_or("", Arg::text)),
        Some(false) => {}
    }
    split.restore_dir(outer);
}

/// Read code an interpreter takes from its input (a here-document or
/// here-string), run `depth` levels deep, and add what it does to the split.
/// What it finds is kept, but code that is not written whole on the line is
/// never read whole, so a line it finds nothing in is `unknown`. Python reads
/// its input as bytes, and honours a coding declaration in the first two
/// lines that decodes them to other text than the reader sees: such code is
/// not read.
pub(crate) fn apply_input(split: &mut Split, language: Language, code: &str, depth: usize) {
    split.unread_code(code);
    if language == Language::Python && reader::declares_other_encoding(code) {
        split.problem(
            Rule::Unknown,
            "runs code the guard does not read",
            Some(&shorten(code)),
        );
    }
    apply(split, language, code, depth, false);
}

/// Read `code` in `language`, run `depth` levels deep, and add what it does
/// to the split. `unplaced` is whether the code starts in a directory only
/// known when it runs (it is a piece of nested code run after a `chdir` the
/// reader cannot place).
fn apply(split: &mut Split, language: Language, code: &str, depth: usize, unplaced: bool) {
    if !unit::within_limits(split, code, depth) {
        return;
    }
    let reading = reader::read(language, code);
    if reading.deep {
        split.problem(Rule::Unreadable, "nests too deeply to read", None);
    }
    // A `chdir` in the code moves its own process, not the line.
    let outer = split.dir_snapshot();
    let places = places(&reading.acts, depth);
    if places.len() == 1 {
        for act in reading.acts {
            perform(split, act, depth, unplaced);
        }
    } else {
        // The code can be in any of these places when it runs an act: a
        // function is defined before the `chdir` and called after it, a loop's
        // second pass follows the first pass's `chdir`, an action registered
        // for later runs when the code ends. So each act is judged from
        // each place, and from nowhere known where that cannot be told.
        for act in reading.acts {
            if matches!(act, Act::Chdir(_)) {
                // Only where it goes is read here; the places hold the rest.
                perform(split, act, depth, unplaced);
                split.restore_dir(outer.clone());
                continue;
            }
            for place in &places {
                for dir in place {
                    run(split, "cd", vec![flag("--"), dir.clone()], depth);
                }
                let unplaced = after(unplaced, place);
                perform(split, act.clone(), depth, unplaced);
                split.restore_dir(outer.clone());
            }
        }
    }
    split.restore_dir(outer);
}

/// Whether nested code (`exec("…")`, `eval("…")`), run `depth` levels deep,
/// may change the directory: it is read, with its own language and at any
/// depth, and holds a `chdir`. Code the reader cannot follow, or that is too
/// long or too deep to read, may.
fn changes_directory(language: Language, code: &str, depth: usize) -> bool {
    if depth > unit::MAX_DEPTH || code.len() > unit::MAX_LEN {
        return true;
    }
    let reading = reader::read(language, code);
    reading.deep
        || reading.acts.iter().any(|act| match act {
            Act::Chdir(_) | Act::Unread(_) => true,
            Act::Code(language, text) => changes_directory(*language, text, depth + 1),
            _ => false,
        })
}

/// The most places code is judged from: past it, from none known.
const MAX_PLACES: usize = 12;

/// Where the code may be when it runs an act: each is the `cd`s that lead
/// there from where the code starts. Just the start (one place, no `cd`s)
/// when the code never changes directory. Else the start, each `chdir`'s
/// target and the places the `chdir`s lead to one after another as they are
/// written: a target that is an absolute folder is where the code is, and one
/// below where it was (`sub`) is another folder below the start, so those
/// places hold wherever the code can be. When the targets mix the two, one
/// goes up (`..`) or is only known when it runs, or a nested piece of code
/// holds a `chdir` (read, not searched for, at any depth) or cannot be read,
/// the code may be anywhere, and a relative path is only known when it runs.
fn places(acts: &[Act], depth: usize) -> Vec<Vec<Arg>> {
    let mut targets = Vec::new();
    let mut hidden = false;
    for act in acts {
        match act {
            Act::Chdir(target) => targets.push(arg(target.clone())),
            Act::Code(language, text) => {
                hidden |= changes_directory(*language, text, depth + 1);
            }
            _ => {}
        }
    }
    if targets.is_empty() && !hidden {
        return vec![Vec::new()];
    }
    let (mut absolute, mut below, mut unknown) = (false, false, hidden);
    for target in &targets {
        match target.known() {
            Some(dir) if dir.starts_with(['/', '~']) => absolute = true,
            Some(dir) if !dir.split('/').any(|part| part == "..") => below = true,
            _ => unknown = true,
        }
    }
    let mut places = vec![Vec::new()];
    for (at, target) in targets.iter().enumerate() {
        places.push(vec![target.clone()]);
        if at > 0 {
            places.push(targets[..=at].to_vec());
        }
    }
    if unknown || (absolute && below) || places.len() > MAX_PLACES {
        places = vec![Vec::new(), vec![Arg::Unknown("a directory".to_string())]];
    }
    places
}

/// Add what one act does to the split, as the shell command that does the
/// same.
///
/// `unplaced` is whether the code is in a directory only known when it runs:
/// a path that counts from there, and a program or script run from there, is
/// only known when it runs too, so each is `unknown` (a delete or a write is
/// judged as the shell judges one from such a place, and a path of its own
/// that is absolute or in the home directory is judged as it is anywhere).
fn perform(split: &mut Split, act: Act, depth: usize, unplaced: bool) {
    match act {
        Act::Remove(path) => run(split, "rm", vec![flag("-rf"), flag("--"), arg(path)], depth),
        Act::Write(path) => split.write(Shell::Posix, arg(path)),
        Act::Read(path) => {
            let path = arg(path);
            let doubt = read_doubt(&path, unplaced);
            opened(split, "cat", vec![flag("--")], path, doubt, depth);
        }
        Act::ReadTree(path) => {
            let path = arg(path);
            let doubt = read_doubt(&path, unplaced);
            let args = vec![flag("-r"), flag("--"), Arg::Known("x".to_string())];
            opened(split, "grep", args, path, doubt, depth);
        }
        Act::Opaque(path) => opened(
            split,
            "cat",
            vec![flag("--")],
            arg(path),
            Some(HANDED),
            depth,
        ),
        Act::Move { from, to } => run(split, "mv", vec![flag("--"), arg(from), arg(to)], depth),
        Act::Link { target, link } => {
            run(
                split,
                "ln",
                vec![flag("-s"), flag("--"), arg(target), arg(link)],
                depth,
            );
        }
        Act::Chmod { path, mode } => {
            run(
                split,
                "chmod",
                vec![flag("--"), arg(mode), arg(path)],
                depth,
            );
        }
        Act::Chown(path) => run(
            split,
            "chown",
            vec![flag("--"), Arg::Known("user".to_string()), arg(path)],
            depth,
        ),
        Act::Chdir(path) => run(split, "cd", vec![flag("--"), arg(path)], depth),
        Act::In(dir, acts) => {
            let dir = arg(dir);
            let outer = split.dir_snapshot();
            let unplaced = after(unplaced, std::slice::from_ref(&dir));
            run(split, "cd", vec![flag("--"), dir], depth);
            for act in acts {
                perform(split, act, depth, unplaced);
            }
            split.restore_dir(outer);
        }
        Act::Script(script) => {
            let script = arg(script);
            if unplaced {
                split.problem(Rule::Unknown, UNPLACED_RUN, Some(script.text()));
            }
            run(split, "sh", vec![flag("-c"), script], depth);
        }
        Act::Program(words) => {
            let mut words: Vec<Arg> = words.into_iter().map(arg).collect();
            if !words.is_empty() {
                if unplaced {
                    let shown = words.iter().map(Arg::text).collect::<Vec<_>>().join(" ");
                    split.problem(Rule::Unknown, UNPLACED_RUN, Some(&shown));
                }
                let program = words.remove(0);
                // A word only known when the code runs, or known in part, is
                // a word the guard cannot judge: the line is `unknown`, unless
                // the unit finds a key in the part that is known.
                let finding = words
                    .iter()
                    .find(|word| word.known().is_none())
                    .map(|word| Finding {
                        rule: Rule::Unknown,
                        reason: UNKNOWN_WORD.to_string(),
                        target: Some(word.text().to_string()),
                        instead: None,
                    });
                let name = program.known().map(str::to_string);
                let before = split.units.len();
                launch::add(split, Unit::new(Shell::Posix, program, words, None), depth);
                if let Some(finding) = finding {
                    let unit = split.units.get(before..).and_then(|added| {
                        added
                            .iter()
                            .position(|unit| unit.key().is_some() && unit.key() == name)
                    });
                    match unit {
                        Some(at) => {
                            split.loose.insert(before + at, finding);
                        }
                        None => split.findings.push(finding),
                    }
                }
            }
        }
        Act::Code(language, text) => apply(split, language, &text, depth + 1, unplaced),
        Act::Unread(code) => split.problem(
            Rule::Unknown,
            "runs code the guard does not read",
            Some(&code),
        ),
        Act::Downloaded(code) => {
            split.problem(
                Rule::RunDownloaded,
                Said::instead(
                    "runs code it downloads",
                    "download the code to a file and read it first",
                ),
                Some(&code),
            );
            split.problem(
                Rule::Unknown,
                "runs code the guard does not read",
                Some(&code),
            );
        }
        Act::Loads(code) => split.problem(
            Rule::Unknown,
            "loads code from outside the workspace",
            Some(&code),
        ),
        Act::Environment => {}
        Act::Started(acts) => {
            split.problem(Rule::Unknown, ENVIRONED, None);
            for act in acts {
                perform(split, act, depth, unplaced);
            }
        }
    }
}

/// Why a path that counts from a directory only known when the code runs is
/// `unknown`.
const UNPLACED_READ: &str = "opens a file from a directory only known when the code runs";

/// Why a program started with a word only known when the code runs, or known
/// in part, is `unknown`.
const UNKNOWN_WORD: &str = "runs a program with an argument only known when the code runs";

/// Why a program or script run from a directory only known when the code
/// runs is `unknown`.
const UNPLACED_RUN: &str = "runs from a directory only known when the code runs";

/// Whether the code is still in a directory only known when it runs after the
/// `cd`s of `dirs` from a start that was (`unplaced`) or was not: an absolute
/// folder places it, one below where it was or above it (`..`) keeps it
/// where it was, and one only known when it runs leaves it unplaced.
fn after(unplaced: bool, dirs: &[Arg]) -> bool {
    dirs.iter().fold(unplaced, |state, dir| match dir.known() {
        Some(text) if text.starts_with(['/', '~']) => false,
        Some(_) => state,
        None => true,
    })
}

/// Why a read of `path` is `unknown`, if it is: the path is only known when
/// the code runs, or known in part, or counts from a directory only known
/// when it runs (`unplaced`). A path of the home directory or an absolute one
/// is the same wherever the code is, and so is a key it names (which the unit
/// finds and says as `read_secret`).
fn read_doubt(path: &Arg, unplaced: bool) -> Option<&'static str> {
    match path.known() {
        None => Some(PARTIAL),
        Some(text) if unplaced && !text.starts_with(['/', '~']) => Some(UNPLACED_READ),
        Some(_) => None,
    }
}

fn flag(text: &str) -> Arg {
    Arg::Known(text.to_string())
}

/// Why a read of a file is `unknown`: the path is only known when the code
/// runs, or in part.
const PARTIAL: &str = "opens a file whose path is only known when the code runs";

/// Why a path handed to a call the reader does not know is `unknown`.
const HANDED: &str = "gives a path to a call the guard does not read";

/// Add the unit `program args… path`, which opens the file the code names.
/// Only a path the code gives whole is a path the guard knows. One only
/// known when the code runs, or known in part, is a read of a file the guard
/// cannot name: the line is `unknown` for the `doubt` it carries, unless the
/// part of the path it does know already lies in a place that holds a key,
/// which the unit finds and says (`read_secret`). Deletes and writes fail
/// closed the same way.
fn opened(
    split: &mut Split,
    program: &str,
    mut args: Vec<Arg>,
    path: Arg,
    doubt: Option<&str>,
    depth: usize,
) {
    let shown = path.text().to_string();
    args.push(path);
    let before = split.units.len();
    run(split, program, args, depth);
    let Some(reason) = doubt else {
        return;
    };
    let finding = Finding {
        rule: Rule::Unknown,
        reason: reason.to_string(),
        target: Some(shown),
        instead: None,
    };
    let unit = split.units.get(before..).and_then(|added| {
        added
            .iter()
            .position(|unit| unit.key().as_deref() == Some(program))
    });
    match unit {
        Some(at) => {
            split.loose.insert(before + at, finding);
        }
        // The program was not added as itself: nothing says what the file is.
        None => split.findings.push(finding),
    }
}

/// Add the unit `program args…`, as if the line had run it.
fn run(split: &mut Split, program: &str, args: Vec<Arg>, depth: usize) {
    launch::add(
        split,
        Unit::new(Shell::Posix, flag(program), args, None),
        depth,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reader holds code to the limits the shell holds a line to, and
    /// shows the start of code the way the shell does (two copies, one in
    /// each crate, because the shell shows it with or without the reader).
    #[test]
    fn the_reader_and_the_shell_agree_on_the_limits_and_on_the_start_of_code() {
        assert_eq!(reader::MAX_DEPTH, unit::MAX_DEPTH);
        assert_eq!(reader::MAX_TREE_DEPTH, unit::MAX_TREE_DEPTH);
        assert_eq!(reader::MAX_LEN, unit::MAX_LEN);
        for code in [
            "if (",
            "  if ( second line\nthird",
            &format!("if ( {}", "x".repeat(200)),
            &format!("if ( {}\nmore", "é".repeat(80)),
            "if (\u{3000}",
        ] {
            let acts = reader::read(Language::JavaScript, code).acts;
            let [Act::Unread(shown)] = acts.as_slice() else {
                panic!("{code:?}: {acts:?}");
            };
            assert_eq!(*shown, shorten(code), "{code:?}");
        }
    }
}
