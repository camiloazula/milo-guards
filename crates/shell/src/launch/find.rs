//! `find`: the places it searches, what its filters can match, and the
//! programs its `-exec` runs for each file found.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

mod search;

use super::{add, MAX_WRAPPERS};
use crate::unit::{option_start, Arg, Split, Unit};
use crate::{Rule, Shell};
use search::{git_inside, Reach, Search};

/// The most work `find -exec` may be read to do for one line, in all the
/// `find`s inside `find`s, counted in bytes of the program and arguments
/// built to hand on, `{}` replaced: each level runs the program once for
/// each place it searches, so the work could grow as fast as the line is
/// long, or faster. Arguments would not do: one holding a thousand `{}` is
/// a thousand times the bytes of one that holds none.
const MAX_EXEC_WORK: usize = 1024 * 1024;

/// `find`'s `-exec`, `-execdir`, `-ok` and `-okdir` run a program for each
/// file found: each becomes a unit, with `{}` a file under each place it
/// searches.
pub(super) fn find_exec(split: &mut Split, unit: &Unit, depth: usize) {
    // A `find` that runs a `find` that runs a `find` ... would be walked as
    // deep as the line is long.
    if split.find_depth >= MAX_WRAPPERS {
        split.problem(
            Rule::Unreadable,
            "wraps a program in too many others to read",
            None,
        );
        return;
    }
    split.find_depth += 1;
    run_each(split, unit, depth);
    split.find_depth -= 1;
}

/// [`find_exec`], once it is known how deep it is.
fn run_each(split: &mut Split, unit: &Unit, depth: usize) {
    let targets = find_targets(&unit.args);
    let mut iter = unit.args.iter();
    while let Some(arg) = iter.next() {
        if !matches!(arg.known(), Some("-exec" | "-execdir" | "-ok" | "-okdir")) {
            continue;
        }
        let command: Vec<&Arg> = iter
            .by_ref()
            .take_while(|arg| !matches!(arg.known(), Some(";" | "+")))
            .collect();
        let Some((program, rest)) = command.split_first() else {
            continue;
        };
        let placeholder = rest
            .iter()
            .any(|arg| arg.known().is_some_and(|text| text.contains("{}")));
        // What each argument weighs before the path is put in for its `{}`.
        let shape: Vec<(usize, usize)> = rest
            .iter()
            .map(|arg| {
                let holes = arg.known().map_or(0, |text| text.matches("{}").count());
                (arg.text().len() + 1, holes)
            })
            .collect();
        let fixed = program.text().len() + 1 + shape.iter().map(|(bytes, _)| bytes).sum::<usize>();
        let holes: usize = shape.iter().map(|(_, holes)| holes).sum();
        for target in &targets {
            // The path goes in for each `{}`, or on the end when there is none.
            let path = target.text().len();
            let built = fixed + holes * path + if placeholder { 0 } else { path + 1 };
            split.find_work = split.find_work.saturating_add(built + 1);
            if split.find_work > MAX_EXEC_WORK {
                split.problem(Rule::Unreadable, "runs too many programs to read", None);
                return;
            }
            let mut args: Vec<Arg> = rest
                .iter()
                .map(|arg| match (arg.known(), target) {
                    (Some(text), Arg::Known(path)) if text.contains("{}") => {
                        Arg::Known(text.replace("{}", path))
                    }
                    (Some(text), _) if text.contains("{}") => Arg::Unknown(text.to_string()),
                    _ => (*arg).clone(),
                })
                .collect();
            // `-exec rm \;` with no `{}` passes the file as the last argument.
            if !placeholder {
                args.push(target.clone());
            }
            let mut found = Unit::new(Shell::Posix, (*program).clone(), args, None);
            found.wrappers.push("find".to_string());
            found.startup = Rc::clone(&unit.startup);
            add(split, found, depth);
        }
    }
}

/// The tests of `find` whose next argument is a pattern, a number or a
/// type.
pub(crate) const FIND_VALUED: [&str; 28] = [
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-lname",
    "-ilname",
    "-regex",
    "-iregex",
    "-type",
    "-xtype",
    "-newer",
    "-mtime",
    "-mmin",
    "-atime",
    "-amin",
    "-ctime",
    "-cmin",
    "-size",
    "-perm",
    "-user",
    "-group",
    "-maxdepth",
    "-mindepth",
    "-links",
    "-samefile",
    "-regextype",
];

/// Whether an argument of `find`'s expression, after the places it searches,
/// is only known when it runs where only a test or an action can stand: not
/// the value of a test or an action that takes one (`-name "$p"`), nor a
/// word of the command an `-exec` runs. It may be `-delete`.
pub(crate) fn find_unread_primary(args: &[Arg]) -> bool {
    /// Actions and tests beside [`FIND_VALUED`] that take one value.
    const ALSO_VALUED: [&str; 10] = [
        "-printf", "-fprint", "-fprint0", "-fls", "-inum", "-uid", "-gid", "-fstype", "-used",
        "-context",
    ];
    let at = options_end(args);
    let after_starts = args
        .get(at..)
        .unwrap_or_default()
        .iter()
        .position(starts_expression);
    let Some(first) = after_starts else {
        return false;
    };
    let mut iter = args[at + first..].iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            None => return true,
            Some(text) if FIND_VALUED.contains(&text) || ALSO_VALUED.contains(&text) => {
                iter.next();
            }
            Some("-fprintf") => {
                iter.next();
                iter.next();
            }
            Some("-exec" | "-execdir" | "-ok" | "-okdir") => {
                for word in iter.by_ref() {
                    if matches!(word.known(), Some(";" | "+")) {
                        break;
                    }
                }
            }
            Some(text) if text.starts_with("-newer") => {
                iter.next();
            }
            Some(_) => {}
        }
    }
    false
}

/// Whether an argument of `find` starts its expression, after the places
/// it searches: a test, an action, `(` or `!`, written or only known when
/// it runs and starting with `-` (`"-$A"`, see [`option_start`]).
fn starts_expression(arg: &Arg) -> bool {
    match arg.known() {
        Some(text) => text.starts_with('-') || text == "(" || text == "!",
        None => option_start(arg, Shell::Posix).is_some(),
    }
}

/// The paths a `find` acts on, for each folder it searches: the folder
/// handed on whole (the folder itself and what it holds, see
/// [`crate::path::WHOLE`]) when its expression may act on `.git` there as a
/// folder, or on an entry no name or path pattern picks out, else an entry
/// inside it, and `.git` too when the expression may act on `.git` as a
/// file or on one of the entries it holds (`-name HEAD`, `-name '*.pack'`),
/// which a name search finds at any depth (see [`search`]).
pub(crate) fn find_targets(args: &[Arg]) -> Vec<Arg> {
    let starts = find_starts(args);
    let search = Search::read(expression(args));
    let reach = search.reach_all(&starts);
    let mut targets = Vec::new();
    for (start, reach) in starts.into_iter().zip(reach) {
        match (start, reach) {
            (Arg::Known(text), Reach::Whole) => {
                targets.push(Arg::Known(crate::path::whole_of(&text)));
            }
            (start, Reach::Whole) => targets.push(start),
            (Arg::Known(text), Reach::Inside { git }) => {
                targets.push(Arg::Known(crate::path::found_in(&text)));
                if git {
                    targets.push(Arg::Known(git_inside(&text)));
                }
            }
            (other, Reach::Inside { .. }) => targets.push(other),
        }
    }
    targets
}

/// Whether `find` with `args` may act on a file named `name` at any depth
/// below a folder it searches, by the name tests of its expression alone: an
/// expression that cannot be read may act on any. Each name is walked once.
pub(crate) fn find_may_act_on(args: &[Arg]) -> impl Fn(&str) -> bool {
    let search = Search::read(expression(args));
    let asked: RefCell<HashMap<String, bool>> = RefCell::new(HashMap::new());
    move |name| {
        if let Some(&answer) = asked.borrow().get(name) {
            return answer;
        }
        let answer = search.may_act_on_named(name);
        asked.borrow_mut().insert(name.to_string(), answer);
        answer
    }
}

/// The places `find` searches: its arguments before the first test or
/// action, after its own options (`-H`, `-L`, `-P`, `-D …`, `-O…`); `.` when
/// none.
pub(crate) fn find_starts(args: &[Arg]) -> Vec<Arg> {
    let at = options_end(args);
    let starts: Vec<Arg> = args
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|arg| !starts_expression(arg))
        .cloned()
        .collect();
    if starts.is_empty() {
        vec![Arg::Known(".".to_string())]
    } else {
        starts
    }
}

/// Where `find`'s own options (`-H`, `-L`, `-P`, `-D …`, `-O…`) end.
fn options_end(args: &[Arg]) -> usize {
    let mut at = 0;
    while let Some(text) = args.get(at).and_then(Arg::known) {
        match text {
            "-H" | "-L" | "-P" => at += 1,
            "-D" | "-O" => at += 2,
            text if text.starts_with("-O") && text.len() > 2 => at += 1,
            _ => break,
        }
    }
    at
}

/// `find`'s expression: its arguments after the places it searches.
fn expression(args: &[Arg]) -> &[Arg] {
    let at = options_end(args).min(args.len());
    let rest = &args[at..];
    let first = rest
        .iter()
        .position(starts_expression)
        .unwrap_or(rest.len());
    &rest[first..]
}
