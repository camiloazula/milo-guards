//! `find`: the places it searches, what its filters can match, and the
//! programs its `-exec` runs for each file found.

use std::rc::Rc;

use super::{add, MAX_WRAPPERS};
use crate::unit::{Arg, Split, Unit};
use crate::{Rule, Shell};

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

/// The paths a `find` acts on: the folders it searches themselves when its
/// filter can match `.git` or every name, else an entry inside each.
pub(crate) fn find_targets(args: &[Arg]) -> Vec<Arg> {
    let starts = find_starts(args);
    if find_can_match_git(args) {
        starts
    } else {
        starts
            .into_iter()
            .map(|start| match start {
                Arg::Known(text) => Arg::Known(format!("{text}/x")),
                other => other,
            })
            .collect()
    }
}

/// Whether a `find`'s name filter can match `.git` (or there is none, so
/// every name including `.git` is matched).
fn find_can_match_git(args: &[Arg]) -> bool {
    let mut names = Vec::new();
    let mut paths = Vec::new();
    // A negation (`!`, `-not`) or an alternative (`-o`, `-or`, `,`) can turn
    // any name filter into "everything else": then every name counts.
    let mut open = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("-name" | "-iname" | "-lname" | "-ilname") => {
                names.extend(iter.next().and_then(Arg::known));
            }
            Some("-path" | "-ipath" | "-wholename" | "-iwholename") => {
                paths.extend(iter.next().and_then(Arg::known));
            }
            Some("-regex" | "-iregex" | "!" | "-not" | "-o" | "-or" | ",") => open = true,
            Some(_) => {}
            None => open = true,
        }
    }
    // `-path` matches the whole path from where find starts (`./.git/x`).
    let starts: Vec<String> = find_starts(args)
        .iter()
        .map(|start| {
            start
                .known()
                .unwrap_or(".")
                .trim_end_matches('/')
                .to_string()
        })
        .collect();
    let path_hits_git = paths.iter().any(|pattern| {
        starts.iter().any(|start| {
            glob_can_match(pattern, &format!("{start}/.git"))
                || glob_can_match(pattern, &format!("{start}/.git/x"))
        })
    });
    open || path_hits_git
        || (names.is_empty() && paths.is_empty())
        || names.iter().any(|name| glob_can_match(name, ".git"))
}

/// Whether the shell pattern `pattern` can match `name`. A `[…]` class is
/// read as `?` (one character), which can only widen the match, so the
/// answer is never wrongly `false`.
fn glob_can_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = {
        let mut out = Vec::new();
        let mut chars = pattern.chars();
        while let Some(c) = chars.next() {
            if c == '[' {
                out.push('?');
                for inner in chars.by_ref() {
                    if inner == ']' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = n;
            p += 1;
        } else if let Some(at) = star {
            p = at + 1;
            mark += 1;
            n = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// The places `find` searches: its arguments before the first test or
/// action, after its own options (`-H`, `-L`, `-P`, `-D …`, `-O…`); `.` when
/// none.
pub(crate) fn find_starts(args: &[Arg]) -> Vec<Arg> {
    let mut at = 0;
    while let Some(text) = args.get(at).and_then(Arg::known) {
        match text {
            "-H" | "-L" | "-P" => at += 1,
            "-D" | "-O" => at += 2,
            text if text.starts_with("-O") && text.len() > 2 => at += 1,
            _ => break,
        }
    }
    let starts: Vec<Arg> = args
        .get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|arg| {
            !arg.known()
                .is_some_and(|text| text.starts_with('-') || text == "(" || text == "!")
        })
        .cloned()
        .collect();
    if starts.is_empty() {
        vec![Arg::Known(".".to_string())]
    } else {
        starts
    }
}
