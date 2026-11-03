//! What the tests share: a short, stable spelling of an act, so a case reads
//! as the acts it expects, and the runner of the case files (`cases`).

#![allow(dead_code, unreachable_pub)]

pub mod cases;

use milo_guards_code::{Act, Arg, Language};

/// An argument as a case spells it: the value when the code gives it,
/// `?` when only known when it runs, `FOLDER*` for a path somewhere in a
/// folder.
pub fn arg(arg: &Arg) -> String {
    match arg {
        Arg::Known(text) => text.clone(),
        Arg::Unknown(_) => "?".to_string(),
        Arg::Below { folder, .. } => format!("{folder}*"),
    }
}

/// An act as a case spells it.
pub fn show(act: &Act) -> String {
    match act {
        Act::Remove(path) => format!("remove {}", arg(path)),
        Act::Write(path) => format!("write {}", arg(path)),
        Act::Read(path) => format!("read {}", arg(path)),
        Act::ReadTree(path) => format!("read-tree {}", arg(path)),
        Act::Opaque(path) => format!("opaque {}", arg(path)),
        Act::Move { from, to } => format!("move {} {}", arg(from), arg(to)),
        Act::Link { target, link } => format!("link {} {}", arg(target), arg(link)),
        Act::Chmod { path, mode } => format!("chmod {} {}", arg(mode), arg(path)),
        Act::Chown(path) => format!("chown {}", arg(path)),
        Act::Chdir(path) => format!("chdir {}", arg(path)),
        Act::In(dir, acts) => format!("in {} [{}]", arg(dir), shown(acts)),
        Act::Script(script) => format!("script {}", arg(script)),
        Act::Program(words) => format!(
            "run {}",
            words.iter().map(arg).collect::<Vec<_>>().join(" ")
        ),
        Act::Code(Language::Python, text) => format!("python {text}"),
        Act::Code(Language::JavaScript, text) => format!("javascript {text}"),
        Act::Unread(_) => "unread".to_string(),
        Act::Downloaded(_) => "downloaded".to_string(),
        Act::Loads(_) => "loads".to_string(),
        Act::Environment => "environment".to_string(),
        Act::Started(acts) => format!("started [{}]", shown(acts)),
    }
}

/// Acts as a case spells them, joined by `, `.
pub fn shown(acts: &[Act]) -> String {
    acts.iter().map(show).collect::<Vec<_>>().join(", ")
}
