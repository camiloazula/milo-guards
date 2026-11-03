//! The path model's case files: what the words of a case mean here, and the
//! runner that checks every case of a file. The format is in CONTRIBUTING.md;
//! the reading of it is shared with the guards (see [`format`]).
//!
//! A case is `FLAVOUR[@PATHS] [home] [hidden] [deep] ANSWER... | PATH`:
//!
//! - `FLAVOUR` is `posix` or `windows`, how the path is spelled;
//! - `PATHS` names the machine the path is judged on: `posix`, `macos`,
//!   `windows`, or a `paths` declaration earlier in the file. Without it, a
//!   POSIX path is judged on `posix` and a Windows one on `windows`;
//! - `home` gives the path as `Spelling::Home` (the part below the home
//!   directory), not `Spelling::Plain`; `hidden` says a wildcard matches a
//!   leading dot, and `deep` that a folder is read whole;
//! - the answer is one or more fields, each a question asked of
//!   `Resolver` and the answer it must give: `place=`, `into=` (a write
//!   into it, `place_into`) and `place_hidden=` give a place (below);
//!   `startup=`, `below=` (`startup_below`), `picks=` (`picks_secret`),
//!   `kernel=` and `git=` give their words, or `none`; `absolute=` and
//!   `opened=` give the path, or `none`; `reaches=` (`reaches_secret`) and
//!   `network=` (`spelling::network`) give `yes` or `no`.
//!
//! A place is `inside`, `outside`, `unknown`, `disk`, `null`, `registry`,
//! `temp` (a temporary folder itself), `in_temp` (below one), `workspace`
//! (a workspace folder itself), `holds_workspace`, `home` (the home
//! directory itself), `holds_home`, or a kind and its words: `top:WORDS`,
//! `secret:WORDS`, `startup:WORDS`, `history:WORDS` and `protected:WORDS`.
//!
//! A declaration is `paths NAME FIELDS`, as the shell guard's: `base=MACHINE`,
//! or `cwd=` and `home=`; `workspace=` (one for each folder, after the
//! base's), and `folder=` or `file=` (a protected path), each followed by its
//! `words=`.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a test reads its case files from the crate's `tests/cases`"
)]

#[path = "cases.rs"]
pub mod format;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use format::{Record, Word};
use milo_guards_core::spelling::network;
use milo_guards_core::{Flavour, Paths, Place, Protected, Resolver, Sensitivity, Spelling};

/// A POSIX machine: the workspace in the home directory.
pub fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

/// A macOS machine: home under `/Users`.
pub fn macos() -> Paths {
    Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"])
}

/// A Windows machine.
pub fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

/// The questions a case can ask, by the field that asks each.
pub const ASKS: [&str; 12] = [
    "place",
    "into",
    "place_hidden",
    "startup",
    "below",
    "picks",
    "kernel",
    "git",
    "absolute",
    "opened",
    "reaches",
    "network",
];

/// The questions `hidden` changes the answer of.
const HIDDEN: [&str; 6] = [
    "into",
    "place_hidden",
    "startup",
    "below",
    "picks",
    "reaches",
];

/// One case of a case file.
#[derive(Debug, Clone)]
pub struct Case {
    /// Where it is: `tests/cases/NAME.cases:LINE`.
    pub at: String,
    pub flavour: Flavour,
    pub paths: Paths,
    /// The path is `Spelling::Home`, not `Spelling::Plain`.
    pub home: bool,
    pub hidden: bool,
    pub deep: bool,
    /// Each question asked, and the answer it must give, as a case writes it.
    pub expect: BTreeMap<&'static str, String>,
    /// The path, decoded.
    pub path: String,
}

impl Case {
    /// The words before the answer and the answer, as a case file writes
    /// them, in a fixed order.
    pub fn spelled(&self) -> String {
        let mut words = Vec::new();
        for (on, word) in [
            (self.home, "home"),
            (self.hidden, "hidden"),
            (self.deep, "deep"),
        ] {
            if on {
                words.push(word.to_string());
            }
        }
        for (ask, value) in &self.expect {
            words.push(format!("{ask}={value:?}"));
        }
        words.join(" ")
    }
}

/// A place as a case file writes it.
pub fn place_name(place: Place) -> String {
    match place {
        Place::Inside => "inside".to_string(),
        Place::Outside => "outside".to_string(),
        Place::Unknown => "unknown".to_string(),
        Place::Disk => "disk".to_string(),
        Place::Null => "null".to_string(),
        Place::Registry => "registry".to_string(),
        Place::Temp { exact: true } => "temp".to_string(),
        Place::Temp { exact: false } => "in_temp".to_string(),
        Place::Workspace { exact: true } => "workspace".to_string(),
        Place::Workspace { exact: false } => "holds_workspace".to_string(),
        Place::Home { exact: true } => "home".to_string(),
        Place::Home { exact: false } => "holds_home".to_string(),
        Place::Top(words) => format!("top:{words}"),
        Place::Sensitive(words, Sensitivity::Secret) => format!("secret:{words}"),
        Place::Sensitive(words, Sensitivity::Startup) => format!("startup:{words}"),
        Place::Sensitive(words, Sensitivity::History) => format!("history:{words}"),
        Place::Protected(words) => format!("protected:{words}"),
        other => format!("{other:?}"),
    }
}

/// Whether `value` is a place a case file can write.
fn is_place(value: &str) -> bool {
    const BARE: [&str; 12] = [
        "inside",
        "outside",
        "unknown",
        "disk",
        "null",
        "registry",
        "temp",
        "in_temp",
        "workspace",
        "holds_workspace",
        "home",
        "holds_home",
    ];
    match value.split_once(':') {
        Some((kind, words)) => {
            ["top", "secret", "startup", "history", "protected"].contains(&kind)
                && !words.is_empty()
        }
        None => BARE.contains(&value),
    }
}

/// What `ask` answers for `case`, as a case file writes it.
pub fn answer(case: &Case, ask: &str) -> String {
    let resolver = Resolver::new(&case.paths);
    let spelled = if case.home {
        Spelling::Home(&case.path)
    } else {
        Spelling::Plain(&case.path)
    };
    let (flavour, hidden) = (case.flavour, case.hidden);
    let words = |words: Option<&str>| words.unwrap_or("none").to_string();
    let path = |path: Option<PathBuf>| {
        path.map_or_else(
            || "none".to_string(),
            |path| path.to_string_lossy().into_owned(),
        )
    };
    let yes = |yes: bool| if yes { "yes" } else { "no" }.to_string();
    match ask {
        "place" => place_name(resolver.place(spelled, flavour)),
        "into" => place_name(resolver.place_into(spelled, flavour, hidden)),
        "place_hidden" => place_name(resolver.place_hidden(spelled, flavour, hidden)),
        "startup" => words(resolver.startup(spelled, flavour, hidden)),
        "below" => words(resolver.startup_below(spelled, flavour, hidden)),
        "picks" => words(resolver.picks_secret(spelled, flavour, hidden)),
        "kernel" => words(resolver.kernel(spelled, flavour)),
        "git" => words(resolver.git(spelled, flavour)),
        "absolute" => path(resolver.absolute(spelled, flavour)),
        "opened" => path(resolver.opened(spelled, flavour)),
        "reaches" => yes(resolver.reaches_secret(spelled, flavour, hidden, case.deep)),
        "network" => yes(network(&case.path, flavour)),
        other => format!("no question `{other}`"),
    }
}

/// Every case of the file named `name`, checked: a file that is not there,
/// a line that is refused and a case that is wrong fail the test, each named
/// by its file and line.
pub fn check(name: &str) {
    let cases = load(name);
    let wrong: Vec<String> = cases.iter().flat_map(wrong).collect();
    assert!(
        wrong.is_empty(),
        "{} of {} cases wrong:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}

/// The cases of the file named `name`; every refusal fails the test.
pub fn load(name: &str) -> Vec<Case> {
    let read = format::read(name).and_then(|records| cases(&records));
    let refused = read.as_ref().err().cloned().unwrap_or_default();
    assert!(
        refused.is_empty(),
        "{} lines refused:\n{}",
        refused.len(),
        refused.join("\n")
    );
    read.unwrap_or_default()
}

/// The cases of `source`, the text of the file `file`, or every refusal.
pub fn parse(file: &str, source: &str) -> Result<Vec<Case>, Vec<String>> {
    format::parse(file, source).and_then(|records| cases(&records))
}

/// What a repeated case shares with the first: the flavour, the paths, the
/// spelling, the path and the answer.
pub type Key = (
    bool,
    String,
    [bool; 3],
    String,
    BTreeMap<&'static str, String>,
);

/// The key a repeated case shares with the first.
pub fn key(case: &Case) -> Key {
    (
        case.flavour == Flavour::Windows,
        format!("{:?}", case.paths),
        [case.home, case.hidden, case.deep],
        case.path.clone(),
        case.expect.clone(),
    )
}

/// One line for a case: where it is, the flavour, the paths, the answer and
/// the path as Rust writes a string, tab separated.
pub fn dumped(case: &Case) -> String {
    format!(
        "{}\t{:?}\t{:?}\t{}\t{:?}",
        case.at,
        case.flavour,
        case.paths,
        case.spelled(),
        case.path
    )
}

/// What is wrong with `case`: one message for each answer it misses.
pub fn wrong(case: &Case) -> Vec<String> {
    case.expect
        .iter()
        .filter_map(|(ask, want)| {
            let got = answer(case, ask);
            (got != *want).then(|| {
                format!(
                    "{}: expected {ask}={want:?}: {:?}\n    got {got:?}",
                    case.at, case.path
                )
            })
        })
        .collect()
}

/// The cases of `records`, or every refusal: an unknown word or field, a
/// malformed answer, an unknown machine, a repeated case.
fn cases(records: &[Record]) -> Result<Vec<Case>, Vec<String>> {
    let mut machines: HashMap<String, Paths> = [
        ("posix".to_string(), posix()),
        ("macos".to_string(), macos()),
        ("windows".to_string(), windows()),
    ]
    .into_iter()
    .collect();
    let mut cases = Vec::new();
    let mut refused = Vec::new();
    for record in records {
        let result = match (&record.text, record.words.first()) {
            (None, Some(Word::Bare(word))) if word == "paths" => {
                declaration(&record.words[1..], &machines)
                    .map(|(name, paths)| {
                        machines.insert(name, paths);
                    })
                    .map_err(|why| vec![why])
            }
            (None, _) => Err(vec!["a case with no `| PATH`".to_string()]),
            (Some(path), _) => case(&record.words, &machines).map(|mut case| {
                case.at.clone_from(&record.at);
                case.path.clone_from(path);
                cases.push(case);
            }),
        };
        if let Err(whys) = result {
            refused.extend(whys.into_iter().map(|why| format!("{}: {why}", record.at)));
        }
    }
    refused.extend(format::repeated(
        cases.iter().map(|case| (case.at.clone(), key(case))),
    ));
    if refused.is_empty() {
        Ok(cases)
    } else {
        Err(refused)
    }
}

/// A `paths` declaration: its name and the paths it makes.
fn declaration(
    words: &[Word],
    machines: &HashMap<String, Paths>,
) -> Result<(String, Paths), String> {
    let Some(Word::Bare(name)) = words.first() else {
        return Err("`paths` takes a name first".to_string());
    };
    if machines.contains_key(name) {
        return Err(format!("the paths `{name}` are already named"));
    }
    let mut base: Option<Paths> = None;
    let (mut cwd, mut home) = (None, None);
    let mut workspaces: Vec<PathBuf> = Vec::new();
    let mut protected: Vec<(bool, PathBuf, Option<String>)> = Vec::new();
    for word in &words[1..] {
        let (field, value) = match word {
            Word::Field(field, value) => (field, value),
            Word::Bare(bare) => {
                return Err(format!("an unknown word `{bare}` in a `paths` declaration"))
            }
        };
        match field.as_str() {
            "base" => {
                let paths = machines
                    .get(value)
                    .ok_or_else(|| format!("no paths named `{value}`"))?;
                base = Some(paths.clone());
            }
            "cwd" => cwd = Some(PathBuf::from(value)),
            "home" => home = Some(PathBuf::from(value)),
            "workspace" => workspaces.push(PathBuf::from(value)),
            "folder" | "file" => protected.push((field == "folder", PathBuf::from(value), None)),
            "words" => match protected.last_mut() {
                Some((_, _, words @ None)) => *words = Some(value.clone()),
                _ => return Err("`words` must follow its `folder` or `file`".to_string()),
            },
            other => {
                return Err(format!(
                    "an unknown field `{other}` in a `paths` declaration"
                ))
            }
        }
    }
    let mut paths = match (base, cwd, home) {
        (Some(base), None, None) => base,
        (None, Some(cwd), Some(home)) => Paths::new(cwd, home, Vec::<PathBuf>::new()),
        _ => return Err("a `paths` declaration takes `base`, or `cwd` and `home`".to_string()),
    };
    paths.workspaces.extend(workspaces);
    for (folder, path, words) in protected {
        let words: &'static str = Box::leak(
            words
                .ok_or("each `folder` and `file` takes its `words`")?
                .into_boxed_str(),
        );
        paths = paths.with_protected([if folder {
            Protected::folder(path, words)
        } else {
            Protected::file(path, words)
        }]);
    }
    Ok((name.clone(), paths))
}

/// The case its words make, its place in the file and its path still empty.
fn case(words: &[Word], machines: &HashMap<String, Paths>) -> Result<Case, Vec<String>> {
    let Some(Word::Bare(head)) = words.first() else {
        return Err(vec!["a case starts with its flavour".to_string()]);
    };
    let (flavour, machine) = match head.split_once('@') {
        Some((flavour, machine)) => (flavour, Some(machine)),
        None => (head.as_str(), None),
    };
    let flavour = match flavour {
        "posix" => Flavour::Posix,
        "windows" => Flavour::Windows,
        other => return Err(vec![format!("an unknown flavour `{other}`")]),
    };
    let machine = machine.unwrap_or(if flavour == Flavour::Posix {
        "posix"
    } else {
        "windows"
    });
    let paths = machines
        .get(machine)
        .ok_or_else(|| vec![format!("no paths named `{machine}`")])?
        .clone();
    let mut case = Case {
        at: String::new(),
        flavour,
        paths,
        home: false,
        hidden: false,
        deep: false,
        expect: BTreeMap::new(),
        path: String::new(),
    };
    let mut seen: HashSet<&str> = HashSet::new();
    let mut refused = Vec::new();
    for word in &words[1..] {
        let (name, value) = match word {
            Word::Bare(name) => (name.as_str(), None),
            Word::Field(name, value) => (name.as_str(), Some(value.as_str())),
        };
        if !seen.insert(name) {
            refused.push(format!("`{name}` twice"));
            continue;
        }
        if let Err(why) = add(&mut case, name, value) {
            refused.push(why);
        }
    }
    if refused.is_empty() {
        if let Err(why) = whole(&case) {
            refused.push(why);
        }
    }
    if refused.is_empty() {
        Ok(case)
    } else {
        Err(refused)
    }
}

/// `case` with the word `name` (and its `value`) added.
fn add(case: &mut Case, name: &str, value: Option<&str>) -> Result<(), String> {
    match (name, value) {
        ("home", None) => case.home = true,
        ("hidden", None) => case.hidden = true,
        ("deep", None) => case.deep = true,
        ("home" | "hidden" | "deep", Some(_)) => return Err(format!("`{name}` takes no value")),
        (ask, Some(value)) => {
            let Some(ask) = ASKS.into_iter().find(|known| *known == ask) else {
                return Err(format!("an unknown field `{ask}`"));
            };
            let fits = match ask {
                "place" | "into" | "place_hidden" => is_place(value),
                "reaches" | "network" => value == "yes" || value == "no",
                _ => !value.is_empty(),
            };
            if !fits {
                return Err(format!("`{value}` is no answer `{ask}` gives"));
            }
            case.expect.insert(ask, value.to_string());
        }
        (ask, None) if ASKS.contains(&ask) => {
            return Err(format!("`{ask}` takes a value: `{ask}=...`"))
        }
        (other, None) => return Err(format!("an unknown word `{other}`")),
    }
    Ok(())
}

/// Whether the words of a case make one question each, and every word
/// changes the answer of one.
fn whole(case: &Case) -> Result<(), String> {
    if case.expect.is_empty() {
        return Err(format!(
            "a case with no answer: one of `{}`",
            ASKS.join("`, `")
        ));
    }
    if case.hidden && !case.expect.keys().any(|ask| HIDDEN.contains(ask)) {
        return Err(format!("`hidden` takes one of `{}`", HIDDEN.join("`, `")));
    }
    if case.deep && !case.expect.contains_key("reaches") {
        return Err("`deep` takes `reaches`".to_string());
    }
    if case.home && case.expect.contains_key("network") {
        return Err("`network` reads the text, not a `home` spelling".to_string());
    }
    Ok(())
}
