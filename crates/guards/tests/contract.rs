//! What every guard promises, checked on the code itself.
//!
//! A guard reads what an agent is about to do and answers; it does not do
//! anything itself. So no guard's source (nor its `build.rs`) may touch the
//! file system, the environment, processes, the network, threads, the
//! clock, the terminal or the operating system's own APIs, and no guard may
//! build on another guard: each stands on the shared core and its own
//! parsers.
//!
//! This is a text scan, a backstop for the `disallowed-*` lists in
//! `clippy.toml`, which refuse the same calls by what they resolve to.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "this test reads the repository's own files, which no guard may do"
)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The repository's root, two folders above this crate.
fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().unwrap_or(root)
}

/// The folders under `crates/`, by name.
fn crates() -> Result<Vec<String>, String> {
    let dir = root().join("crates");
    let entries = fs::read_dir(&dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().join("Cargo.toml").is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    Ok(names)
}

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, found)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    Ok(())
}

/// The code a crate ships: every `.rs` file under its `src`, and its
/// `build.rs` if it has one, which runs at build time and so is as much a
/// part of the guard as its source.
fn crate_sources(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    sources(&dir.join("src"), &mut found)?;
    let build = dir.join("build.rs");
    if build.is_file() {
        found.push(build);
    }
    Ok(found)
}

// ---- reading the code, not the comments ----

/// `source` with comments, and the inside of string and character
/// literals, blanked out, keeping its lines. What a comment or a string
/// says is no use of a forbidden API.
fn code_of(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(chars[i]));
                    i += 1;
                }
            }
        } else if c == 'r' && matches!(next, Some('"' | '#')) && raw_string_at(&chars, i).is_some()
        {
            let (hashes, start) = raw_string_at(&chars, i).unwrap_or((0, i + 1));
            out.extend(std::iter::repeat_n(' ', start - i));
            i = start;
            while i < chars.len() {
                if chars[i] == '"' && (0..hashes).all(|k| chars.get(i + 1 + k) == Some(&'#')) {
                    out.extend(std::iter::repeat_n(' ', 1 + hashes));
                    i += 1 + hashes;
                    break;
                }
                out.push(blank(chars[i]));
                i += 1;
            }
        } else if c == '"' {
            out.push(' ');
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    out.push(blank(chars[i]));
                    i += 1;
                }
                out.push(blank(chars[i]));
                i += 1;
            }
            out.push(' ');
            i += 1;
        } else if c == '\'' && char_literal_len(&chars, i).is_some() {
            let len = char_literal_len(&chars, i).unwrap_or(1);
            out.extend(std::iter::repeat_n(' ', len));
            i += len;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// For `r"…"` and `r#"…"#` at `at`: the number of `#` and where the text
/// starts.
fn raw_string_at(chars: &[char], at: usize) -> Option<(usize, usize)> {
    let mut i = at + 1;
    let mut hashes = 0;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    (chars.get(i) == Some(&'"')).then_some((hashes, i + 1))
}

/// The length of the character literal at `at` (`'a'`, `'\n'`), or `None`
/// when the quote starts a lifetime.
fn char_literal_len(chars: &[char], at: usize) -> Option<usize> {
    match (chars.get(at + 1)?, chars.get(at + 2)?) {
        ('\\', _) => {
            let close = chars[at + 2..].iter().position(|&c| c == '\'')?;
            Some(close + 3)
        }
        (_, '\'') => Some(3),
        _ => None,
    }
}

// ---- use trees ----

#[derive(Debug, PartialEq)]
enum Token {
    Name(String),
    Path,
    Open,
    Close,
    Comma,
    Star,
    Other,
}

fn tokens(code: &str) -> Vec<Token> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let mut name: String = chars[start..i].iter().collect();
            // `name!(…)` is a macro call; `a != b` is not.
            if chars.get(i) == Some(&'!') && chars.get(i + 1) != Some(&'=') {
                name.push('!');
                i += 1;
            }
            out.push(Token::Name(name));
        } else if c == ':' && chars.get(i + 1) == Some(&':') {
            out.push(Token::Path);
            i += 2;
        } else {
            out.push(match c {
                '{' => Token::Open,
                '}' => Token::Close,
                ',' => Token::Comma,
                '*' => Token::Star,
                _ => Token::Other,
            });
            i += 1;
        }
    }
    out
}

/// Step over the `as alias` that renames what was just imported: the
/// alias is a new name, not a further path.
fn skip_alias(tokens: &[Token], i: &mut usize) {
    let after_spaces = |mut at: usize| {
        while tokens.get(at) == Some(&Token::Other) {
            at += 1;
        }
        at
    };
    let keyword = after_spaces(*i);
    if tokens.get(keyword) == Some(&Token::Name("as".to_string())) {
        let alias = after_spaces(keyword + 1);
        if matches!(tokens.get(alias), Some(Token::Name(_))) {
            *i = alias + 1;
        }
    }
}

/// Parse the rest of a path after the name at `tokens[*i - 1]`, pushing
/// every full path it spells (`std::{io::{stdin, Read}, fs}` is three).
fn paths_from(tokens: &[Token], i: &mut usize, prefix: &[String], out: &mut Vec<Vec<String>>) {
    let mut here = prefix.to_vec();
    loop {
        if tokens.get(*i) != Some(&Token::Path) {
            out.push(here);
            return;
        }
        *i += 1;
        match tokens.get(*i) {
            Some(Token::Name(name)) => {
                here.push(name.clone());
                *i += 1;
            }
            Some(Token::Star) => {
                here.push("*".to_string());
                *i += 1;
                out.push(here);
                return;
            }
            Some(Token::Open) => {
                *i += 1;
                loop {
                    match tokens.get(*i) {
                        Some(Token::Name(name)) => {
                            *i += 1;
                            if name == "self" {
                                // `{self}` and `{self as x}` import the
                                // module itself, as `use module;` does.
                                out.push(here.clone());
                            } else {
                                let mut branch = here.clone();
                                branch.push(name.clone());
                                paths_from(tokens, i, &branch, out);
                            }
                            skip_alias(tokens, i);
                        }
                        Some(Token::Star) => {
                            *i += 1;
                            let mut branch = here.clone();
                            branch.push("*".to_string());
                            out.push(branch);
                        }
                        Some(Token::Open) => {
                            *i += 1;
                        }
                        Some(Token::Comma) => *i += 1,
                        Some(Token::Close) => {
                            *i += 1;
                            return;
                        }
                        Some(_) => *i += 1,
                        None => return,
                    }
                }
            }
            _ => {
                out.push(here);
                return;
            }
        }
    }
}

/// Every path in `code` that starts at `std`, `core`'s sibling `alloc`
/// aside: `std::fs::read`, `use std::{env, fs}`, `::std::process::exit`.
fn std_paths(code: &str) -> Vec<Vec<String>> {
    let tokens = tokens(code);
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == Token::Name("std".to_string()) {
            i += 1;
            paths_from(&tokens, &mut i, &["std".to_string()], &mut out);
        } else {
            i += 1;
        }
    }
    out
}

// ---- the rules ----

/// What no guard may use, by path prefix.
const FORBIDDEN: [&[&str]; 11] = [
    &["std", "fs"],
    &["std", "env"],
    &["std", "process"],
    &["std", "net"],
    &["std", "thread"],
    &["std", "os"],
    &["std", "time", "SystemTime"],
    &["std", "time", "Instant"],
    &["std", "io", "stdin"],
    &["std", "io", "stdout"],
    &["std", "io", "stderr"],
];

/// Modules of `std` that hold a forbidden item and so are never imported
/// whole or by glob: `use std::time;` would hide `time::Instant`.
const GUARDED_MODULES: [&[&str]; 2] = [&["std", "time"], &["std", "io"]];

/// Macros that write to the terminal.
const PRINTING: [&str; 4] = ["println!", "print!", "eprintln!", "eprint!"];

/// Why `path` is not allowed, if it is not.
fn forbidden(path: &[String]) -> Option<String> {
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    for banned in FORBIDDEN {
        if path.starts_with(banned) {
            return Some(format!("uses `{}`", path.join("::")));
        }
    }
    for module in GUARDED_MODULES {
        let whole = path == module;
        let glob =
            path.len() == module.len() + 1 && path.starts_with(module) && path[module.len()] == "*";
        if whole || glob {
            return Some(format!(
                "imports `{}` as a whole, which hides `{}` items: import what you need",
                path.join("::"),
                module.join("::")
            ));
        }
    }
    if path == ["std", "*"] || path == ["std"] {
        return Some("imports `std` as a whole".to_string());
    }
    None
}

/// Everything wrong with one source file's `code` (comments and strings
/// already blanked), as lines to print.
fn violations(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    for path in std_paths(code) {
        if let Some(why) = forbidden(&path) {
            found.push(why);
        }
    }
    for token in tokens(code) {
        if let Token::Name(name) = token {
            if PRINTING.contains(&name.as_str()) {
                found.push(format!("calls `{name}`"));
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

#[test]
fn no_guard_does_io_or_reads_the_environment() -> Result<(), String> {
    let mut wrong = Vec::new();
    let mut files = 0;
    for name in crates()? {
        for file in crate_sources(&root().join("crates").join(&name))? {
            files += 1;
            let text = fs::read_to_string(&file)
                .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
            for why in violations(&code_of(&text)) {
                wrong.push(format!("{}: {why}", file.display()));
            }
        }
    }
    assert!(
        files > 0,
        "found no source files: is the walk looking in the right place?"
    );
    assert!(
        wrong.is_empty(),
        "a guard must not do I/O or read the environment, which makes it nondeterministic:\n{}",
        wrong.join("\n")
    );
    Ok(())
}

// ---- Cargo.toml ----

/// One dependency a manifest declares, as it is written.
#[derive(Debug, Default, PartialEq)]
struct Dependency {
    /// The key it is declared under.
    name: String,
    /// `package = "…"`: the crate it really is, when the key renames it.
    package: Option<String>,
    /// `path = "…"`: the folder it lives in.
    path: Option<String>,
    /// `workspace = true`: declared in the root manifest's
    /// `[workspace.dependencies]` instead.
    workspace: bool,
}

impl Dependency {
    /// Take in `key = value` written about this dependency: a `package`,
    /// `path` or `workspace` key, or an inline table holding them.
    fn read(&mut self, key: &str, value: &str) {
        match key {
            "package" => self.package = unquote(value),
            "path" => self.path = unquote(value),
            "workspace" => self.workspace = value.trim() == "true",
            _ => {}
        }
        if let Some(table) = value.trim().strip_prefix('{') {
            for field in ["package", "path"] {
                if let Some(found) = inline(table, field) {
                    self.read(field, &format!("\"{found}\""));
                }
            }
            if inline_is_true(table, "workspace") {
                self.workspace = true;
            }
        }
    }
}

/// The text of a quoted TOML string.
fn unquote(value: &str) -> Option<String> {
    let value = value.trim();
    let quote = value.chars().next().filter(|c| matches!(c, '"' | '\''))?;
    let rest = &value[1..];
    rest.find(quote).map(|end| rest[..end].to_string())
}

/// Where `key` stands as a key in the inline table `table` (`a = 1, key =
/// "x"`): the text after its `=`.
fn inline_value<'a>(table: &'a str, key: &str) -> Option<&'a str> {
    table.match_indices(key).find_map(|(at, _)| {
        let before = table[..at].chars().next_back();
        let after = table[at + key.len()..].trim_start();
        let key_start = before.is_none_or(|c| c.is_whitespace() || matches!(c, '{' | ','));
        (key_start && after.starts_with('=')).then(|| after[1..].trim_start())
    })
}

/// The string `key` is set to in the inline table `table`.
fn inline(table: &str, key: &str) -> Option<String> {
    unquote(inline_value(table, key)?)
}

/// Whether `key` is set to `true` in the inline table `table`.
fn inline_is_true(table: &str, key: &str) -> bool {
    inline_value(table, key).is_some_and(|rest| rest.starts_with("true"))
}

/// The dependencies a manifest declares, in `[dependencies]`,
/// `[dev-dependencies]`, `[build-dependencies]`, `[workspace.dependencies]`
/// and their `target` forms, whether written as `name = "1"`,
/// `name = { … }`, `name.workspace = true` or a table of their own.
fn dependencies(manifest: &str) -> Vec<Dependency> {
    let mut found: Vec<Dependency> = Vec::new();
    let mut in_deps = false;
    let mut own_table = false;
    for line in manifest.lines() {
        let line = strip_comment(line).trim();
        if let Some(header) = line.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let header = header.trim_matches(['[', ']']).trim();
            // `[dependencies]`, `[target.'cfg(unix)'.dev-dependencies]`, or a
            // dependency of its own: `[dependencies.name]`.
            let (table, own) = match header.split_once("dependencies.") {
                Some((before, name))
                    if before.is_empty() || before.ends_with('-') || before.ends_with('.') =>
                {
                    (true, Some(name.trim_matches('"').to_string()))
                }
                _ => (header.ends_with("dependencies"), None),
            };
            in_deps = table && own.is_none();
            own_table = own.is_some();
            if let Some(name) = own {
                found.push(Dependency {
                    name,
                    ..Dependency::default()
                });
            }
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().trim_matches('"');
            if in_deps {
                // `name.workspace = true` and `name = { … }`.
                let (name, field) = key.split_once('.').unwrap_or((key, ""));
                if found.last().is_none_or(|last| last.name != name) {
                    found.push(Dependency {
                        name: name.to_string(),
                        ..Dependency::default()
                    });
                }
                if let Some(last) = found.last_mut() {
                    last.read(field, value);
                }
            } else if own_table {
                if let Some(last) = found.last_mut() {
                    last.read(key, value);
                }
            }
        }
    }
    found
}

/// `line` without a trailing `# comment` (a `#` inside a quoted string
/// stays).
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (at, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(open), c) if c == open => quote = None,
            (None, '#') => return &line[..at],
            _ => {}
        }
    }
    line
}

/// The folder name a `path = "…"` ends in: `../shell` and `crates/shell/`
/// are `shell`.
fn folder_of(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .find(|part| !part.is_empty() && *part != ".")
}

/// The crates that read code of another language for a guard (`code`), not
/// guards: they say what the code does, never whether that is risky. A guard
/// may build on one, as it does on its other parsers; a reader builds on the
/// core and its own parsers like a guard does, and on no guard and no other
/// reader.
const READERS: [&str; 1] = ["code"];

/// Whether `package` names a reader's crate (`milo-guards-code`).
fn is_reader_package(package: &str) -> bool {
    package
        .strip_prefix("milo-guards-")
        .is_some_and(|folder| READERS.contains(&folder))
}

/// Whether `package` names a guard's own crate or the front door.
fn is_guard_package(package: &str) -> bool {
    (package.starts_with("milo-guards-")
        && package != "milo-guards-core"
        && !is_reader_package(package))
        || package == "milo-guards"
}

/// Why `dep`, declared by crate `owner`, is another guard or the front door
/// (or, for a reader, another reader): by its key, by the crate it renames,
/// or by the folder it points to. `workspace` holds the root manifest's
/// `[workspace.dependencies]`.
fn other_guard(
    dep: &Dependency,
    owner: &str,
    folders: &[String],
    workspace: &HashMap<&str, &Dependency>,
) -> Option<String> {
    // A path to the manifest's own folder is the crate itself, turning on a
    // feature of its own for its tests: cargo refuses a path that holds
    // another crate than the one named.
    if !dep.workspace && dep.path.as_deref().map(|path| path.trim_end_matches('/')) == Some(".") {
        return None;
    }
    let mut declared = vec![dep];
    if dep.workspace {
        declared.extend(workspace.get(dep.name.as_str()));
    }
    // A guard may build on a reader; a reader may build on none.
    let owner_reads = READERS.contains(&owner);
    for dep in declared {
        for name in std::iter::once(dep.name.as_str()).chain(dep.package.as_deref()) {
            if is_guard_package(name) || (owner_reads && is_reader_package(name)) {
                return Some(format!("`{name}`"));
            }
        }
        if let Some(folder) = dep.path.as_deref().and_then(folder_of) {
            let reader = READERS.contains(&folder) && !owner_reads;
            if folder != owner
                && folder != "core"
                && !reader
                && folders.iter().any(|name| name == folder)
            {
                return Some(format!(
                    "the crate in `crates/{folder}` (path `{}`)",
                    dep.path.as_deref().unwrap_or_default()
                ));
            }
        }
    }
    None
}

/// The dependencies of crate `name`'s manifest that break the direction of
/// the crates, one line each.
fn wrong_dependencies(
    name: &str,
    manifest: &str,
    root_manifest: &str,
    folders: &[String],
) -> Vec<String> {
    let deps = dependencies(manifest);
    let root_deps = dependencies(root_manifest);
    let workspace: HashMap<&str, &Dependency> = root_deps
        .iter()
        .map(|dep| (dep.name.as_str(), dep))
        .collect();
    match name {
        "core" if !deps.is_empty() => {
            let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
            vec![format!(
                "crates/core depends on {names:?}: it depends on nothing but std"
            )]
        }
        "core" | "guards" => Vec::new(),
        _ => deps
            .iter()
            .filter_map(|dep| {
                let other = other_guard(dep, name, folders, &workspace)?;
                Some(format!(
                    "crates/{name} depends on `{}`, which is {other}: a guard depends on \
                     `milo-guards-core`, its own parsers and a code reader only (a reader \
                     on the core and its parsers), and the front door depends on the \
                     guards, never the other way",
                    dep.name
                ))
            })
            .collect(),
    }
}

#[test]
fn a_guard_builds_on_the_core_and_never_on_another_guard() -> Result<(), String> {
    let read = |path: PathBuf| {
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    };
    let root_manifest = read(root().join("Cargo.toml"))?;
    let folders = crates()?;
    let mut wrong = Vec::new();
    let mut guards = 0;
    for name in &folders {
        let manifest = read(root().join("crates").join(name).join("Cargo.toml"))?;
        if !matches!(name.as_str(), "core" | "guards") {
            guards += 1;
        }
        wrong.extend(wrong_dependencies(
            name,
            &manifest,
            &root_manifest,
            &folders,
        ));
    }
    assert!(
        guards > 0,
        "found no guard crates: is the walk looking in the right place?"
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    Ok(())
}

// ---- the checker checks itself ----

#[test]
fn comments_and_strings_are_not_code() {
    let source = "// std::fs::read\n/* std::env::var /* nested */ std::process */ let a = \"std::net\"; \
         let b = r#\"std::thread\"#; let c = '\"'; let d: &'static str = \"\\\"std::fs\";\nlet e = 1;";
    let code = code_of(source);
    assert!(violations(&code).is_empty(), "{code}");
    assert_eq!(
        code.lines().count(),
        source.lines().count(),
        "lines are kept"
    );
}

#[test]
fn every_forbidden_use_is_found() {
    for (source, expected) in [
        ("let a = std::fs::read(p);", "std::fs::read"),
        ("use std::{env, path::Path};", "std::env"),
        ("use std::{io::{self, stdin}, fs};", "std::fs"),
        ("use std::io::{stdout, Write};", "std::io::stdout"),
        ("let a = ::std::process::exit(1);", "std::process::exit"),
        ("use std::net::TcpStream;", "std::net::TcpStream"),
        ("std::thread::spawn(f);", "std::thread::spawn"),
        ("use std::time::{Duration, Instant};", "std::time::Instant"),
        (
            "let t = std::time::SystemTime::now();",
            "std::time::SystemTime::now",
        ),
        ("use std::io::stdin;", "std::io::stdin"),
        ("use std::time;", "std::time"),
        ("use std::io::*;", "std::io::*"),
        ("use std::*;", "std"),
        ("println!(\"x\");", "println!"),
        ("eprintln!(\"x\")", "eprintln!"),
        // The terminal's third stream, and the operating system's own APIs.
        ("let e = std::io::stderr();", "std::io::stderr"),
        ("use std::io::{stderr, Write};", "std::io::stderr"),
        (
            "use std::os::unix::fs::symlink;",
            "std::os::unix::fs::symlink",
        ),
        (
            "let p = std::os::unix::process::parent_id();",
            "std::os::unix::process",
        ),
        ("use std::os;", "std::os"),
        ("use std::{os::fd::AsRawFd, fmt};", "std::os::fd::AsRawFd"),
        // `self` in a group is the module itself, however it is renamed.
        ("use std::io::{self, Read};", "std::io"),
        ("use std::io::{self as sio};", "std::io"),
        ("use std::time::{self};", "std::time"),
        ("use std::{io::{self}, fmt};", "std::io"),
        ("use std::{self};", "std"),
        ("use std::fs as files;", "std::fs"),
        ("use std::{fs as files, fmt};", "std::fs"),
    ] {
        let found = violations(&code_of(source));
        assert!(
            found.iter().any(|why| why.contains(expected)),
            "{source}: expected {expected}, found {found:?}"
        );
    }
}

#[test]
fn pure_code_passes() {
    for source in [
        "use std::collections::HashMap; use std::io::Error; use std::time::Duration;",
        "use std::{fmt::Debug, hash::Hash, path::PathBuf};",
        "let a = x != y; let b = !c; assert!(a, \"print! is fine in a string\");",
        "fn f<'a>(x: &'a str) -> char { 'x' }",
        "let io = 1; let fs = io; let env = fs;",
        // An alias is a name, not a path: it does not read as `std::io::stdin`.
        "use std::io::{Error as stdin, Read as stdout};",
        "use std::fmt::{self, Debug}; use std::collections::{self as c};",
    ] {
        assert!(
            violations(&code_of(source)).is_empty(),
            "{source}: {:?}",
            violations(&code_of(source))
        );
    }
}

/// The files `crate_sources` finds in a crate with a `src` folder, before and
/// after a `build.rs` is added.
fn sample_crate(dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let io = |e: std::io::Error| e.to_string();
    fs::create_dir_all(dir.join("src")).map_err(io)?;
    fs::write(dir.join("src/lib.rs"), "").map_err(io)?;
    let without = crate_sources(dir)?;
    fs::write(dir.join("build.rs"), "fn main() {}").map_err(io)?;
    Ok((without, crate_sources(dir)?))
}

#[test]
fn a_crates_build_script_is_read_with_its_source() -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("milo-contract-{}", std::process::id()));
    let result = sample_crate(&dir);
    let _ = fs::remove_dir_all(&dir);
    let (without, with) = result?;
    assert_eq!(without, [dir.join("src/lib.rs")]);
    assert_eq!(with, [dir.join("src/lib.rs"), dir.join("build.rs")]);
    // And what is in it counts: a build script reading the environment is
    // found the same way as any source.
    assert!(!violations(&code_of("fn main() { let _ = std::env::var(\"X\"); }")).is_empty());
    Ok(())
}

#[test]
fn dependencies_are_read_from_every_table() {
    let manifest = "\
[package]
name = \"x\"
[dependencies]
a = \"1\"
b.workspace = true
c = { workspace = true, features = [\"testing\"] } # comment
[dev-dependencies]
d = \"1\"
[target.'cfg(unix)'.dependencies]
e = \"1\"
[dependencies.f]
version = \"1\"
[features]
g = [\"dep:a\"]
";
    let names: Vec<String> = dependencies(manifest)
        .into_iter()
        .map(|dep| dep.name)
        .collect();
    assert_eq!(names, ["a", "b", "c", "d", "e", "f"]);
}

#[test]
fn package_path_and_workspace_are_read_in_every_form() {
    let manifest = "\
[dependencies]
a = { package = \"milo-guards-shell\", version = \"1\" }
b = { path = \"../shell\" } # comment with path = \"nope\"
c.package = \"milo-guards\"
d.path = \"../guards\"
e = { workspace = true }
f = { features = [\"path\"], version = \"1\" }
[dev-dependencies.g]
package = \"milo-guards-shell\"
[target.'cfg(unix)'.build-dependencies.h]
path = \"../../crates/shell/\"
";
    let found = dependencies(manifest);
    let summary: Vec<_> = found
        .iter()
        .map(|dep| {
            (
                dep.name.as_str(),
                dep.package.as_deref(),
                dep.path.as_deref(),
                dep.workspace,
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("a", Some("milo-guards-shell"), None, false),
            ("b", None, Some("../shell"), false),
            ("c", Some("milo-guards"), None, false),
            ("d", None, Some("../guards"), false),
            ("e", None, None, true),
            ("f", None, None, false),
            ("g", Some("milo-guards-shell"), None, false),
            ("h", None, Some("../../crates/shell/"), false),
        ]
    );
}

#[test]
fn another_guard_is_found_however_the_manifest_names_it() {
    let folders: Vec<String> = ["core", "guards", "shell", "files"]
        .map(String::from)
        .to_vec();
    let root = "\
[workspace.dependencies]
milo-guards-core = { path = \"crates/core\" }
milo-guards-shell = { path = \"crates/shell\" }
sneaky = { package = \"milo-guards-shell\", path = \"crates/shell\" }
";
    let wrong = |manifest: &str| wrong_dependencies("files", manifest, root, &folders);
    for dep in [
        "milo-guards-shell.workspace = true",
        "milo-guards = \"1\"",
        "renamed = { package = \"milo-guards-shell\", version = \"1\" }",
        "renamed = { path = \"../shell\" }",
        "renamed = { path = \"../../crates/guards/\" }",
        "sneaky.workspace = true",
        "other = { git = \"https://example.com/x\", package = \"milo-guards\" }",
    ] {
        assert_eq!(wrong(&format!("[dependencies]\n{dep}\n")).len(), 1, "{dep}");
        assert_eq!(
            wrong(&format!("[dev-dependencies]\n{dep}\n")).len(),
            1,
            "{dep} (dev)"
        );
    }
    let table = "[dependencies.renamed]\npath = \"../shell\"\n";
    assert_eq!(wrong(table).len(), 1, "{table}");
}

#[test]
fn the_core_and_a_guards_own_parsers_are_allowed() {
    let folders: Vec<String> = ["core", "guards", "shell", "files"]
        .map(String::from)
        .to_vec();
    let root = "[workspace.dependencies]\nmilo-guards-core = { path = \"crates/core\" }\n";
    let manifest = "\
[dependencies]
milo-guards-core.workspace = true
tree-sitter = \"0.26\"
renamed-core = { path = \"../core\" }
vendored = { path = \"../../vendor/parser\" }
[dev-dependencies]
milo-guards-core = { workspace = true, features = [\"testing\"] }
milo-guards-files = { path = \".\", default-features = false, features = [\"testing\"] }
";
    assert!(wrong_dependencies("files", manifest, root, &folders).is_empty());
    // The core depends on nothing at all.
    let core = wrong_dependencies("core", "[dependencies]\nserde = \"1\"\n", root, &folders);
    assert_eq!(core.len(), 1, "{core:?}");
    assert!(wrong_dependencies("core", "[package]\nname = \"x\"\n", root, &folders).is_empty());
}

#[test]
fn a_guard_may_build_on_a_code_reader_and_a_reader_on_no_guard() {
    let folders: Vec<String> = ["core", "guards", "shell", "code", "files"]
        .map(String::from)
        .to_vec();
    let root = "\
[workspace.dependencies]
milo-guards-core = { path = \"crates/core\" }
milo-guards-code = { path = \"crates/code\" }
milo-guards-shell = { path = \"crates/shell\" }
sneaky = { package = \"milo-guards-code\", path = \"crates/code\" }
";
    // A guard builds on a reader, in every form the manifest can name it.
    for dep in [
        "milo-guards-code = { workspace = true, optional = true }",
        "milo-guards-code.workspace = true",
        "renamed = { package = \"milo-guards-code\", version = \"1\" }",
        "renamed = { path = \"../code\" }",
        "sneaky.workspace = true",
    ] {
        let manifest = format!("[dependencies]\n{dep}\n");
        assert!(
            wrong_dependencies("files", &manifest, root, &folders).is_empty(),
            "{dep}"
        );
    }
    // A reader builds on the core and its parsers, and on no guard, no other
    // reader and not the front door.
    let parsers = "[dependencies]\nmilo-guards-core.workspace = true\ntree-sitter = \"0.26\"\n";
    assert!(wrong_dependencies("code", parsers, root, &folders).is_empty());
    for dep in [
        "milo-guards-shell.workspace = true",
        "milo-guards = \"1\"",
        "renamed = { path = \"../shell\" }",
        "renamed = { package = \"milo-guards-shell\", version = \"1\" }",
        "renamed = { path = \"../files\" }",
    ] {
        let manifest = format!("[dependencies]\n{dep}\n");
        assert_eq!(
            wrong_dependencies("code", &manifest, root, &folders).len(),
            1,
            "{dep}"
        );
    }
    assert!(is_reader_package("milo-guards-code"));
    assert!(!is_reader_package("milo-guards-shell"));
    assert!(!is_guard_package("milo-guards-code"));
}
