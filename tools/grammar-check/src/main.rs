//! `grammar-check`: prints how the shell guard's grammars and the real shells
//! read every POSIX and PowerShell line of the case files and a generated
//! set, and fails on a difference not on the known list. `just grammars`
//! runs it; see `CONTRIBUTING.md`.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a program: it reads its arguments and the environment, prints, and ends with its code"
)]

use std::path::{Path, PathBuf};

use grammar_check::check::{self, Options, Status};
use grammar_check::room;
use grammar_check::shells::{self, Kind};

const USAGE: &str = "usage: grammar-check [--scratch DIR] [--cases DIR]... [--known FILE] \
[--bash PATH] [--pwsh PATH] [--with pwsh] [--without bash|pwsh]... [--require bash|pwsh]... \
[--generated N] [--jobs N] [--entries] [--private] [--unsandboxed]
       grammar-check --sandbox-profile FILE";

fn main() {
    match options(std::env::args().skip(1)) {
        Ok(Some(options)) => {
            let outcome = check::run(&options);
            print!("{}", outcome.report);
            room::end(outcome.code);
        }
        Ok(None) => {}
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            room::end(2);
        }
    }
}

/// The repository's root, where the case files are.
fn root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().unwrap_or(root)
}

/// The options of a run, or `None` when the arguments asked for something
/// else, done here.
fn options(mut args: impl Iterator<Item = String>) -> Result<Option<Options>, String> {
    let root = root();
    let mut cases = Vec::new();
    let mut known = root.join("tools/grammar-check/known.cases");
    let mut scratch = std::env::temp_dir();
    let mut paths: Vec<(Kind, PathBuf)> = Vec::new();
    let mut with = Vec::new();
    let mut without = Vec::new();
    let mut required = Vec::new();
    let mut generated = 1000;
    let mut jobs = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let mut private = false;
    let mut entries = false;
    let mut unsandboxed = false;
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} wants a value"));
        let shell = |value: String| Kind::named(&value).ok_or(format!("no shell `{value}`"));
        match arg.as_str() {
            "--sandbox-profile" => {
                let file = PathBuf::from(value()?);
                let temp = std::env::temp_dir();
                let temp = temp.canonicalize().unwrap_or(temp);
                if let Some(folder) = file.parent() {
                    std::fs::create_dir_all(folder).map_err(|e| e.to_string())?;
                }
                std::fs::write(&file, room::sandbox_profile(&root, &temp))
                    .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
                return Ok(None);
            }
            "--scratch" => scratch = PathBuf::from(value()?),
            "--cases" => cases.push(PathBuf::from(value()?)),
            "--known" => known = PathBuf::from(value()?),
            "--bash" | "--pwsh" => {
                let kind = shell(arg[2..].to_string())?;
                paths.push((kind, PathBuf::from(value()?)));
            }
            "--with" => with.push(shell(value()?)?),
            "--without" => without.push(shell(value()?)?),
            "--require" => required.push(shell(value()?)?),
            "--generated" => {
                generated = value()?.parse().map_err(|_| "--generated wants a number")?;
            }
            "--jobs" => jobs = value()?.parse().map_err(|_| "--jobs wants a number")?,
            "--private" => private = true,
            "--entries" => entries = true,
            "--unsandboxed" => unsandboxed = true,
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    if cases.is_empty() {
        cases = vec![
            root.join("crates/shell/tests/cases"),
            root.join("crates/guards/tests/cases"),
        ];
    }
    let path_var = std::env::var_os("PATH");
    let shells = Kind::ALL
        .into_iter()
        .map(|kind| {
            // PowerShell's half has not run anywhere yet: it is asked only
            // when the run says so.
            let on = !without.contains(&kind)
                && (kind != Kind::Pwsh || with.contains(&kind) || required.contains(&kind));
            if !on {
                return (kind, Status::Off);
            }
            let given = paths
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, p)| p.clone());
            match given.or_else(|| shells::on_path(kind.name(), path_var.as_deref())) {
                Some(path) => (kind, Status::At(path)),
                None => (kind, Status::NotInstalled),
            }
        })
        .collect();
    Ok(Some(Options {
        root,
        cases,
        known,
        scratch,
        shells,
        required,
        generated,
        private,
        entries,
        jobs,
        unsandboxed,
    }))
}
