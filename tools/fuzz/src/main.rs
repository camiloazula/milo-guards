//! `fuzz`: seeds a fuzz target from the case files, builds it with
//! cargo-fuzz and runs it for a time, and says only whether it found an
//! input that breaks a promise and where it kept it. `just fuzz` runs it;
//! see `CONTRIBUTING.md`.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a program: it reads its arguments, prints, and ends with its code"
)]

use std::path::PathBuf;

use fuzz::promises::Target;
use fuzz::run::{self, ExitCode, Options, Outcome};

const USAGE: &str = "usage: fuzz run TARGET [SECONDS] [--out DIR] [--keep-going] [--private]
       fuzz seeds TARGET DIR
       fuzz targets";

fn main() -> ExitCode {
    match command(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// The target `name` names.
fn target(name: Option<&String>) -> Result<Target, String> {
    let name = name.ok_or("no target named")?;
    Target::named(name).ok_or_else(|| {
        let names: Vec<&str> = Target::ALL.iter().map(|target| target.name()).collect();
        format!("no target `{name}`: the targets are {}", names.join(", "))
    })
}

/// Do what `args` ask, and say with what code to end.
fn command(args: Vec<String>) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("targets") => {
            for target in Target::ALL {
                println!("{}", target.name());
            }
            Ok(ExitCode::SUCCESS)
        }
        Some("seeds") => {
            let target = target(args.get(1))?;
            let folder = PathBuf::from(args.get(2).ok_or("no folder named")?);
            let count = run::write_seeds(target, &folder)?;
            println!("{}: {count} seeds in {}", target.name(), folder.display());
            Ok(ExitCode::SUCCESS)
        }
        Some("run") => {
            let options = options(&args[1..])?;
            let name = options.target.name();
            let shown =
                |count: Option<u64>| count.map_or_else(|| "unknown".to_string(), |n| n.to_string());
            match run::run(&options)? {
                Outcome::Clean(counts) => {
                    println!(
                        "{name}: found nothing in {} s: {} inputs run, coverage {}, features {}, \
                         corpus {}",
                        options.seconds,
                        shown(counts.executions),
                        shown(counts.coverage),
                        shown(counts.features),
                        shown(counts.corpus)
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Outcome::Found(counts, files) => {
                    let found = options.out.join("found").join(name);
                    println!(
                        "{name}: found {} input(s) that break a promise, hang or crash, after {} \
                         inputs run, kept in {} with the log. They are a security report: \
                         report them privately, as SECURITY.md says, never in an issue, a pull \
                         request or a case file.",
                        files.len().max(1),
                        shown(counts.executions),
                        found.display()
                    );
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        _ => Err("no command".to_string()),
    }
}

/// The options of `run`.
fn options(args: &[String]) -> Result<Options, String> {
    let target = target(args.first())?;
    let mut seconds = 300;
    let mut out = run::root().join("target/fuzz");
    let mut private = false;
    let mut keep_going = false;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => out = PathBuf::from(rest.next().ok_or("--out takes a folder")?),
            "--private" => private = true,
            "--keep-going" => keep_going = true,
            number => {
                seconds = number
                    .parse()
                    .map_err(|_| format!("`{number}` is not a number of seconds"))?;
            }
        }
    }
    Ok(Options {
        target,
        seconds,
        out,
        keep_going,
        private,
    })
}
