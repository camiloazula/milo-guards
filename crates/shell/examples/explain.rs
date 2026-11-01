//! Prints how the shell guard reads a line: every program it runs, where its
//! arguments land, and what each found.
//!
//! ```text
//! cargo run -p milo-guards-shell --example explain -- \
//!     --shell posix --cwd /work/app --home /home/me --workspace /work/app \
//!     'sudo rm -rf ~ && bash -c "git reset --hard"'
//! ```
//!
//! Options: `--shell posix|powershell|cmd` (default `posix`), `--cwd`,
//! `--home`, and `--workspace` (repeat it for more than one folder). The
//! last argument is the line. This is the one place that reads arguments and
//! prints: the guard itself does neither.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "an example is a program: it reads its arguments and prints; the guard does neither"
)]

use milo_guards_shell::{explain, Paths, Shell};

const USAGE: &str = "usage: explain [--shell posix|powershell|cmd] [--cwd DIR] [--home DIR] \
[--workspace DIR]... '<line>'";

fn main() {
    match run(std::env::args().skip(1)) {
        Ok(tree) => print!("{tree}"),
        Err(message) => {
            eprintln!("{message}\n{USAGE}");
            std::process::exit(2);
        }
    }
}

fn run(args: impl Iterator<Item = String>) -> Result<String, String> {
    let mut shell = Shell::Posix;
    let mut cwd = "/work/app".to_string();
    let mut home = "/home/me".to_string();
    let mut workspaces: Vec<String> = Vec::new();
    let mut line = None;
    let mut args = args;
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--shell" => {
                shell = match value("--shell")?.as_str() {
                    "posix" => Shell::Posix,
                    "powershell" => Shell::PowerShell,
                    "cmd" => Shell::Cmd,
                    other => return Err(format!("unknown shell {other:?}")),
                };
            }
            "--cwd" => cwd = value("--cwd")?,
            "--home" => home = value("--home")?,
            "--workspace" => workspaces.push(value("--workspace")?),
            _ if line.is_none() => line = Some(arg),
            _ => return Err("only one line is read".to_string()),
        }
    }
    let line = line.ok_or("no line given")?;
    if workspaces.is_empty() {
        workspaces.push(cwd.clone());
    }
    let paths = Paths::new(cwd, home, workspaces);
    Ok(explain(&line, shell, &paths).to_string())
}
