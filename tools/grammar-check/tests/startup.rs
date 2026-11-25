//! bash reads no startup file and nothing of the environment it is started
//! from. Under `-n` it would run none of them anyway, so the environment is
//! shown on a bash given no text at all, with the flags it parses lines with
//! but the no-exec ones: `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`,
//! `PROMPT_COMMAND` and an exported function, each a canary that leaves a
//! file if it runs, and none does, nor does a profile or `.bashrc` in its
//! home. A profile is read only by a login shell and `.bashrc` only by an
//! interactive one, and the tool starts neither (nor does this test, which
//! could reach a terminal), so `--noprofile` and `--norc` are held by the
//! arguments the room is given. It is one test, in a file of its own,
//! because it sets the variables in its own process first.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    clippy::unwrap_used,
    reason = "the test sets its own environment and makes its own folders"
)]

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::time::Duration;

use grammar_check::room::{self, Limits, Room, Start};
use grammar_check::shells::{self, Kind, BASH_STARTUP};

/// Start bash at `bash` in `room` with `flags` after its startup flags and
/// `text` on its input; whether it ended.
fn started(bash: &Path, room: &Room, flags: &[&str], text: &[u8]) -> Option<i32> {
    let args: Vec<OsString> = BASH_STARTUP
        .iter()
        .chain(flags)
        .map(OsString::from)
        .collect();
    room.start(&Start {
        program: bash,
        args,
        env: Vec::new(),
        stdin: text,
        // The canary startup files are there on purpose.
        home_stays_empty: false,
        silent: true,
        limits: Limits::LINE,
    })
    .unwrap()
    .code
}

#[test]
fn bash_reads_no_startup_file_and_nothing_of_the_parent() {
    let Some(bash) = shells::on_path(Kind::Bash.name(), std::env::var_os("PATH").as_deref()) else {
        eprintln!("bash is not installed: skipped");
        return;
    };
    let folder = std::env::temp_dir().join(format!("grammar-check-startup-{}", room::id()));
    let _ = fs::remove_dir_all(&folder);
    let canaries = folder.join("canaries");
    fs::create_dir_all(&canaries).unwrap();
    let c = canaries.display();
    let script = folder.join("script");
    fs::write(&script, format!("true\necho ran > {c}/script\n")).unwrap();
    // The parent's environment, which the room must not hand on.
    std::env::set_var("BASH_ENV", &script);
    std::env::set_var("ENV", &script);
    std::env::set_var("SHELLOPTS", "xtrace");
    std::env::set_var("BASHOPTS", "expand_aliases");
    std::env::set_var("PS4", format!("$(echo ran > {c}/ps4)"));
    std::env::set_var("PROMPT_COMMAND", format!("echo ran > {c}/prompt_command"));
    std::env::set_var(
        "BASH_FUNC_true%%",
        format!("() {{ echo ran > {c}/function; }}"),
    );
    std::env::set_var(
        "BASH_FUNC_true()",
        format!("() {{ echo ran > {c}/function_old; }}"),
    );
    let room = Room::new(&folder.join("room")).unwrap();
    for name in [".bash_profile", ".bash_login", ".profile", ".bashrc"] {
        fs::write(room.home().join(name), format!("echo ran > {c}/{name}\n")).unwrap();
    }
    // A line, parsed as the tool parses every line.
    let mut parse = shells::bash_parse(&bash, "true; echo hi");
    parse.home_stays_empty = false;
    assert_eq!(room.start(&parse).unwrap().code, Some(0));
    // No text at all, and no `-n`: the parent's variables do not reach it,
    // so `BASH_ENV` (which a bash reading a script runs first) is not read.
    assert_eq!(started(&bash, &room, &[], b""), Some(0));
    // The flags that keep a profile and `.bashrc` out are the room's, in
    // front of the no-exec ones, for every line.
    assert_eq!(shells::bash_args(), ["--noprofile", "--norc", "-r", "-n"]);
    assert_eq!(shells::bash_parse(&bash, "x").args, shells::bash_args());
    std::thread::sleep(Duration::from_millis(500));
    let mut fired: Vec<String> = fs::read_dir(&canaries)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    fired.sort();
    let _ = fs::remove_dir_all(&folder);
    assert_eq!(fired, [] as [String; 0]);
}
