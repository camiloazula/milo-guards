//! Each layer of the room (`src/room.rs`), held on its own, with programs
//! that are not shells and no line at all: the environment a program is
//! started with is the room's and nothing else, it starts in the room's
//! working folder, its input is closed, it is killed past its time, what it
//! prints past the cap is read and dropped, a program it leaves holding its
//! output stops the run, and so does a file left in the room or a word on
//! the standard output of a shell that must print none.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::disallowed_macros,
    clippy::unwrap_used,
    reason = "the test makes its own folders and starts plain programs in a room"
)]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use grammar_check::room::{Failure, Finished, Limits, Room, Start, LOCALE};

/// A room in a folder of the test's own.
fn room(name: &str) -> (PathBuf, Room) {
    let folder = std::env::temp_dir().join(format!(
        "grammar-check-room-{name}-{}",
        grammar_check::room::id()
    ));
    let _ = fs::remove_dir_all(&folder);
    fs::create_dir_all(&folder).unwrap();
    let room = Room::new(&folder.join("room")).unwrap();
    (folder, room)
}

fn start(room: &Room, program: &str, args: &[&str], stdin: &[u8]) -> Result<Finished, Failure> {
    start_with(room, program, args, stdin, Limits::LINE, false)
}

fn start_with(
    room: &Room,
    program: &str,
    args: &[&str],
    stdin: &[u8],
    limits: Limits,
    silent: bool,
) -> Result<Finished, Failure> {
    room.start(&Start {
        program: Path::new(program),
        args: args.iter().map(OsString::from).collect(),
        env: Vec::new(),
        stdin,
        home_stays_empty: true,
        silent,
        limits,
    })
}

#[test]
fn a_program_gets_the_rooms_environment_and_nothing_else() {
    let (folder, room) = room("environment");
    let printed = start(&room, "/usr/bin/env", &[], b"").unwrap();
    let mut seen: Vec<String> = String::from_utf8_lossy(&printed.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    seen.sort();
    let mut wanted = vec![
        format!("HOME={}", room.home().display()),
        format!("LC_ALL={LOCALE}"),
        format!("PATH={}", room.bin().display()),
        format!("TMPDIR={}", room.tmp().display()),
    ];
    wanted.sort();
    assert_eq!(seen, wanted);
    // It starts in the room's working folder.
    let here = start(&room, "/bin/pwd", &["-P"], b"").unwrap();
    assert_eq!(
        String::from_utf8_lossy(&here.stdout).trim(),
        room.work().display().to_string()
    );
    let _ = fs::remove_dir_all(folder);
}

#[test]
fn a_programs_input_is_closed_after_its_text() {
    let (folder, room) = room("input");
    // `cat` ends only at the end of its input.
    let read = start(&room, "/bin/cat", &[], b"some text").unwrap();
    assert_eq!(
        (read.code, read.stdout.as_slice()),
        (Some(0), &b"some text"[..])
    );
    let _ = fs::remove_dir_all(folder);
}

#[test]
fn a_program_past_its_time_is_killed() {
    let (folder, room) = room("time");
    let limits = Limits {
        patience: Duration::from_millis(500),
        output: 1024,
    };
    assert_eq!(
        start_with(&room, "/bin/sleep", &["20"], b"", limits, false),
        Err(Failure::TimedOut)
    );
    let _ = fs::remove_dir_all(folder);
}

#[test]
fn what_a_program_prints_past_the_cap_is_dropped_and_it_ends_as_it_would() {
    let (folder, room) = room("cap");
    let limits = Limits {
        patience: Duration::from_secs(10),
        output: 64 * 1024,
    };
    let printed = start_with(
        &room,
        "/usr/bin/head",
        &["-c", "300000", "/dev/zero"],
        b"",
        limits,
        false,
    )
    .unwrap();
    // It was not cut off by a closed pipe: it ended with 0.
    assert_eq!((printed.code, printed.stdout.len()), (Some(0), 64 * 1024));
    let _ = fs::remove_dir_all(folder);
}

#[test]
fn a_program_left_holding_the_output_stops_the_run() {
    let (folder, room) = room("held");
    match start(&room, env!("CARGO_BIN_EXE_hold-output-open"), &[], b"") {
        Err(Failure::Stop(why)) => assert!(why.contains("still holds the output"), "{why}"),
        other => panic!("a program left holding the output must stop the run: {other:?}"),
    }
    let _ = fs::remove_dir_all(folder);
}

#[test]
fn a_program_started_beside_another_does_not_inherit_its_pipes() {
    // Long-lived programs started while short ones are: were a long one to
    // inherit a short one's pipe while it is made, the short one's room
    // would find its output held open after it ended, and stop. Without the
    // room's lock around a start this failed about one run in ten here; it is
    // a check of the lock, not a proof of it.
    let folder = std::env::temp_dir().join(format!(
        "grammar-check-room-beside-{}",
        grammar_check::room::id()
    ));
    let _ = fs::remove_dir_all(&folder);
    fs::create_dir_all(&folder).unwrap();
    let done = std::sync::atomic::AtomicBool::new(false);
    let stops = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let mut long = Vec::new();
        for n in 0..150 {
            let folder = &folder;
            long.push(scope.spawn(move || {
                let room = Room::new(&folder.join(format!("long-{n}"))).unwrap();
                // Longer than the room waits for a closed output (5 s).
                let _ = start(&room, "/bin/sleep", &["6"], b"");
            }));
        }
        for n in 0..6 {
            let (folder, done, stops) = (&folder, &done, &stops);
            scope.spawn(move || {
                let room = Room::new(&folder.join(format!("short-{n}"))).unwrap();
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Err(Failure::Stop(_)) = start(&room, "/usr/bin/true", &[], b"") {
                        stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            });
        }
        for handle in long {
            let _ = handle.join();
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let _ = fs::remove_dir_all(&folder);
    assert_eq!(
        stops.into_inner(),
        0,
        "a short program's output was held open"
    );
}

#[test]
fn a_word_on_a_silent_programs_output_stops_the_run() {
    let (folder, room) = room("silent");
    match start_with(&room, "/bin/echo", &["ran"], b"", Limits::LINE, true) {
        Err(Failure::Stop(why)) => assert!(why.contains("printed on its standard output"), "{why}"),
        other => panic!("a word on the output must stop the run: {other:?}"),
    }
    let _ = fs::remove_dir_all(folder);
}

#[test]
fn a_file_left_in_the_room_stops_the_run() {
    for (n, folder) in ["work", "home", "bin", "tmp"].into_iter().enumerate() {
        let (scratch, room) = room(&format!("left-{n}"));
        let target = match folder {
            "work" => room.work().to_path_buf(),
            "home" => room.home().to_path_buf(),
            "bin" => room.bin().to_path_buf(),
            _ => room.tmp().to_path_buf(),
        };
        fs::write(target.join("left"), "").unwrap();
        match start(&room, "/usr/bin/true", &[], b"") {
            Err(Failure::Stop(why)) => assert!(why.contains("appeared"), "{why}"),
            other => panic!("a file in the room's {folder} must stop the run: {other:?}"),
        }
        let _ = fs::remove_dir_all(scratch);
    }
}

#[test]
fn the_sandbox_of_just_grammars_holds_where_it_is_said_to() {
    // `just grammars` sets this when it runs the tests under sandbox-exec,
    // on macOS; elsewhere there is no sandbox to hold.
    if std::env::var_os("GRAMMAR_CHECK_SANDBOXED").is_none_or(|value| value.is_empty()) {
        eprintln!("not under the sandbox of just grammars: skipped");
        return;
    }
    // No read under /Users, though the files are there to read.
    assert!(fs::read_dir("/Users").is_err(), "/Users can be listed");
    assert!(
        fs::read("/Users/Shared/.localized").is_err() || !Path::new("/Users/Shared").exists(),
        "a file under /Users can be read"
    );
    // The checkout is read (its case files), wherever it is.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    assert!(
        fs::read(&manifest).is_ok(),
        "{} cannot be read",
        manifest.display()
    );
    // No write but in the temporary folder.
    let beside = Path::new(env!("CARGO_MANIFEST_DIR")).join("sandbox-canary");
    assert!(
        fs::write(&beside, "").is_err(),
        "{} was written",
        beside.display()
    );
    let _ = fs::remove_file(&beside);
    let temp = std::env::temp_dir().join(format!(
        "grammar-check-sandbox-{}",
        grammar_check::room::id()
    ));
    assert!(
        fs::write(&temp, "").is_ok(),
        "the temporary folder cannot be written"
    );
    let _ = fs::remove_file(&temp);
    // And bash starts.
    let (folder, room) = room("sandbox");
    let bash = start(
        &room,
        "/bin/bash",
        &["--noprofile", "--norc", "--version"],
        b"",
    )
    .unwrap();
    assert_eq!(bash.code, Some(0));
    let _ = fs::remove_dir_all(folder);
}
