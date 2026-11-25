//! Where a shell is started, and how: the layers that keep a line from
//! running even if the shell's own no-exec mode did not.
//!
//! Every shell this tool starts is started by [`Room::start`], and only
//! there:
//!
//! - with an environment of its own and nothing else (`env_clear`): `HOME` is
//!   an empty folder of the room, so `~` is that folder; `PATH` is another
//!   empty folder, so a program named without a slash is found nowhere;
//!   `TMPDIR` is a third; no `BASH_ENV`, `ENV` or `ZDOTDIR` reaches it;
//! - in an empty working folder of the room;
//! - with its standard input a pipe that is closed once the text is written
//!   (the line, for a POSIX shell; nothing, for PowerShell);
//! - for a bounded time: past it the shell is killed and the line has no
//!   answer;
//! - with a bounded read of what it prints: past the cap the rest is read
//!   and dropped, so a shell that says a lot is not cut off mid-answer.
//!
//! After it ends, the room is checked: its working folder and `PATH` folder
//! must still be empty, and for bash its home and temporary folder too
//! (PowerShell keeps caches of its own in those two, so they are not watched
//! for it); nothing may still hold the shell's output open, which a program
//! it left running would; and bash must have printed nothing on its standard
//! output. A check that fails is a [`Failure::Stop`]: the tool stops at once
//! and says what it found.
//!
//! None of this is a sandbox of the operating system's. On macOS `just
//! grammars` runs the tool and its tests under `sandbox-exec` with
//! [`sandbox_profile`]; on Linux these layers and the shells' own modes are
//! all there is.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "this is the tool's one place that starts a process and the folders it runs in"
)]

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::Duration;

/// How long a shell may take, and how much of what it prints is read.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// How long the shell may run before it is killed.
    pub patience: Duration,
    /// The most bytes read from each of its standard output and error.
    pub output: usize,
}

impl Limits {
    /// The limits of one parse of one line by a POSIX shell.
    pub const LINE: Self = Self {
        patience: Duration::from_secs(10),
        output: 64 * 1024,
    };
}

/// A shell that ran to its end, and what it printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// Its exit code; `None` when a signal ended it.
    pub code: Option<i32>,
    /// What it printed on its standard output, up to the limit.
    pub stdout: Vec<u8>,
    /// What it printed on its standard error, up to the limit.
    pub stderr: Vec<u8>,
}

/// Why a shell gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// It could not be started, or its pipes failed: the tool's own problem.
    Start(String),
    /// It ran past its time and was killed.
    TimedOut,
    /// Something happened that a parse never does: a folder that must stay
    /// empty is not, something still holds the shell's output open, or a
    /// POSIX shell printed on its standard output. The tool stops.
    Stop(String),
}

/// The folders one worker starts its shells in, each empty and its own.
#[derive(Debug)]
pub struct Room {
    root: PathBuf,
    home: PathBuf,
    work: PathBuf,
    bin: PathBuf,
    tmp: PathBuf,
    input: PathBuf,
}

/// What is handed to a shell and what is checked once it ends.
#[derive(Debug)]
pub struct Start<'a> {
    /// The shell, by its absolute path.
    pub program: &'a Path,
    /// Its arguments: the no-exec flags and nothing from a line.
    pub args: Vec<OsString>,
    /// Variables set beside `HOME`, `PATH`, `TMPDIR` and `LC_ALL`.
    pub env: Vec<(&'static str, OsString)>,
    /// What its standard input is given before it is closed.
    pub stdin: &'a [u8],
    /// Whether its home must stay empty: a POSIX shell's must, PowerShell
    /// keeps caches of its own there.
    pub home_stays_empty: bool,
    /// Whether it must print nothing on its standard output: a POSIX shell
    /// in no-exec mode never does.
    pub silent: bool,
    /// How long it may run and how much it may print.
    pub limits: Limits,
}

/// The locale every shell reads its line in: UTF-8, as an agent's terminal
/// is, and the same on every machine.
pub const LOCALE: &str = "C.UTF-8";

/// Held while a program is started, by every thread of the tool. Starting
/// one makes its pipes, and on macOS a pipe is made first and marked
/// close-on-exec after, so a program another thread starts in between
/// inherits the pipe: when it lives long (a PowerShell batch, a program a
/// test leaves running), it holds the other room's output open and that
/// room stops the run, though its own program did nothing. `spawn` returns
/// once the parent has closed its copies of the child's ends, so holding
/// this across it is enough.
static STARTING: Mutex<()> = Mutex::new(());

/// The tool's process id, for the names of the folders it makes.
pub fn id() -> u32 {
    std::process::id()
}

/// End the tool with `code`.
#[allow(clippy::exit, reason = "the program's one way out, with its code")]
pub fn end(code: i32) -> ! {
    std::process::exit(code)
}

/// Make the FIFO `path` with `/usr/bin/mkfifo`, for the tests that show a
/// shell opens no file a line names; whether it was made.
pub fn make_fifo(path: &Path) -> bool {
    let _starting = STARTING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Command::new("/usr/bin/mkfifo")
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether this process can read under `/Users` on macOS, which the
/// sandbox of `just grammars` refuses: then nothing but the room's layers
/// stands between a line and the machine, and the tool does not start a
/// shell unless told to (`--unsandboxed`). Elsewhere, `false`: there is no
/// such sandbox to be outside of.
pub fn unsandboxed_on_macos() -> bool {
    cfg!(target_os = "macos") && fs::read_dir("/Users").is_ok()
}

impl Room {
    /// Make a room at `root`, which must not exist yet: its own folder and
    /// the empty folders a shell is started with.
    pub fn new(root: &Path) -> io::Result<Self> {
        fs::create_dir(root)?;
        // Absolute: `HOME` and the rest are read by the shell from its own
        // working folder.
        let root = root.canonicalize()?;
        let room = Self {
            home: root.join("home"),
            work: root.join("work"),
            bin: root.join("bin"),
            tmp: root.join("tmp"),
            input: root.join("input"),
            root,
        };
        for folder in [&room.home, &room.work, &room.bin, &room.tmp, &room.input] {
            fs::create_dir(folder)?;
        }
        Ok(room)
    }

    /// The room's own folder.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The folder the room keeps what it hands a shell as a file: a batch of
    /// lines for PowerShell, each encoded, never a line as written.
    pub fn input(&self) -> &Path {
        &self.input
    }

    /// The empty folder a shell runs in.
    pub fn work(&self) -> &Path {
        &self.work
    }

    /// The empty folder that is `TMPDIR`.
    pub fn tmp(&self) -> &Path {
        &self.tmp
    }

    /// The empty folder that is `HOME`.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The empty folder that is `PATH`, and `PSModulePath` for PowerShell.
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// Start `start.program` in this room with every layer, give it
    /// `start.stdin`, wait for it within its limits, and check the room.
    pub fn start(&self, start: &Start<'_>) -> Result<Finished, Failure> {
        let mut command = Command::new(start.program);
        command
            .args(&start.args)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", &self.bin)
            .env("TMPDIR", &self.tmp)
            .env("LC_ALL", LOCALE)
            .current_dir(&self.work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &start.env {
            command.env(name, value);
        }
        let spawned = {
            let _starting = STARTING
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            command.spawn()
        };
        let mut child = spawned.map_err(|e| {
            Failure::Start(format!("cannot start {}: {e}", start.program.display()))
        })?;
        let (Some(mut input), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Failure::Start(
                "the shell's pipes were not made".to_string(),
            ));
        };
        let (sent, outputs) = mpsc::channel();
        let readers = [(0, stdout_reader(stdout)), (1, stderr_reader(stderr))];
        for (which, mut reader) in readers {
            let sent = sent.clone();
            let cap = start.limits.output;
            thread::spawn(move || {
                let _ = sent.send((which, capped(&mut reader, cap)));
            });
        }
        drop(sent);
        // Written from a thread of its own, so a shell that does not read
        // its input cannot hold this one: it is killed when its time is up.
        let text = start.stdin.to_vec();
        let writer = thread::spawn(move || {
            // A shell that ends before reading all of it closes the pipe;
            // what it said is what counts.
            let _ = input.write_all(&text);
            drop(input);
        });
        let status = wait_within(&mut child, start.limits.patience);
        let _ = writer.join();
        let status = status?;
        // Each reader ends when every holder of the pipe has closed it. The
        // shell has ended, so a reader that does not end soon has a program
        // the shell started still holding its output.
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        for _ in 0..2 {
            match outputs.recv_timeout(Duration::from_secs(5)) {
                Ok((0, read)) => stdout = read,
                Ok((_, read)) => stderr = read,
                Err(_) => {
                    return Err(Failure::Stop(format!(
                        "something still holds the output of {} open after it ended: a program it started may be running",
                        start.program.display()
                    )))
                }
            }
        }
        self.check(start)?;
        if start.silent && !stdout.is_empty() {
            return Err(Failure::Stop(format!(
                "{} printed on its standard output in no-exec mode: {:?}",
                start.program.display(),
                String::from_utf8_lossy(&stdout)
            )));
        }
        Ok(Finished {
            code: status.code(),
            stdout,
            stderr,
        })
    }

    /// The room after a shell ended: every folder that must stay empty is.
    fn check(&self, start: &Start<'_>) -> Result<(), Failure> {
        let mut watched = vec![&self.work, &self.bin];
        if start.home_stays_empty {
            watched.push(&self.home);
            watched.push(&self.tmp);
        }
        for folder in watched {
            let entries = fs::read_dir(folder).map_err(|e| {
                Failure::Stop(format!(
                    "cannot read {} after a parse: {e}",
                    folder.display()
                ))
            })?;
            if let Some(entry) = entries.flatten().next() {
                return Err(Failure::Stop(format!(
                    "{} appeared after {} parsed a line: a line may have run",
                    entry.path().display(),
                    start.program.display()
                )));
            }
        }
        Ok(())
    }
}

/// Wait for `child` to end, for at most about `patience`; kill it past that.
/// It sleeps between looks and counts them, and reads no clock.
fn wait_within(child: &mut std::process::Child, patience: Duration) -> Result<ExitStatus, Failure> {
    // A parse takes a few milliseconds: look often at first, then less.
    const QUICK: Duration = Duration::from_millis(1);
    const QUICK_LOOKS: u32 = 50;
    const SLOW: Duration = Duration::from_millis(10);
    let quick = QUICK * QUICK_LOOKS;
    let slow_looks = u32::try_from(patience.saturating_sub(quick).as_millis() / SLOW.as_millis())
        .unwrap_or(u32::MAX);
    for look in 0..QUICK_LOOKS.saturating_add(slow_looks) {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => thread::sleep(if look < QUICK_LOOKS { QUICK } else { SLOW }),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Failure::Start(format!("cannot wait for the shell: {e}")));
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(Failure::TimedOut)
}

fn stdout_reader(stdout: std::process::ChildStdout) -> Box<dyn Read + Send> {
    Box::new(stdout)
}

fn stderr_reader(stderr: std::process::ChildStderr) -> Box<dyn Read + Send> {
    Box::new(stderr)
}

/// Up to `cap` bytes of `reader`, and the rest read and dropped: a shell
/// that prints more ends as it would, not killed by a closed pipe.
fn capped(reader: &mut dyn Read, cap: usize) -> Vec<u8> {
    let mut read = Vec::new();
    let _ = reader
        .take(u64::try_from(cap).unwrap_or(u64::MAX))
        .read_to_end(&mut read);
    let _ = io::copy(reader, &mut io::sink());
    read
}

/// The `sandbox-exec` profile `just grammars` runs the tool and its tests
/// under on macOS: no network; no read under `/Users` but of `checkout`,
/// the repository, whose case files and builds the tool reads (a later rule
/// wins, so a checkout under `/Users` still works); no write but under
/// `temp`, where the rooms and the tests' folders are, and to `/dev`.
pub fn sandbox_profile(checkout: &Path, temp: &Path) -> String {
    let quoted = |path: &Path| format!("{:?}", path.display().to_string());
    format!(
        "(version 1)\n(allow default)\n(deny network*)\n(deny file-read* (subpath \"/Users\"))\n\
         (allow file-read* (subpath {}))\n(deny file-write*)\n\
         (allow file-write* (subpath {}) (subpath \"/dev\"))\n",
        quoted(checkout),
        quoted(temp)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_names_the_checkout_and_the_temporary_folder() {
        let profile = sandbox_profile(Path::new("/Users/me/repo"), Path::new("/private/var/t"));
        assert!(profile.contains("(deny file-read* (subpath \"/Users\"))\n(allow file-read* (subpath \"/Users/me/repo\"))"), "{profile}");
        assert!(
            profile.contains("(allow file-write* (subpath \"/private/var/t\") (subpath \"/dev\"))"),
            "{profile}"
        );
        assert!(profile.contains("(deny network*)"), "{profile}");
    }

    #[test]
    fn a_read_stops_at_its_cap() {
        let mut text: &[u8] = b"abcdef";
        assert_eq!(capped(&mut text, 4), b"abcd");
        let mut short: &[u8] = b"ab";
        assert_eq!(capped(&mut short, 4), b"ab");
    }
}
