//! A program that starts the command after its own options hands that
//! command on, and the command is judged as one written alone: Windows'
//! console hosts and remote runners (`conhost`, `wt`, `psexec`, `nircmd`,
//! `pcalua`, rundll32's launchers, `gsudo`, Windows' `sudo`), WMI's process
//! class, and on POSIX systems the queues, the session, display and
//! container runners, the programs that run a command as another user or
//! with other limits, the toolboxes that share the home directory, and the
//! terminal emulators. An option the guard does not know may take the word
//! after it, so the command is not read past it.
//!
//! The lines and their answers are in `tests/cases/launchers.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("launchers");
}
