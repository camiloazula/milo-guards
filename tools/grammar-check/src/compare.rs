//! The guard's reading of a line beside a shell's.
//!
//! What can be compared is what the shell can say without running anything:
//!
//! - bash, in no-exec mode, says only whether it accepts the line (and its
//!   first error). So a POSIX line is compared by that alone.
//! - PowerShell's parser gives its whole tree. A line both accept is also
//!   compared by its commands: every command of the line's own script (not
//!   one inside a script block, which runs only when called) must be a
//!   program the guard read at the line's own depth, by its name, and its
//!   words must be the guard's, where both know them.

use milo_guards_shell::testing::Grammar;

use crate::guard::{Program, Reading};
use crate::powershell::{Command, Parsed, Word};
use crate::shells::Verdict;

/// How a shell's reading and the guard's differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// (a) The shell accepts the line and the grammar reads it with an
    /// error, or the guard never hands it to the grammar: the guard answers
    /// `unreadable`, which is cautious.
    GrammarRejects,
    /// (b) The grammar reads the line whole and the shell refuses it: the
    /// line does not run as written.
    ShellRejects,
    /// (c) Both accept the line, and the guard split it otherwise: a command
    /// it does not read, or other words. Reported privately (SECURITY.md),
    /// never kept on the known list.
    Split,
}

impl Kind {
    /// Its name on the known list and in the report.
    pub const fn name(self) -> &'static str {
        match self {
            Self::GrammarRejects => "grammar_rejects",
            Self::ShellRejects => "shell_rejects",
            Self::Split => "split",
        }
    }

    /// What it means, in the report's words.
    pub const fn says(self) -> &'static str {
        match self {
            Self::GrammarRejects => {
                "the shell accepts it and the guard's grammar does not read it whole"
            }
            Self::ShellRejects => "the guard's grammar reads it whole and the shell refuses it",
            Self::Split => "both accept it and the guard splits it otherwise",
        }
    }
}

/// One difference, in words: its kind, what the shell said and what the
/// guard read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Found {
    /// Its kind.
    pub kind: Kind,
    /// What the shell said.
    pub shell: String,
    /// What the guard read.
    pub guard: String,
}

/// What the grammar's reading is, in words.
fn grammar_words(grammar: Grammar) -> &'static str {
    match grammar {
        Grammar::Whole => "reads it whole",
        Grammar::Error => "reads it with an error (unreadable)",
        _ => "never hands it to the grammar (unreadable)",
    }
}

/// How a POSIX shell's verdict and the guard's reading differ, if they do.
pub fn posix(reading: &Reading, verdict: &Verdict) -> Option<Found> {
    let whole = reading.grammar == Grammar::Whole;
    match verdict {
        Verdict::Accepts if !whole => Some(Found {
            kind: Kind::GrammarRejects,
            shell: "accepts".to_string(),
            guard: grammar_words(reading.grammar).to_string(),
        }),
        Verdict::Rejects(error) if whole => Some(Found {
            kind: Kind::ShellRejects,
            shell: format!("refuses: {error}"),
            guard: grammar_words(reading.grammar).to_string(),
        }),
        _ => None,
    }
}

/// How PowerShell's parse and the guard's reading differ, if they do.
pub fn powershell(reading: &Reading, parsed: &Parsed) -> Option<Found> {
    let whole = reading.grammar == Grammar::Whole;
    match parsed {
        Parsed::Rejects(offset, id) if whole => Some(Found {
            kind: Kind::ShellRejects,
            shell: format!("refuses: {id} at offset {offset}"),
            guard: grammar_words(reading.grammar).to_string(),
        }),
        Parsed::Rejects(..) => None,
        Parsed::Accepts(_) if !whole => Some(Found {
            kind: Kind::GrammarRejects,
            shell: "accepts".to_string(),
            guard: grammar_words(reading.grammar).to_string(),
        }),
        Parsed::Accepts(commands) => split(&reading.programs, commands),
    }
}

/// A text as compared: PowerShell reads the dashes and quotes of other
/// scripts as its own, and so does the guard.
fn fold(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\u{2013}' | '\u{2014}' | '\u{2015}' => '-',
            '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => '\'',
            '\u{201c}' | '\u{201d}' | '\u{201e}' => '"',
            c => c,
        })
        .collect()
}

/// A name as compared: PowerShell's names have no case.
fn name(text: &str) -> String {
    fold(text).to_lowercase()
}

/// The name of a command, when the parser knows it.
fn command_name(command: &Command) -> Option<String> {
    match command.words.first()? {
        Word::Value(text) | Word::Parameter(text) => Some(name(text)),
        Word::Unknown => None,
    }
}

/// Whether the guard's word `guard` is the parser's word `shell`, where both
/// know it.
fn same_word(guard: Option<&str>, shell: &Word) -> bool {
    match (guard, shell) {
        (None, _) | (_, Word::Unknown) => true,
        (Some(guard), Word::Parameter(text)) => name(guard) == name(text),
        (Some(guard), Word::Value(text)) => fold(guard) == fold(text),
    }
}

/// Whether the program's words (its name, then its arguments) are the
/// command's.
fn same_words(program: &Program, command: &Command) -> bool {
    program.args.len() + 1 == command.words.len()
        && command_name(command).is_none_or(|shell| name(&program.program) == shell)
        && program
            .args
            .iter()
            .zip(&command.words[1..])
            .all(|(guard, shell)| same_word(guard.as_deref(), shell))
}

/// The commands of the line's own script beside the programs the guard read.
fn split(programs: &[Program], commands: &[Command]) -> Option<Found> {
    let mut taken = vec![false; programs.len()];
    let mut missing = Vec::new();
    let mut other = Vec::new();
    for command in commands.iter().filter(|command| !command.nested) {
        let Some(wanted) = command_name(command) else {
            continue;
        };
        let by_name = |program: &Program| name(&program.program) == wanted;
        let by_wrapper =
            |program: &Program| program.wrappers.first().is_some_and(|w| name(w) == wanted);
        let free = |index: &usize| !taken[*index];
        let exact = (0..programs.len())
            .filter(free)
            .find(|&i| by_name(&programs[i]) && same_words(&programs[i], command));
        if let Some(index) = exact {
            taken[index] = true;
            continue;
        }
        if let Some(index) = (0..programs.len())
            .filter(free)
            .find(|&i| by_name(&programs[i]))
        {
            taken[index] = true;
            other.push((&programs[index], command));
            continue;
        }
        // A wrapper's own words are not the guard's to give back.
        if let Some(index) = (0..programs.len())
            .filter(free)
            .find(|&i| by_wrapper(&programs[i]))
        {
            taken[index] = true;
            continue;
        }
        missing.push(command);
    }
    if missing.is_empty() && other.is_empty() {
        return None;
    }
    let mut shell = Vec::new();
    let mut guard = Vec::new();
    for command in &missing {
        shell.push(format!("runs {}", shown_command(command)));
        guard.push("reads no program of that name".to_string());
    }
    for (program, command) in &other {
        shell.push(format!("runs {}", shown_command(command)));
        guard.push(format!("reads {}", shown_program(program)));
    }
    Some(Found {
        kind: Kind::Split,
        shell: shell.join("; "),
        guard: guard.join("; "),
    })
}

/// A word in the report: as written, or `?`.
fn shown(word: Option<&str>) -> String {
    word.map_or_else(|| "?".to_string(), |text| format!("{text:?}"))
}

fn shown_command(command: &Command) -> String {
    let words: Vec<String> = command
        .words
        .iter()
        .map(|word| match word {
            Word::Value(text) | Word::Parameter(text) => shown(Some(text)),
            Word::Unknown => shown(None),
        })
        .collect();
    format!("[{}]", words.join(", "))
}

fn shown_program(program: &Program) -> String {
    let words: Vec<String> = std::iter::once(shown(Some(&program.program)))
        .chain(program.args.iter().map(|arg| shown(arg.as_deref())))
        .collect();
    format!("[{}]", words.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(name: &str, args: &[Option<&str>]) -> Program {
        Program {
            program: name.to_string(),
            wrappers: Vec::new(),
            args: args.iter().map(|arg| arg.map(str::to_string)).collect(),
        }
    }

    fn reading(grammar: Grammar, programs: Vec<Program>) -> Reading {
        Reading {
            grammar,
            programs,
            safe: true,
        }
    }

    fn command(nested: bool, words: &[Word]) -> Command {
        Command {
            nested,
            words: words.to_vec(),
        }
    }

    fn value(text: &str) -> Word {
        Word::Value(text.to_string())
    }

    #[test]
    fn a_posix_line_is_compared_by_accept_and_reject() {
        let whole = reading(Grammar::Whole, Vec::new());
        let error = reading(Grammar::Error, Vec::new());
        let unread = reading(Grammar::NotRead, Vec::new());
        let refused = Verdict::Rejects("line 1: syntax error".to_string());
        assert_eq!(posix(&whole, &Verdict::Accepts), None);
        assert_eq!(posix(&error, &refused), None);
        assert_eq!(
            posix(&error, &Verdict::Accepts).map(|f| f.kind),
            Some(Kind::GrammarRejects)
        );
        assert_eq!(
            posix(&unread, &Verdict::Accepts).map(|f| f.guard),
            Some("never hands it to the grammar (unreadable)".to_string())
        );
        let found = posix(&whole, &refused).unwrap();
        assert_eq!(found.kind, Kind::ShellRejects);
        assert_eq!(found.shell, "refuses: line 1: syntax error");
    }

    #[test]
    fn a_powershell_line_both_accept_is_compared_by_its_commands() {
        let guard = reading(
            Grammar::Whole,
            vec![
                program("Remove-Item", &[Some("a"), Some("b"), Some("-Recurse")]),
                program("rm", &[None]),
            ],
        );
        let same = Parsed::Accepts(vec![
            command(
                false,
                &[
                    value("remove-item"),
                    value("a"),
                    value("b"),
                    Word::Parameter("\u{2013}recurse".into()),
                ],
            ),
            // In a script block: not compared.
            command(true, &[value("Stop-Computer")]),
            // A name only known when it runs: not compared.
            command(false, &[Word::Unknown, value("x")]),
        ]);
        assert_eq!(powershell(&guard, &same), None);
        let missing = Parsed::Accepts(vec![command(false, &[value("Stop-Computer")])]);
        let found = powershell(&guard, &missing).unwrap();
        assert_eq!(found.kind, Kind::Split);
        assert_eq!(found.shell, "runs [\"Stop-Computer\"]");
        let other = Parsed::Accepts(vec![command(false, &[value("rm"), value("x"), value("y")])]);
        assert_eq!(
            powershell(&guard, &other).map(|f| f.guard),
            Some("reads [\"rm\", ?]".to_string())
        );
        let refused = Parsed::Rejects(3, "MissingEndCurlyBrace".into());
        assert_eq!(
            powershell(&guard, &refused).map(|f| f.shell),
            Some("refuses: MissingEndCurlyBrace at offset 3".to_string())
        );
        let error = reading(Grammar::Error, Vec::new());
        assert_eq!(powershell(&error, &refused), None);
        assert_eq!(
            powershell(&error, &Parsed::Accepts(Vec::new())).map(|f| f.kind),
            Some(Kind::GrammarRejects)
        );
    }

    #[test]
    fn a_wrapper_is_a_command_the_guard_read() {
        let mut wrapped = program("rm", &[Some("x")]);
        wrapped.wrappers = vec!["sudo".to_string()];
        let guard = reading(Grammar::Whole, vec![wrapped]);
        let parsed = Parsed::Accepts(vec![command(
            false,
            &[
                value("sudo"),
                Word::Parameter("-u".into()),
                value("root"),
                value("rm"),
                value("x"),
            ],
        )]);
        assert_eq!(powershell(&guard, &parsed), None);
    }

    #[test]
    fn every_kind_has_a_name_and_words() {
        for kind in [Kind::GrammarRejects, Kind::ShellRejects, Kind::Split] {
            assert!(!kind.name().is_empty() && !kind.says().is_empty());
        }
    }
}
