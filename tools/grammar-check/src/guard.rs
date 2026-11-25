//! How the shell guard read a line: whether its grammar read the line itself
//! whole, the programs it read at the line's own depth with their words, and
//! whether it answered safe.

use milo_guards_shell::testing::{self, Grammar};
use milo_guards_shell::{explain, ArgKind, Paths, Shell};

use crate::lines::Family;

/// One program the guard read at the line's own depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The program, as written.
    pub program: String,
    /// The wrappers taken off in front of it, outermost first.
    pub wrappers: Vec<String>,
    /// Its arguments after the wrappers' own: the value when the text gives
    /// it, `None` when it is only known when it runs.
    pub args: Vec<Option<String>>,
}

/// The guard's reading of one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    /// How the grammar read the line itself.
    pub grammar: Grammar,
    /// The programs it read at the line's own depth (none nested in a
    /// script the line hands a shell), in its order.
    pub programs: Vec<Program>,
    /// Whether the guard answered safe.
    pub safe: bool,
}

/// The paths a line is read with: the split does not depend on them, and a
/// PowerShell line is read on a Windows machine, as its case files read it.
fn paths(family: Family) -> Paths {
    match family {
        Family::Posix => Paths::new("/work/app", "/home/me", ["/work/app"]),
        Family::PowerShell => Paths::new("C:\\work\\app", "C:\\Users\\me", ["C:\\work\\app"]),
    }
}

/// The guard's shell for `family`.
const fn shell(family: Family) -> Shell {
    match family {
        Family::Posix => Shell::Posix,
        Family::PowerShell => Shell::PowerShell,
    }
}

/// Read `line` of `family` as the guard does.
pub fn read(line: &str, family: Family) -> Reading {
    let paths = paths(family);
    let shell = shell(family);
    let explanation = explain(line, shell, &paths);
    let programs = explanation
        .units
        .iter()
        .filter(|unit| unit.depth == 0 && unit.shell == shell)
        .map(|unit| Program {
            program: unit.program.clone(),
            wrappers: unit.wrappers.clone(),
            args: unit
                .args
                .iter()
                .map(|arg| (arg.kind == ArgKind::Known).then(|| arg.written.clone()))
                .collect(),
        })
        .collect();
    Reading {
        grammar: testing::grammar(line, shell, &paths),
        programs,
        safe: explanation.assessment().is_safe(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grammar_and_the_programs_are_read() {
        let whole = read("sudo rm -rf ~ && bash -c 'ls'", Family::Posix);
        assert_eq!(whole.grammar, Grammar::Whole);
        assert!(!whole.safe);
        assert_eq!(whole.programs[0].program, "rm");
        assert_eq!(whole.programs[0].wrappers, ["sudo"]);
        assert_eq!(
            whole.programs[0].args,
            [Some("-rf".into()), Some("~".into())]
        );
        // The `ls` of the nested script is not at the line's own depth.
        assert!(whole.programs.iter().all(|program| program.program != "ls"));
        assert_eq!(read("echo (", Family::Posix).grammar, Grammar::Error);
        // A nested script the grammar cannot read is not the line itself.
        assert_eq!(
            read("bash -c 'echo ('", Family::Posix).grammar,
            Grammar::Whole
        );
        let powershell = read("Remove-Item $x -Recurse", Family::PowerShell);
        assert_eq!(powershell.grammar, Grammar::Whole);
        assert_eq!(powershell.programs[0].args, [None, Some("-Recurse".into())]);
        assert_eq!(
            read("Get-Item {", Family::PowerShell).grammar,
            Grammar::Error
        );
        let long = "a".repeat(200_000);
        assert_eq!(read(&long, Family::Posix).grammar, Grammar::NotRead);
    }
}
