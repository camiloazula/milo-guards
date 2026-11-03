//! The aliases and functions a PowerShell line sets (`Set-Alias x
//! Remove-Item`, `$function:f = $b`): a command of that name may run what
//! the name was set to, so it is judged as that too.

use std::collections::HashMap;
use std::rc::Rc;

use crate::unit;
use crate::Shell;

/// How many names a line may set before the guard stops reading them: the
/// line is then unknown, as a command of a name past them is not judged.
const MAX_SET: usize = 64;

/// How many more readings of its commands the names a line sets may add in
/// all: each is one more unit to judge, so this bounds the work whatever the
/// line does.
const MAX_READINGS: usize = 256;

/// What a name the line sets stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stands {
    /// An alias to the command of this name, as written (`Remove-Item`,
    /// `rm`, `C:\tools\x.exe`).
    Command(String),
    /// An alias to a command only known when it runs (`Set-Alias x $t`).
    Unknown,
    /// A function whose body is only known when it runs
    /// (`$function:f = $b`).
    Function,
}

/// What [`Aliases::set`] did with a name.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Set {
    /// It is noted.
    Noted,
    /// The line had set the name to the same before.
    Again,
    /// The line has set as many names as the guard reads; `first` is true
    /// the first time, so the finding is said once.
    Over { first: bool },
}

/// The names a command may stand for, worked out by [`Aliases::resolve`].
#[derive(Debug, Default)]
pub(super) struct Resolved {
    /// The commands it may run past the name itself, each as written, in the
    /// order the line set them: one for each key, and none of the name's own
    /// key, as that is the command already read.
    pub(super) commands: Vec<String>,
    /// Whether it may run a command only known when it runs.
    pub(super) unknown: bool,
    /// Whether it may run a function whose body is only known when it runs.
    pub(super) function: bool,
}

/// The aliases and functions a line sets, read from the whole line before
/// its commands are judged (see [`super::Walker::define`]), so a command
/// written before the name is set (in a function body, a loop, a trap) is
/// judged by it too.
#[derive(Debug, Default)]
pub(crate) struct Aliases {
    /// Each name (in lower case: PowerShell's names ignore case) with what it
    /// stands for, each pair once, and the key of the command it stands for,
    /// worked out when it is set.
    set: Vec<(String, Stands, Option<String>)>,
    /// What each name a command was named by resolves to, worked out once and
    /// forgotten when the line sets one more name, so a command costs one
    /// lookup however many targets its name has.
    resolved: HashMap<String, Rc<Resolved>>,
    /// How many names were refused for being past [`MAX_SET`].
    refused: usize,
    /// How many readings have been added.
    readings: usize,
}

impl Aliases {
    /// Whether the line sets any name at all.
    pub(super) fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Note that the line sets `name` to stand for `stands`.
    pub(super) fn set(&mut self, name: &str, stands: Stands) -> Set {
        let name = name.to_ascii_lowercase();
        if self
            .set
            .iter()
            .any(|(set, was, _)| *set == name && *was == stands)
        {
            return Set::Again;
        }
        if self.set.len() >= MAX_SET {
            self.refused += 1;
            return Set::Over {
                first: self.refused == 1,
            };
        }
        let key = match &stands {
            Stands::Command(command) => Some(unit::key(command, Shell::PowerShell)),
            Stands::Unknown | Stands::Function => None,
        };
        self.set.push((name, stands, key));
        self.resolved.clear();
        Set::Noted
    }

    /// What a command named `name` may run, past the name itself: every
    /// target the line sets the name to, and, when a target is a name the
    /// line sets too, what that one may run (PowerShell looks an alias up
    /// again when it runs), each name read once. Worked out once for each
    /// name, until the line sets one more.
    pub(super) fn resolve(&mut self, name: &str) -> Rc<Resolved> {
        let name = name.to_ascii_lowercase();
        if let Some(resolved) = self.resolved.get(&name) {
            return Rc::clone(resolved);
        }
        let mut resolved = Resolved::default();
        let mut keys = vec![unit::key(&name, Shell::PowerShell)];
        let mut seen = vec![name.clone()];
        let mut next = 0;
        while let Some(from) = seen.get(next).cloned() {
            next += 1;
            for (_, stands, key) in self.set.iter().filter(|(set, _, _)| *set == from) {
                match stands {
                    Stands::Command(command) => {
                        if let Some(key) = key.as_ref().filter(|key| !keys.contains(key)) {
                            keys.push(key.clone());
                            resolved.commands.push(command.clone());
                        }
                        let lower = command.to_ascii_lowercase();
                        if !seen.contains(&lower) {
                            seen.push(lower);
                        }
                    }
                    Stands::Unknown => resolved.unknown = true,
                    Stands::Function => resolved.function = true,
                }
            }
        }
        let resolved = Rc::new(resolved);
        self.resolved.insert(name, Rc::clone(&resolved));
        resolved
    }

    /// Whether the line has added as many readings as the guard reads: it is
    /// unreadable, and no more names are worked out.
    pub(super) fn exhausted(&self) -> bool {
        self.readings > MAX_READINGS
    }

    /// Count one more reading of a command; `None` while the line is within
    /// [`MAX_READINGS`], and `Some(first)` past it, `first` being true the
    /// first time, so the finding is said once.
    pub(super) fn reading(&mut self) -> Option<bool> {
        self.readings += 1;
        (self.readings > MAX_READINGS).then_some(self.readings == MAX_READINGS + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_resolves_through_the_names_it_is_set_to() {
        let mut aliases = Aliases::default();
        assert_eq!(
            aliases.set("x", Stands::Command("Remove-Item".into())),
            Set::Noted
        );
        assert_eq!(aliases.set("Y", Stands::Command("X".into())), Set::Noted);
        aliases.set("y", Stands::Unknown);
        aliases.set("z", Stands::Command("z".into()));
        let resolved = aliases.resolve("y");
        assert_eq!(resolved.commands, ["X", "Remove-Item"]);
        assert!(resolved.unknown);
        assert!(!resolved.function);
        // A target of the name's own key is the command already read.
        assert!(aliases.resolve("z").commands.is_empty());
        assert!(aliases.resolve("w").commands.is_empty());
        // Setting one more name is seen by a name resolved before.
        aliases.set("w", Stands::Command("Stop-Process".into()));
        assert_eq!(aliases.resolve("W").commands, ["Stop-Process"]);
    }

    #[test]
    fn the_names_set_and_the_readings_are_bounded() {
        let mut aliases = Aliases::default();
        for at in 0..MAX_SET {
            assert_eq!(aliases.set(&format!("n{at}"), Stands::Function), Set::Noted);
        }
        // The same name and target again is not one more.
        assert_eq!(aliases.set("N0", Stands::Function), Set::Again);
        assert_eq!(
            aliases.set("m", Stands::Function),
            Set::Over { first: true }
        );
        assert_eq!(
            aliases.set("m", Stands::Function),
            Set::Over { first: false }
        );
        for _ in 0..MAX_READINGS {
            assert_eq!(aliases.reading(), None);
        }
        assert!(!aliases.exhausted());
        assert_eq!(aliases.reading(), Some(true));
        assert!(aliases.exhausted());
        assert_eq!(aliases.reading(), Some(false));
    }
}
