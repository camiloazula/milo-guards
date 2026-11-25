//! What a guard's tests share: sample directories, and a table check that
//! names every row that came out wrong at once.
//!
//! Available with the `testing` feature, as a dev-dependency:
//!
//! ```toml
//! [dev-dependencies]
//! milo-guards-core = { workspace = true, features = ["testing"] }
//! ```

use crate::{Assessment, Flavour, Paths, Place, Resolver, RuleName, Spelling};

/// The counted work one resolver may spend walking paths through drive
/// mounts and links.
pub const MOST_WORK: usize = crate::resolve::MOST_WORK;

/// The most links a path is followed through (what Windows follows, the
/// most of any system).
pub const MOST_HOPS: usize = crate::resolve::MOST_HOPS;

/// The longest link target read, in bytes.
pub const MOST_TARGET: usize = crate::resolve::MOST_TARGET;

/// The most links held.
pub const MOST_LINKS: usize = crate::resolve::MOST_LINKS;

/// The counted work the build of the tree of links may spend.
pub const MOST_BUILD: usize = crate::resolve::MOST_BUILD;

/// The most parts of one pattern read as `.` and `..` too.
pub const MOST_CLIMBING: usize = crate::resolve::MOST_CLIMBING;

/// The most rounds the places of links named below links are worked out in.
pub const MOST_ROUNDS: usize = crate::resolve::MOST_ROUNDS;

/// The work of placing one path through the links and the drive mounts the
/// caller names, as counts that are the same on every machine, for a test
/// that holds it to a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkWork {
    /// The counted work `place` spent of the resolver's budget: each part a
    /// walk read, each name a pattern was matched against.
    pub work: usize,
    /// How many places `place` read the path as, the most serious of which
    /// it answers.
    pub readings: usize,
    /// Whether the resolver read the tree of links kept with them, not one
    /// built for the call.
    pub kept: bool,
}

/// The work of placing `path`, spelled for `flavour`, on `paths`.
#[must_use]
pub fn link_work(paths: &Paths, path: &str, flavour: Flavour) -> LinkWork {
    let (work, readings, kept) = Resolver::link_work(paths, Spelling::Plain(path), flavour);
    LinkWork {
        work,
        readings,
        kept,
    }
}

/// The work each of `spellings` spends, placed in turn by one resolver (one
/// judged call), and the place of each: the budget is shared, so past it a
/// path is only known when it runs.
#[must_use]
pub fn work_of_each(
    paths: &Paths,
    spellings: &[&str],
    flavour: Flavour,
) -> (Vec<usize>, Vec<Place>) {
    Resolver::work_of_each(paths, spellings, flavour)
}

/// The counted work placing `path`, spelled for `flavour`, spends on a
/// fresh resolver for `paths` (each part a walk through a drive mount read,
/// each name a pattern was matched against), the same on every machine, for
/// a test that holds it to a bound; and the place.
#[must_use]
pub fn mount_work(paths: &Paths, path: &str, flavour: Flavour) -> (usize, Place) {
    Resolver::mount_work(paths, Spelling::Plain(path), flavour)
}

/// A POSIX machine: the workspace in the home directory.
#[must_use]
pub fn posix() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

/// A macOS machine: home under `/Users`.
#[must_use]
pub fn macos() -> Paths {
    Paths::new("/Users/me/dev/repo", "/Users/me", ["/Users/me/dev/repo"])
}

/// A Windows machine.
#[must_use]
pub fn windows() -> Paths {
    Paths::new(
        r"C:\Users\me\dev\repo",
        r"C:\Users\me",
        [r"C:\Users\me\dev\repo"],
    )
}

/// The rules `input` breaks under `judge`, in order.
pub fn rules<R: RuleName>(input: &str, judge: impl Fn(&str) -> Assessment<R>) -> Vec<R> {
    judge(input)
        .findings()
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

/// Every `safe` input is safe under `judge` and every `risky` input breaks
/// its rule; the rows that do not are named together.
///
/// # Panics
///
/// When any row is wrong, listing all of them.
pub fn check<R: RuleName>(
    safe: &[&str],
    risky: &[(&str, R)],
    judge: impl Fn(&str) -> Assessment<R>,
) {
    let mut wrong = Vec::new();
    for input in safe {
        let assessment = judge(input);
        if !assessment.is_safe() {
            wrong.push(format!(
                "expected safe: {input}\n    got {:?}",
                assessment.findings()
            ));
        }
    }
    for (input, rule) in risky {
        let assessment = judge(input);
        if !assessment.findings().iter().any(|f| f.rule == *rule) {
            wrong.push(format!(
                "expected {rule:?}: {input}\n    got {:?}",
                assessment.findings()
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} rows wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Finding;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum Toy {
        Bad,
        Worse,
    }

    impl RuleName for Toy {
        fn name(self) -> &'static str {
            match self {
                Self::Bad => "bad",
                Self::Worse => "worse",
            }
        }
    }

    /// A guard that calls `bad` and `worse` risky, and nothing else.
    fn judge(input: &str) -> Assessment<Toy> {
        let found: Vec<_> = [("bad", Toy::Bad), ("worse", Toy::Worse)]
            .into_iter()
            .filter(|(word, _)| input.contains(word))
            .map(|(word, rule)| Finding {
                rule,
                reason: format!("says {word}"),
                target: None,
                instead: None,
            })
            .collect();
        if found.is_empty() {
            Assessment::Safe
        } else {
            Assessment::Risky(found)
        }
    }

    #[test]
    fn a_table_that_holds_passes() {
        check(
            &["fine", ""],
            &[("bad", Toy::Bad), ("bad worse", Toy::Worse)],
            judge,
        );
        assert_eq!(rules("worse bad", judge), [Toy::Bad, Toy::Worse]);
        assert!(rules("fine", judge).is_empty());
    }

    #[test]
    #[should_panic(expected = "3 rows wrong")]
    fn every_wrong_row_is_named_at_once() {
        check(&["bad"], &[("fine", Toy::Bad), ("bad", Toy::Worse)], judge);
    }

    #[test]
    fn rule_names_are_the_wire_names() {
        assert_eq!(Toy::Bad.name(), "bad");
        assert_eq!(Toy::Worse.name(), "worse");
    }

    #[test]
    fn the_sample_machines_are_absolute() {
        assert!(posix().cwd.starts_with("/home"));
        assert!(macos().cwd.starts_with("/Users"));
        assert!(windows().home.to_string_lossy().starts_with("C:"));
    }
}
