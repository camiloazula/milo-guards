//! The paths a reads-only line reads, and how each is read, for
//! [`effect_paths`](crate::effect_paths).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::path::Resolver;
use crate::unit::Stage;
use crate::Shell;

/// One place a line that only reads reads, and how it is read.
///
/// The [`path`](Self::path) is absolute, as the guard resolves it by
/// spelling: it is the place to look at on the disk, and [`how`](Self::how)
/// says what else the program reaches from it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadPath {
    /// The place: one exact path, the fixed folder a pattern expands in, or
    /// the root of a walk.
    pub path: PathBuf,
    /// How the program reads it.
    pub how: How,
}

/// How a program reads a [`ReadPath`], which says what a caller checks on
/// the disk.
///
/// This enum is exhaustive on purpose: a way of reading the caller does not
/// handle would be a way past its check, so a new one must break every
/// caller's `match` at compile time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum How {
    /// One exact path (a file operand, a `<` source, a folder listed, a
    /// `cd`): canonicalize it.
    Exact,
    /// A pattern the shell expands. The [`path`](ReadPath::path) is the fixed
    /// folder the pattern expands in, and this is the rest of the pattern, as
    /// written, below it: the whole pattern is the folder, a separator and
    /// this (`src/*/x.rs` is `src` and `*/x.rs`; `*.rs` is the working
    /// directory and `*.rs`). The caller expands the pattern on disk the way
    /// the shell does (a wildcard may match a leading dot: match it, to be
    /// safe), and canonicalizes the folder and every match. A link the
    /// expansion crosses (`src/a -> ~`) shows in a match.
    Glob(String),
    /// A folder the program walks (a recursive search, a listing, the
    /// repository `git` reads), or hands the names of to a program that opens
    /// them. The caller canonicalizes the root. `follows_links` says the
    /// program opens what it finds through symbolic links (`grep -R`,
    /// `rg -L`, `find -L`, `find -exec cat`, `ls | xargs cat`, `diff -r`, any
    /// walk the guard does not know for sure to stay out of links): then a
    /// link anywhere below the root can lead out of the workspace, which only
    /// walking the folder on disk would show. A caller may simply treat a
    /// walk that follows links as reading beyond the workspace. When it is
    /// `false` the program does not cross links it meets below the root
    /// (`grep -r`, `rg`, `find`, `ls -R`, `git`), and canonicalizing the root
    /// is the whole check.
    Tree {
        /// Whether the program opens what it finds through links.
        follows_links: bool,
    },
}

/// A read as `land` recorded it, before it is made a path.
#[derive(Debug)]
pub(super) struct Landed {
    /// The path as written, or the fixed folder of a pattern.
    pub(super) text: String,
    /// What follows the folder of a pattern.
    pub(super) glob: Option<String>,
    /// Whether the reader goes below it.
    pub(super) deep: bool,
    /// Whether the reader opens what it finds through links.
    pub(super) follows: bool,
    pub(super) shell: Shell,
    /// The pipeline stage that read it.
    pub(super) stage: Option<Stage>,
}

/// Make what was recorded the answer: absolute paths, a walk whose names a
/// later stage opens made a following one, sorted, each once. A path that is
/// the root of a walk is not also listed as an exact path.
pub(super) fn resolve(
    landed: &[Landed],
    followed: &BTreeSet<(usize, usize)>,
    resolver: &Resolver,
) -> Vec<ReadPath> {
    let mut exact = BTreeSet::new();
    let mut trees: BTreeMap<PathBuf, bool> = BTreeMap::new();
    let mut globs = BTreeSet::new();
    for read in landed {
        let Some(path) = resolver.absolute(&read.text, read.shell) else {
            continue;
        };
        let handed = read
            .stage
            .is_some_and(|stage| followed.contains(&(stage.pipeline, stage.index)));
        if handed || (read.deep && read.follows) {
            // A walk that opens what it finds through links, or a listing
            // whose names a later stage opens.
            trees.insert(path, true);
        } else if let Some(rest) = &read.glob {
            globs.insert(ReadPath {
                path,
                how: How::Glob(rest.clone()),
            });
        } else if read.deep {
            trees.entry(path).or_insert(false);
        } else {
            exact.insert(path);
        }
    }
    let mut paths: Vec<ReadPath> = globs.into_iter().collect();
    paths.extend(trees.iter().map(|(path, follows_links)| ReadPath {
        path: path.clone(),
        how: How::Tree {
            follows_links: *follows_links,
        },
    }));
    paths.extend(
        exact
            .into_iter()
            .filter(|path| !trees.contains_key(path))
            .map(|path| ReadPath {
                path,
                how: How::Exact,
            }),
    );
    paths.sort();
    paths
}
