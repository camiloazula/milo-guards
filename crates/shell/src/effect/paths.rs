//! The paths a reads-only line reads, and how each is read, for
//! [`effect_paths`](crate::effect_paths).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use super::reach::Walk;
use crate::path::Resolver;
use crate::unit::Stage;
use crate::Shell;

/// One place a line that only reads reads, and how it is read.
///
/// The [`path`](Self::path) is absolute, as the system opens it, every `..`
/// kept where the line wrote it: it is the place to look at on the disk
/// (resolve it part by part, a `..` climbing from where the link before it
/// led), and [`how`](Self::how) says what else the program reaches from it.
///
/// Two are the same, and are ordered, by the path as the system it is spelled
/// for reads it, part by part (a Windows path split at `\` and `/`, any other
/// at `/` alone), then by how: the same on every host, whatever the host's
/// own `Path` rules are.
#[derive(Debug, Clone)]
pub struct ReadPath {
    /// The place: one exact path, the fixed folder a pattern expands in, or
    /// the root of a walk.
    pub path: PathBuf,
    /// How the program reads it.
    pub how: How,
}

impl PartialEq for ReadPath {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ReadPath {}

impl PartialOrd for ReadPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReadPath {
    fn cmp(&self, other: &Self) -> Ordering {
        compare(&self.path, &other.path).then_with(|| self.how.cmp(&other.how))
    }
}

impl Hash for ReadPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_parts(&self.path, state);
        self.how.hash(state);
    }
}

/// An absolute path as core renders it, compared, ordered and hashed by its
/// parts as the system it is spelled for splits it, not by the rules of the
/// host the guard runs on: a Windows path (a drive, `C:\x`, or a share,
/// `\\server\share`) at both `\` and `/`, any other at `/` alone, where
/// a `\` is a letter of a name (`a\b` is one name). Empty parts and `.` are
/// no parts, as `Path` reads them.
#[derive(Debug, Clone)]
struct Spelled(PathBuf);

impl PartialEq for Spelled {
    fn eq(&self, other: &Self) -> bool {
        compare(&self.0, &other.0) == Ordering::Equal
    }
}

impl Eq for Spelled {}

impl PartialOrd for Spelled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Spelled {
    fn cmp(&self, other: &Self) -> Ordering {
        compare(&self.0, &other.0)
    }
}

/// Whether `text` is spelled as a Windows path: it starts with a drive or a
/// backslash.
fn windows_spelled(text: &str) -> bool {
    let bytes = text.as_bytes();
    matches!(bytes, [letter, b':', ..] if letter.is_ascii_alphabetic()) || text.starts_with('\\')
}

/// The parts of `text`, split as [`Spelled`] says, after whether it is a
/// Windows path.
fn parts(text: &str) -> (bool, impl Iterator<Item = &str>) {
    let windows = windows_spelled(text);
    let separators: &[char] = if windows { &['\\', '/'] } else { &['/'] };
    let parts = text
        .split(separators)
        .filter(|part| !part.is_empty() && *part != ".");
    (windows, parts)
}

/// The order of two paths by their parts (see [`Spelled`]): a POSIX path
/// before a Windows one, then part by part.
fn compare(a: &Path, b: &Path) -> Ordering {
    let (a, b) = (a.to_string_lossy(), b.to_string_lossy());
    let ((a_windows, a_parts), (b_windows, b_parts)) = (parts(&a), parts(&b));
    a_windows.cmp(&b_windows).then_with(|| a_parts.cmp(b_parts))
}

/// Hash `path` by its parts, so two paths [`compare`] calls the same hash
/// the same.
fn hash_parts<H: Hasher>(path: &Path, state: &mut H) {
    let text = path.to_string_lossy();
    let (windows, parts) = parts(&text);
    windows.hash(state);
    for part in parts {
        part.hash(state);
    }
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
    /// `cd`): canonicalize it, which follows each link before the `..` after
    /// it.
    Exact,
    /// A pattern the shell expands. The [`path`](ReadPath::path) is the fixed
    /// folder the pattern expands in, and this is the rest of the pattern, as
    /// written, below it: the whole pattern is the folder, a separator and
    /// this (`src/*/x.rs` is `src` and `*/x.rs`; `*.rs` is the working
    /// directory and `*.rs`; `.a*/x` is the working directory and `.a*/x`, the
    /// leading dot kept). The caller expands the pattern on disk the way
    /// the shell does (a wildcard may match a leading dot: match it, to be
    /// safe), and canonicalizes the folder and every match. A link the
    /// expansion crosses (`src/a -> ~`) shows in a match.
    Glob(String),
    /// A folder the program walks (a recursive search, a listing, the
    /// repository `git` reads), or hands the names of to a program that opens
    /// them. The caller canonicalizes the root. `follows_links` says the
    /// program opens what it finds through symbolic links (`grep -R`,
    /// `grep -rS`, `rg -L`, `find -L`, `find -exec cat`, `ls -RL`, `du -L`,
    /// `ls | xargs cat`, `diff -r`, any walk the guard does not know for sure to
    /// stay out of links, any flag a walker's own list does not name): then a
    /// link anywhere below the root can lead out of the workspace, which only
    /// walking the folder on disk would show. A caller may simply treat a
    /// walk that follows links as reading beyond the workspace. When it is
    /// `false` the program does not cross links it meets below the root
    /// (`grep -r`, `rg`, `find`, `ls -R`, `du`, `git`, given only flags known not
    /// to follow them), and canonicalizing the root is the whole check.
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
    /// How many leading bytes of `text` the shell applied the `..` of itself
    /// (a `cd`), so that part is made absolute by spelling and a `..` after it
    /// is kept. A read is recorded once per way the shell can have gone, `0`
    /// being the way where it kept every `..`.
    pub(super) folded: usize,
    /// What follows the folder of a pattern.
    pub(super) glob: Option<String>,
    /// How the reader walks it.
    pub(super) walk: Walk,
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
    let mut trees: BTreeMap<Spelled, bool> = BTreeMap::new();
    let mut globs = BTreeSet::new();
    for read in landed {
        let Some(path) = opened(read, resolver) else {
            continue;
        };
        let path = Spelled(path);
        let handed = read
            .stage
            .is_some_and(|stage| followed.contains(&(stage.pipeline, stage.index)));
        if handed || read.walk == Walk::Follows {
            // A walk that opens what it finds through links, or a listing
            // whose names a later stage opens.
            trees.insert(path, true);
        } else if let Some(rest) = &read.glob {
            globs.insert(ReadPath {
                path: path.0,
                how: How::Glob(rest.clone()),
            });
        } else if read.walk == Walk::Stays {
            trees.entry(path).or_insert(false);
        } else {
            exact.insert(path);
        }
    }
    let mut paths: Vec<ReadPath> = globs.into_iter().collect();
    paths.extend(trees.iter().map(|(path, follows_links)| ReadPath {
        path: path.0.clone(),
        how: How::Tree {
            follows_links: *follows_links,
        },
    }));
    paths.extend(
        exact
            .into_iter()
            .filter(|path| !trees.contains_key(path))
            .map(|path| ReadPath {
                path: path.0,
                how: How::Exact,
            }),
    );
    paths.sort();
    paths
}

/// The absolute path a read opens, every `..` kept where it was written
/// except those the shell itself applied (`read.folded`): a program opens
/// `link/../x` by following `link` first.
fn opened(read: &Landed, resolver: &Resolver) -> Option<PathBuf> {
    // A folder a search hands on whole is read as the folder.
    let text = read.text.as_str();
    let (text, shell) = (crate::path::whole_folder(text).unwrap_or(text), read.shell);
    match read.folded {
        0 => resolver.opened(text, shell),
        at if at >= text.len() => resolver.absolute(text, shell),
        at => {
            let folder = resolver.absolute(&text[..at], shell)?;
            let joined = format!("{}/{}", folder.to_string_lossy(), &text[at + 1..]);
            resolver.opened(&joined, shell)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hashed(text: &str) -> u64 {
        let mut state = DefaultHasher::new();
        hash_parts(Path::new(text), &mut state);
        state.finish()
    }

    #[test]
    fn paths_compare_by_the_parts_of_their_own_spelling_on_any_host() {
        let order = |a: &str, b: &str| compare(Path::new(a), Path::new(b));
        // A POSIX path is split at `/` alone: a backslash is a letter.
        assert_ne!(order("/r/a\\b", "/r/a/b"), Ordering::Equal);
        assert_eq!(order("/r/a/b", "/r/a\\b"), Ordering::Less);
        // Part by part, as `Path` orders them: `a` before `a.b`.
        assert_eq!(order("/r/a/x", "/r/a.b"), Ordering::Less);
        assert_eq!(order("/r/a//b/./c", "/r/a/b/c"), Ordering::Equal);
        // A Windows path is split at both separators.
        assert_eq!(order(r"C:\a\b", "C:\\a/b"), Ordering::Equal);
        assert_eq!(hashed(r"C:\a\b"), hashed("C:\\a/b"));
        assert_ne!(hashed("/r/a\\b"), hashed("/r/a/b"));
        assert_eq!(order(r"C:\a\x", r"C:\a.b"), Ordering::Less);
        assert_eq!(
            order(r"\\server\share\x", r"\\server\share\y"),
            Ordering::Less
        );
        // A POSIX path sorts before a Windows one.
        assert_eq!(order("/z", r"C:\a"), Ordering::Less);
    }

    #[test]
    fn read_paths_are_the_same_by_their_spelling_and_how() {
        let read = |text: &str, how: How| ReadPath {
            path: PathBuf::from(text),
            how,
        };
        assert_ne!(read("/r/a\\b", How::Exact), read("/r/a/b", How::Exact));
        assert_eq!(read(r"C:\a\b", How::Exact), read("C:\\a/b", How::Exact));
        assert!(read("/r/a", How::Exact) < read("/r/a", How::Glob("*".to_string())));
        let mut set = BTreeSet::new();
        set.insert(Spelled(PathBuf::from("/r/a/b")));
        set.insert(Spelled(PathBuf::from("/r/a\\b")));
        set.insert(Spelled(PathBuf::from("/r//a/b")));
        assert_eq!(set.len(), 2);
    }
}
