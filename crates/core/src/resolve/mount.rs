//! Where a POSIX path lands once the drives this machine shows in a mount
//! the caller names (`Paths::drive_mounts`) are read as drives: under a
//! mount's folder, a folder named for one letter is that drive, `/mnt/c`
//! read as `C:\`, and a `..` above the drive's root is the mount's folder
//! again.
//!
//! Nothing here reads the disk. The mounts' folders are a tree of names,
//! built with the resolver, so each part of a path costs one lookup
//! whatever the number of mounts. Every walk of one resolver spends from one
//! budget of counted work ([`MOST_WORK`]): past it, a path is only known
//! when it runs.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{fold, is_globstar, short_name, Loc, Root};
use crate::canonical;

/// The counted work one resolver may spend walking paths through drive
/// mounts: each part a walk reads, each name a pattern is matched against.
/// Past it, a path is only known when it runs. An everyday line spends a few
/// hundred.
pub(crate) const MOST_WORK: usize = 1 << 20;

/// The work a resolver may still spend (see [`MOST_WORK`]).
#[derive(Debug)]
pub(super) struct Budget {
    left: AtomicUsize,
}

impl Budget {
    pub(super) fn new(work: usize) -> Self {
        Self {
            left: AtomicUsize::new(work),
        }
    }

    /// Spend `work`: `false`, spending nothing, when not that much is left.
    fn spend(&self, work: usize) -> bool {
        let left = self.left.load(Ordering::Relaxed);
        let Some(rest) = left.checked_sub(work) else {
            return false;
        };
        self.left.store(rest, Ordering::Relaxed);
        true
    }

    /// How much is left.
    #[cfg(any(feature = "testing", test))]
    pub(super) fn left(&self) -> usize {
        self.left.load(Ordering::Relaxed)
    }
}

impl Clone for Budget {
    fn clone(&self) -> Self {
        Self::new(self.left.load(Ordering::Relaxed))
    }
}

/// A reading of a pattern that picks a drive in a mount: where the drive
/// lands with the plain parts after the one that picks it, and the parts of
/// the pattern still to match there (`None` when none is left). `None` past
/// the budget.
pub(super) type Picked = Option<(Loc, Option<Vec<String>>)>;

/// One name of the tree of mounts' folders.
#[derive(Debug, Clone)]
struct Node {
    /// The name as the caller spelled it, which a pattern is matched against.
    name: String,
    /// The names below it, by the key [`Mounts::key`] gives them, in order
    /// so that every walk of them is the same.
    children: BTreeMap<String, usize>,
    /// Whether a drive is a folder of this one, named for its letter.
    mount: bool,
}

/// The folders drives are mounted in, as one tree of names from each root
/// a POSIX `/` is read on: the POSIX root, and on Windows the working
/// directory's drive (Git Bash's `/` is in the folder it is installed in,
/// which the guard reads as the root of that drive).
#[derive(Debug, Clone, Default)]
pub(super) struct Mounts {
    nodes: Vec<Node>,
    roots: Vec<(Root, usize)>,
    /// Whether names on a POSIX root compare without case: a Mac's.
    mac: bool,
}

impl Mounts {
    /// The tree of `folders`, each on the POSIX root and on `slash`, the
    /// root a POSIX `/` is read on. Only an absolute POSIX path names a
    /// folder (see [`folder`]): any other names none.
    pub(super) fn new(folders: &[PathBuf], slash: &Root, mac: bool) -> Self {
        let mut mounts = Self {
            mac,
            ..Self::default()
        };
        for folder in folders {
            let Some(loc) = self::folder(&folder.to_string_lossy()) else {
                continue;
            };
            for root in [Root::Unix, slash.clone()] {
                let node = mounts.insert(&Loc {
                    root,
                    parts: loc.parts.clone(),
                });
                mounts.nodes[node].mount = true;
            }
        }
        mounts
    }

    /// Whether any mount is named: without one, every path lands where its
    /// spelling says.
    pub(super) fn any(&self) -> bool {
        !self.roots.is_empty()
    }

    /// Whether `folder` is, or holds, a mount's folder: every name in the
    /// tree is on the way to one.
    pub(super) fn holds_mount(&self, folder: &Loc, budget: &Budget) -> bool {
        self.node_of(folder, budget).is_some()
    }

    /// The node of `loc`, made with every name above it as needed.
    fn insert(&mut self, loc: &Loc) -> usize {
        let mut at = if let Some(node) = self.root(&loc.root) {
            node
        } else {
            self.nodes.push(Node::named(String::new()));
            let node = self.nodes.len() - 1;
            self.roots.push((loc.root.clone(), node));
            node
        };
        for part in &loc.parts {
            let key = self.key(part, &loc.root);
            at = if let Some(&child) = self.nodes[at].children.get(&key) {
                child
            } else {
                self.nodes.push(Node::named(part.clone()));
                let child = self.nodes.len() - 1;
                self.nodes[at].children.insert(key, child);
                child
            };
        }
        at
    }

    /// The node of a root, when anything is below it.
    fn root(&self, root: &Root) -> Option<usize> {
        self.roots
            .iter()
            .find(|(known, _)| known.same(root))
            .map(|(_, node)| *node)
    }

    /// What a name is looked up by on `root`: itself where names compare
    /// with case, and folded where they do not (a drive or a share, and a
    /// Mac): by the widest fold, in either canonical spelling.
    fn key(&self, name: &str, root: &Root) -> String {
        if !self.mac && matches!(root, Root::Unix) {
            return name.to_string();
        }
        if name.is_ascii() {
            return name.to_ascii_lowercase();
        }
        canonical::decomposed(name).into_iter().map(fold).collect()
    }

    /// The node below `node` that `name` is, on `root`: by its key, and on
    /// Windows by its 8.3 short name too (`PROGRA~1` for `Program Files`),
    /// each name below counted against the budget.
    fn child(&self, node: usize, name: &str, root: &Root, budget: &Budget) -> Option<usize> {
        if let Some(&child) = self.nodes[node].children.get(&self.key(name, root)) {
            return Some(child);
        }
        if !matches!(root, Root::Unix) && name.contains('~') {
            for &child in self.nodes[node].children.values() {
                if !budget.spend(1) {
                    return None;
                }
                if short_name(name, &self.nodes[child].name) {
                    return Some(child);
                }
            }
        }
        None
    }

    /// The node of `loc`, from its root: `None` when it has none.
    fn node_of(&self, loc: &Loc, budget: &Budget) -> Option<usize> {
        let mut at = self.root(&loc.root);
        for part in &loc.parts {
            at = at.and_then(|node| self.child(node, part, &loc.root, budget));
        }
        at
    }

    /// Where `raw` lands: its parts walked in order from its root, `..` kept
    /// where it was written. Under a mount, a folder of one letter is that
    /// drive, where `mapping` says a POSIX path is read (the root `/` is
    /// on), and a `..` above the drive's root is the mount's folder again;
    /// `entered` says the walk starts on a drive read through that folder (a
    /// relative path in Git Bash). `None` past the budget.
    pub(super) fn land(
        &self,
        raw: Loc,
        mapping: Option<Root>,
        entered: Option<(Loc, Root)>,
        budget: &Budget,
    ) -> Option<Loc> {
        self.lands(raw, mapping, entered, budget)
            .into_iter()
            .next()
            .flatten()
    }

    /// Every place `raw` lands (see [`land`](Self::land)): where one mount's
    /// folder is below another's (`/mnt` and `/mnt/c`), a folder of one
    /// letter in the first is both its drive and the way to the second, so
    /// each is read. `None` among them for a walk past the budget.
    pub(super) fn lands(
        &self,
        raw: Loc,
        mapping: Option<Root>,
        entered: Option<(Loc, Root)>,
        budget: &Budget,
    ) -> Vec<Option<Loc>> {
        let base = self.root(&raw.root);
        let start = Walk {
            out: Loc::at(raw.root.clone()),
            base,
            nodes: Vec::with_capacity(raw.parts.len()),
            mapping,
            entered,
            at: 0,
        };
        let mut found = Vec::new();
        let mut walks = vec![start];
        while let Some(walk) = walks.pop() {
            found.push(self.walk(walk, &raw.parts, budget, &mut walks));
        }
        found
    }

    /// One walk of `parts` from where `walk` is, each other walk a folder
    /// that is both a drive and the way to another mount starts put in
    /// `more`.
    fn walk(
        &self,
        walk: Walk,
        parts: &[String],
        budget: &Budget,
        more: &mut Vec<Walk>,
    ) -> Option<Loc> {
        let Walk {
            mut out,
            mut base,
            mut nodes,
            mut mapping,
            mut entered,
            at,
        } = walk;
        for (index, part) in parts.iter().enumerate().skip(at) {
            let part = part.clone();
            if !budget.spend(1) {
                return None;
            }
            if part == ".." {
                if out.parts.pop().is_some() {
                    nodes.pop();
                } else if let Some((folder, root)) = entered.take() {
                    if !budget.spend(folder.parts.len()) {
                        return None;
                    }
                    base = self.root(&folder.root);
                    nodes.clear();
                    let mut at = base;
                    for part in &folder.parts {
                        at = at.and_then(|node| self.child(node, part, &folder.root, budget));
                        nodes.push(at);
                    }
                    out = folder;
                    mapping = Some(root);
                }
                continue;
            }
            let at = match nodes.last() {
                Some(node) => *node,
                None => base,
            };
            if let (Some(node), Some(root)) = (at, &mapping) {
                if self.nodes[node].mount && out.root.same(root) {
                    if let Some(letter) = letter(&part) {
                        // The folder is also the way to a mount below it.
                        let below = self.child(node, &part, &out.root, budget);
                        if below.is_some() {
                            let mut folder = out.clone();
                            folder.parts.push(part.clone());
                            let mut held = nodes.clone();
                            held.push(below);
                            more.push(Walk {
                                out: folder,
                                base,
                                nodes: held,
                                mapping: mapping.clone(),
                                entered: entered.clone(),
                                at: index + 1,
                            });
                        }
                        entered = Some((out, root.clone()));
                        out = Loc::at(Root::Drive(letter));
                        base = self.root(&out.root);
                        nodes.clear();
                        mapping = None;
                        continue;
                    }
                }
            }
            let node = at.and_then(|node| self.child(node, &part, &out.root, budget));
            out.parts.push(part);
            nodes.push(node);
        }
        Some(out)
    }

    /// The readings of a pattern whose parts `tail`, from the folder it
    /// starts in (`folder`, already landed), can pick a drive under a
    /// mount: a part is matched against a folder's name on the way to the
    /// mount (`matches` says how, with whether the name is on Windows), one
    /// part to one name, a part of two or more stars (`**`) to any number of
    /// them, and against each of `letters` at the mount, where `mapping`
    /// says a POSIX path is read. The drive then lands with the plain parts
    /// that follow, and what is left of the pattern from its next wildcard
    /// part. Each name is matched once for each part, and every match is
    /// counted against the budget: past it, the reading is `None`.
    pub(super) fn picked(
        &self,
        folder: &Loc,
        tail: &[String],
        mapping: Option<&Root>,
        letters: &[char],
        matches: &dyn Fn(&str, &str, bool) -> bool,
        budget: &Budget,
    ) -> Vec<Picked> {
        let mut readings = Vec::new();
        if !mapping.is_some_and(|root| folder.root.same(root)) {
            return readings;
        }
        let Some(start) = self.node_of(folder, budget) else {
            return readings;
        };
        let windows = folder.windows();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        // Each drive once for each part the rest of the pattern starts at:
        // every mount that picks it there reads the same.
        let mut picked: HashSet<(char, usize)> = HashSet::new();
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        while let Some((node, depth)) = stack.pop() {
            if !seen.insert((node, depth)) {
                continue;
            }
            let Some(part) = tail.get(depth) else {
                continue;
            };
            let globstar = is_globstar(part);
            if globstar {
                // The stars may take no name at all.
                stack.push((node, depth + 1));
            }
            let pattern = if globstar { "*" } else { part.as_str() };
            // Where a part after the stars or after this one starts.
            let from = if globstar { depth } else { depth + 1 };
            if self.nodes[node].mount {
                for &letter in letters {
                    if !budget.spend(1) {
                        readings.push(None);
                        return readings;
                    }
                    let name = letter.to_ascii_lowercase().to_string();
                    if matches(pattern, &name, windows) && picked.insert((letter, from)) {
                        let drive = Loc::at(Root::Drive(letter));
                        readings.push(self.reading(drive, &tail[from..], budget));
                    }
                }
            }
            for &child in self.nodes[node].children.values() {
                if !budget.spend(1) {
                    readings.push(None);
                    return readings;
                }
                if matches(pattern, &self.nodes[child].name, windows) {
                    stack.push((child, if globstar { depth } else { depth + 1 }));
                }
            }
        }
        readings
    }

    /// `raw` with the plain parts of `rest` up to its next wildcard part,
    /// landed, and the parts from that one on.
    fn reading(&self, mut raw: Loc, rest: &[String], budget: &Budget) -> Picked {
        if !budget.spend(rest.len()) {
            return None;
        }
        let wild = rest
            .iter()
            .position(|part| part.contains(crate::spelling::glob::WILDCARDS))
            .unwrap_or(rest.len());
        raw.parts.extend(rest[..wild].iter().cloned());
        let landed = self.land(raw, None, None, budget)?;
        let left = (wild < rest.len()).then(|| rest[wild..].to_vec());
        Some((landed, left))
    }
}

impl Node {
    fn named(name: String) -> Self {
        Self {
            name,
            children: BTreeMap::new(),
            mount: false,
        }
    }
}

/// Where a walk of a path through the mounts is: what it has walked, the
/// node of each part, and the part it goes on from.
struct Walk {
    out: Loc,
    base: Option<usize>,
    nodes: Vec<Option<usize>>,
    mapping: Option<Root>,
    entered: Option<(Loc, Root)>,
    at: usize,
}

/// The folder a drive mount names: an absolute POSIX path, its empty and
/// `.` parts dropped and each `..` applied (`//mnt/./` is `/mnt`). Any other
/// spelling (empty, relative, from `~`, a Windows path) names none.
pub(super) fn folder(text: &str) -> Option<Loc> {
    if !text.starts_with('/') {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part.to_string()),
        }
    }
    Some(Loc {
        root: Root::Unix,
        parts,
    })
}

/// The drive a folder name of one letter is, in capitals.
fn letter(part: &str) -> Option<char> {
    let mut chars = part.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    chars.next().is_none().then(|| letter.to_ascii_uppercase())
}
