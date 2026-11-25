//! Where a path lands once the links the caller has resolved
//! (`Paths::links`) are followed part by part, as the system follows them,
//! through the drive mounts it names too (see `mount`).
//!
//! Nothing here reads the disk. The links are a tree of names, built once
//! for the directories a `Paths` holds (all but the working directory) the
//! first time a guard judges with them, so each part of a path costs one
//! lookup whatever the number of links. Every walk of one resolver spends
//! from one budget of counted work (`MOST_WORK`); a path the walk cannot
//! finish (through more links than any system follows, through a link that
//! cannot be read or placed, past the budget) is only known when it runs.
//! The build spends from a budget of its own, [`MOST_BUILD`], and holds at
//! most [`MOST_LINKS`] links of at most [`MOST_PARTS`] parts in all: past
//! any, no link is held and every path is only known when it runs, whatever
//! the order of the list.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use super::mount::{letter, Budget, Mounts};
use super::{
    fold, is_globstar, severity, short_name, verbatim, windows_name, windows_root, Flavour, Loc,
    Resolver, Root,
};
use crate::spelling::glob::WILDCARDS;
use crate::{canonical, Paths, Place, Protected, Secret};

/// The most links followed to place one path: what Windows follows (63),
/// the most of any system (Linux follows 40, macOS 32). A path through more
/// is one the system itself refuses; to the guard it is only known when it
/// runs, never a place.
pub(crate) const MOST_HOPS: usize = 63;

/// The longest target a link is read for, in bytes: what Linux keeps for a
/// link (`PATH_MAX`), more than any system does. A longer one is no link a
/// system made, and a path through it is only known when it runs.
pub(crate) const MOST_TARGET: usize = 4_096;

/// The most links held. Past it no link is held, and every path is only
/// known when it runs.
pub(crate) const MOST_LINKS: usize = 1 << 18;

/// The most parts the names and targets of the links held may have, all
/// together, a part counting once more for each [`PART_BYTES`] bytes in it:
/// what the tree keeps, and the work and memory of its build, grow with
/// them. Past it no link is held, and every path is only known when it
/// runs. A link of ten parts with a target of four (`node_modules/pkg` to
/// `.pnpm/pkg@1.0.0/node_modules/pkg`) counts 14: 74,898 of them fit.
pub(crate) const MOST_PARTS: usize = 1 << 20;

/// The bytes of a part that count as one part more toward [`MOST_PARTS`].
pub(crate) const PART_BYTES: usize = 64;

/// What `part` counts toward [`MOST_PARTS`].
fn weight(part: &str) -> usize {
    1 + part.len() / PART_BYTES
}

/// The counted work the build of the tree may spend: each part of a link's
/// name and target walked to place it, each round. Past it no link is held,
/// and every path is only known when it runs.
pub(crate) const MOST_BUILD: usize = 1 << 25;

/// The most rounds the places of links named below other links are worked
/// out in: each round places a link one level of nesting deeper. A link
/// still moving after the last is not placed, and every path through it is
/// only known when it runs.
pub(crate) const MOST_ROUNDS: usize = 8;

/// No node, in the `u32` indices of the tree.
const NONE: u32 = u32::MAX;

/// Where a link's target starts from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Start {
    /// The folder the link is in: a relative target.
    Parent,
    /// A root: an absolute target.
    Root(Root),
    /// Nowhere the guard can say: a target it cannot place, a link the
    /// caller could not read, a link named with two targets, a link it
    /// could not place among the others.
    Lost,
}

/// A link's target as the link holds it: where it starts, and its parts,
/// each `..` kept where it is written (the system applies it as it walks).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Target {
    start: Start,
    parts: Vec<String>,
    /// Whether the target is a POSIX path, whose drive mounts are read.
    posix: bool,
}

/// What a folder holds through the links at or below it, for a tool that
/// follows the links it meets: the most serious place one of them lands on,
/// and whether what it lands on, read all the way down, reaches a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Held {
    pub(crate) place: Place,
    pub(crate) reaches: bool,
}

impl Held {
    /// The more serious of the two: by the place, then by whether it
    /// reaches a key, then by the words, so the answer is the same in any
    /// order.
    pub(super) fn max(self, other: Self) -> Self {
        let rank = |held: &Self| (severity(held.place), held.reaches, held.place.words());
        if rank(&other) > rank(&self) {
            other
        } else {
            self
        }
    }

    /// Whether it says anything: a link that lands on a harmless place that
    /// reaches no key holds nothing.
    fn matters(self) -> bool {
        self.reaches || !self.place.harmless()
    }
}

/// One name of the tree of links.
#[derive(Debug, Clone)]
struct Node {
    /// The name as the caller spelled it, which a pattern is matched against.
    name: Box<str>,
    /// The names below it, by the key [`Tree::key`] gives them, in order of
    /// the key, so that every walk of them is the same.
    children: Box<[(Box<str>, u32)]>,
    /// The target, when this name is a link.
    target: u32,
    /// Whether a link is at or below this name.
    links: bool,
    /// What the links at or below it hold (see [`Held`]).
    held: Option<Held>,
}

/// The links the caller has resolved, as one tree of names from each root,
/// and where each link lands as a tree of its own.
#[derive(Debug, Clone, Default)]
pub(super) struct Tree {
    nodes: Vec<Node>,
    roots: Vec<(Root, u32)>,
    targets: Vec<Target>,
    /// The machine the links are on.
    machine: Machine,
    /// Where each link lands, as a tree of names of its own: a path at or
    /// below where a link lands also has the link's name, which counts for
    /// what it means by name (see `Landed::lent`).
    landed: Vec<Node>,
    landed_roots: Vec<(Root, u32)>,
    /// The links each node of `landed` is where they land, by their place.
    aliases: Vec<Vec<Loc>>,
    /// Whether a link's name holds a character a pattern reads as a
    /// wildcard (`[x]`, `a*b`, `{a,b}`): then a pattern is also read as the
    /// path its text spells.
    wild: bool,
    /// Whether no link is held: more than [`MOST_LINKS`], or past
    /// [`MOST_BUILD`]. Every path is then only known when it runs.
    overflow: bool,
}

/// The machine a tree's links are on.
#[derive(Debug, Clone, Copy, Default)]
struct Machine {
    /// Whether names on a POSIX root compare without case: a Mac's.
    mac: bool,
    /// Whether this is a Windows machine, where a link holds a Windows
    /// path; on a POSIX one (WSL included) it holds a POSIX path, wherever
    /// it is.
    windows: bool,
}

/// What a tree was built for: every field of the directories but the
/// working directory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    home: PathBuf,
    workspaces: Vec<PathBuf>,
    protected: Vec<Protected>,
    secrets: Vec<Secret>,
    mounts: Vec<PathBuf>,
    windows_home: Option<PathBuf>,
    links: usize,
}

/// The tree of the links a [`Paths`] names, built for the directories it
/// holds, and where each folder drives are mounted in lands through them.
#[derive(Debug)]
pub(crate) struct Prepared {
    key: Key,
    tree: Tree,
    /// Each drive mount's folder where it lands through the links, when that
    /// is elsewhere: a drive is a folder of it there too.
    mounts: Vec<Loc>,
}

impl Prepared {
    pub(crate) fn new(paths: &Paths) -> Self {
        let (tree, mounts) = Tree::new(paths);
        Self {
            key: key(paths),
            tree,
            mounts,
        }
    }

    /// The tree.
    pub(super) fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Where the drive mounts' folders land through the links.
    pub(super) fn mount_places(&self) -> &[Loc] {
        &self.mounts
    }

    /// Whether it was built for these directories.
    pub(crate) fn is_for(&self, paths: &Paths) -> bool {
        self.key == key(paths)
    }
}

fn key(paths: &Paths) -> Key {
    Key {
        home: paths.home.clone(),
        workspaces: paths.workspaces.clone(),
        protected: paths.protected.clone(),
        secrets: paths.secrets.clone(),
        mounts: paths.drive_mounts.clone(),
        windows_home: paths.windows_home.clone(),
        links: paths.links.len(),
    }
}

/// A path once it has landed: where, whether any link or mount moved it,
/// the link itself when the path ends at one, the path as it reads at each
/// link it went through, and the names of the links that land where it
/// lands.
#[derive(Debug, Clone)]
pub(super) struct Landed {
    pub(super) loc: Loc,
    pub(super) hopped: bool,
    /// Where the link the path ends at is, when it ends at one: what a
    /// delete or a rename acts on, where a read or a write opens `loc`.
    pub(super) itself: Option<Loc>,
    /// The path as it reads where each link it goes through is, the rest of
    /// it applied by its spelling: each is a name of the same file
    /// (`~/.ssh/id_rsa` through a `~/.ssh` that is a link into the
    /// workspace).
    pub(super) names: Vec<Loc>,
    /// The name each link that lands at or above where the path lands gives
    /// it (`~/.ssh/id_rsa` for `dotfiles/ssh/id_rsa`, with `~/.ssh` a link
    /// to `dotfiles/ssh`): it counts only for what it means by name, never
    /// as a place beyond the workspace.
    pub(super) lent: Vec<Loc>,
    /// How many parts of the path were read before the first link it went
    /// through: a `..` after them may be applied as the text spells it or
    /// as the system climbs (see `Resolver::landings`).
    pub(super) first_hop: Option<usize>,
}

impl Landed {
    /// `loc`, landed with no link on its way.
    pub(super) fn plain(loc: Loc) -> Self {
        Self {
            loc,
            hopped: false,
            itself: None,
            names: Vec::new(),
            lent: Vec::new(),
            first_hop: None,
        }
    }
}

/// A reading of a pattern that picks a link or a drive: where it lands, and
/// the parts of the pattern still to match there (`None` when none is
/// left). `None` for one that goes through more links than are followed, or
/// past the budget.
pub(super) type Picked = Option<(Loc, Option<Vec<String>>)>;

/// A tree being built: its edges in a map until the names are all in.
#[derive(Default)]
struct Building {
    names: Vec<Box<str>>,
    edges: HashMap<(u32, String), u32>,
    targets: Vec<u32>,
    roots: Vec<(Root, u32)>,
}

impl Building {
    fn root(&mut self, root: &Root) -> u32 {
        if let Some((_, node)) = self.roots.iter().find(|(known, _)| known.same(root)) {
            return *node;
        }
        self.names.push("".into());
        self.targets.push(NONE);
        let node = to_u32(self.names.len() - 1);
        self.roots.push((root.clone(), node));
        node
    }

    fn insert(&mut self, loc: &Loc, key: &dyn Fn(&str, &Root) -> String) -> u32 {
        let mut at = self.root(&loc.root);
        for part in &loc.parts {
            let edge = (at, key(part, &loc.root));
            at = if let Some(&child) = self.edges.get(&edge) {
                child
            } else {
                self.names.push(part.as_str().into());
                self.targets.push(NONE);
                let child = to_u32(self.names.len() - 1);
                self.edges.insert(edge, child);
                child
            };
        }
        at
    }

    /// The nodes, each with its children in order of their keys.
    fn finish(self) -> (Vec<Node>, Vec<(Root, u32)>) {
        let mut children: Vec<Vec<(Box<str>, u32)>> = vec![Vec::new(); self.names.len()];
        for ((parent, key), child) in self.edges {
            children[parent as usize].push((key.into_boxed_str(), child));
        }
        let nodes = self
            .names
            .into_iter()
            .zip(children)
            .zip(self.targets)
            .map(|((name, mut children), target)| {
                children.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                Node {
                    name,
                    children: children.into_boxed_slice(),
                    target,
                    links: false,
                    held: None,
                }
            })
            .collect();
        (nodes, self.roots)
    }
}

/// The index of `target` in `targets`, kept once.
fn intern(targets: &mut Vec<Target>, indices: &mut HashMap<Target, u32>, target: &Target) -> u32 {
    if let Some(&index) = indices.get(target) {
        return index;
    }
    targets.push(target.clone());
    let index = to_u32(targets.len() - 1);
    indices.insert(target.clone(), index);
    index
}

/// `at` as a node index.
fn to_u32(at: usize) -> u32 {
    u32::try_from(at).unwrap_or(NONE)
}

impl Tree {
    /// The tree for `paths`, and where its mounts' folders land: each link
    /// placed where it lands (a link named below another one is placed
    /// through it, whichever way it is named and in whatever order), kept
    /// under both of its spellings.
    fn new(paths: &Paths) -> (Self, Vec<Loc>) {
        let home = Loc::absolute(&paths.home.to_string_lossy()).firm();
        let mac = super::is_mac(&home);
        let windows = home.windows();
        let flavour = if windows {
            Flavour::Windows
        } else {
            Flavour::Posix
        };
        let empty = Self {
            machine: Machine { mac, windows },
            ..Self::default()
        };
        if paths.links.len() > MOST_LINKS {
            return (empty.overflowed(), Vec::new());
        }
        // A relative link is read from the first workspace folder, or the
        // home directory when there is none: never from the working
        // directory, which the caller may change from call to call.
        let base = paths.workspaces.first().map_or_else(
            || home.clone(),
            |folder| Loc::absolute(&folder.to_string_lossy()),
        );
        let base = if mac { base.firm() } else { base };
        // What the tree keeps grows with the parts of the names and the
        // targets: they are counted as they are read, and past
        // `MOST_PARTS` none is held.
        let mut kept = 0_usize;
        let mut named: Vec<(Loc, Target)> = Vec::new();
        for link in &paths.links {
            let one = (|| {
                let text = link.path.to_string_lossy();
                if text.is_empty() {
                    return None;
                }
                let rooted =
                    windows_root(&text).is_some() || text.starts_with(flavour.separators());
                let homed = text
                    .strip_prefix('~')
                    .filter(|rest| rest.is_empty() || rest.starts_with(flavour.separators()));
                let loc = if let Some(rest) = homed {
                    home.clone().walk(rest, flavour)
                } else if rooted {
                    Loc::absolute(&text)
                } else {
                    base.clone().walk(&text, flavour)
                };
                let loc = if mac { loc.firm() } else { loc };
                if loc.parts.is_empty() {
                    return None;
                }
                let target = empty.target(link.target.as_deref(), &loc);
                Some((loc, target))
            })();
            let Some((loc, target)) = one else {
                continue;
            };
            kept = loc
                .parts
                .iter()
                .chain(&target.parts)
                .fold(kept, |kept, part| kept.saturating_add(weight(part)));
            if kept > MOST_PARTS {
                return (empty.overflowed(), Vec::new());
            }
            named.push((loc, target));
        }
        let wild = named.iter().any(|(loc, _)| {
            loc.parts
                .iter()
                .any(|part| part.contains(WILDCARDS) || part.contains(['{', '}']))
        });
        let slash = Root::Unix;
        let mounts = Mounts::new(&paths.drive_mounts, &slash, mac);
        let budget = Budget::new(MOST_BUILD);
        // Each round places every link through the tree of the round before,
        // all at once, each from its own name: the answer is the same for
        // every order of the list. A link whose place cannot be worked out
        // is lost.
        let mut places: Vec<Option<Loc>> = named.iter().map(|(loc, _)| Some(loc.clone())).collect();
        let mut lost = vec![false; named.len()];
        let mut tree = empty.build(&named, &places, &lost, &mounts, wild);
        let mut settled = false;
        for _ in 0..MOST_ROUNDS {
            let mut next = Vec::with_capacity(named.len());
            for (spelled, _) in &named {
                let mut parent = spelled.clone();
                let name = parent.parts.pop().unwrap_or_default();
                let mapping = matches!(parent.root, Root::Unix).then_some(Root::Unix);
                let at = tree.land(&mounts, parent, mapping, None, &budget);
                if budget.spent() {
                    return (empty.overflowed(), Vec::new());
                }
                next.push(at.map(|landed| {
                    let mut at = landed.loc;
                    at.parts.push(name);
                    at
                }));
            }
            let same = next.iter().zip(&places).all(|(a, b)| match (a, b) {
                (Some(a), Some(b)) => a.is(b) && a.root.same(&b.root),
                (None, None) => true,
                _ => false,
            });
            if same {
                settled = true;
                break;
            }
            places = next;
            tree = empty.build(&named, &places, &lost, &mounts, wild);
        }
        if !settled {
            // The links still moving are not placed: a round more would move
            // them again, and the guard reads no further.
            let mut next = Vec::with_capacity(named.len());
            for (spelled, _) in &named {
                let mut parent = spelled.clone();
                let name = parent.parts.pop().unwrap_or_default();
                let mapping = matches!(parent.root, Root::Unix).then_some(Root::Unix);
                next.push(
                    tree.land(&mounts, parent, mapping, None, &budget)
                        .map(|landed| {
                            let mut at = landed.loc;
                            at.parts.push(name);
                            at
                        }),
                );
            }
            if budget.spent() {
                return (empty.overflowed(), Vec::new());
            }
            // A link still moving is lost where it is named and where it
            // would be placed next.
            for ((place, moved), lost) in places.iter_mut().zip(next).zip(&mut lost) {
                let same = match (&*place, &moved) {
                    (Some(a), Some(b)) => a.is(b) && a.root.same(&b.root),
                    _ => false,
                };
                if !same {
                    *place = moved;
                    *lost = true;
                }
            }
            tree = empty.build(&named, &places, &lost, &mounts, wild);
        }
        // Where each link lands: its name is lent to what is there.
        let mut lands: Vec<Option<Loc>> = Vec::with_capacity(named.len());
        for (((_, target), place), lost) in named.iter().zip(&places).zip(&lost) {
            let landed = place.as_ref().filter(|_| !lost).and_then(|place| {
                let mut parent = place.clone();
                parent.parts.pop();
                tree.through(&mounts, &parent, target, &[], None, &budget)
                    .map(|(loc, _)| loc)
            });
            lands.push(landed);
        }
        if budget.spent() {
            return (empty.overflowed(), Vec::new());
        }
        let mut lent: Vec<(&Loc, &Loc)> = Vec::new();
        for (((spelled, _), place), landed) in named.iter().zip(&places).zip(&lands) {
            if let (Some(landed), Some(place)) = (landed, place) {
                lent.push((landed, spelled));
                lent.push((landed, place));
            }
        }
        tree.alias_all(&lent);
        // Each mount's folder where it lands through the links.
        let mut mount_places = Vec::new();
        for folder in &paths.drive_mounts {
            let Some(loc) = super::mount::folder(&folder.to_string_lossy()) else {
                continue;
            };
            if let Some(landed) = tree.land(&Mounts::default(), loc.clone(), None, None, &budget) {
                if !(landed.loc.is(&loc) && landed.loc.root.same(&loc.root)) {
                    mount_places.push(landed.loc);
                }
            }
        }
        tree.hold(paths, &named, &places, &lands, &mounts, &budget);
        (tree, mount_places)
    }

    /// No link held: every path is only known when it runs.
    fn overflowed(mut self) -> Self {
        self.overflow = true;
        self
    }

    /// The tree of the links `named`, each at its own name and at its place
    /// in `places` (`None` for one with none), with every spelling a Mac or a
    /// drive mount gives it: one with no place, or lost in `lost_links`, is
    /// lost at each.
    fn build(
        &self,
        named: &[(Loc, Target)],
        places: &[Option<Loc>],
        lost_links: &[bool],
        mounts: &Mounts,
        wild: bool,
    ) -> Self {
        let mut tree = Self {
            machine: self.machine,
            wild,
            ..Self::default()
        };
        let mut building = Building::default();
        let mut indices: HashMap<Target, u32> = HashMap::new();
        let lost = Target {
            start: Start::Lost,
            parts: Vec::new(),
            posix: false,
        };
        let key = |name: &str, root: &Root| self.key(name, root);
        for (((spelled, target), place), gone) in named.iter().zip(places).zip(lost_links) {
            let target = if place.is_some() && !gone {
                target
            } else {
                &lost
            };
            let index = intern(&mut tree.targets, &mut indices, target);
            for at in std::iter::once(spelled).chain(place.iter()) {
                for spelling in self.spellings(at, mounts) {
                    let node = building.insert(&spelling, &key) as usize;
                    let set = match building.targets[node] {
                        NONE => index,
                        known if known == index => index,
                        _ => intern(&mut tree.targets, &mut indices, &lost),
                    };
                    building.targets[node] = set;
                }
            }
        }
        let (nodes, roots) = building.finish();
        tree.nodes = nodes;
        tree.roots = roots;
        tree.mark_links();
        tree
    }

    /// The tree of where each link lands, each `(lands, place)` keeping
    /// `place`, a link, as a name of `lands`: built in one pass, each name's
    /// children sorted once, so the cost is the same for each link.
    fn alias_all(&mut self, lent: &[(&Loc, &Loc)]) {
        let mut building = Building::default();
        let mut aliases: HashMap<u32, Vec<Loc>> = HashMap::new();
        let key = |name: &str, root: &Root| self.key(name, root);
        for (lands, place) in lent {
            let node = building.insert(lands, &key);
            let known = aliases.entry(node).or_default();
            if !known
                .iter()
                .any(|alias| alias.is(place) && alias.root.same(&place.root))
            {
                known.push((*place).clone());
            }
        }
        let (nodes, roots) = building.finish();
        let mut list = vec![Vec::new(); nodes.len()];
        for (node, names) in aliases {
            list[node as usize] = names;
        }
        self.landed = nodes;
        self.landed_roots = roots;
        self.aliases = list;
    }

    /// Whether a link lands at, below or above `folder` (already landed):
    /// a name in it may be one a link lends, whether the link lands on a
    /// folder it holds or on one that holds it (`~/.config` a link to the
    /// `dotfiles/config` the workspace is in).
    pub(super) fn lands_around(&self, folder: &Loc, budget: &Budget) -> bool {
        let Some(mut at) = landed_root(&self.landed_roots, &folder.root) else {
            return false;
        };
        for part in &folder.parts {
            if !budget.spend(1) || !self.aliases[at as usize].is_empty() {
                return true;
            }
            let Some(child) = find(
                &self.landed[at as usize].children,
                &self.key(part, &folder.root),
            ) else {
                return false;
            };
            at = child;
        }
        true
    }

    /// The names other links lend `loc`: for each place at or above it that
    /// a link lands on, the link's own place with the rest of `loc` below it.
    fn names_of(&self, loc: &Loc, budget: &Budget) -> Vec<Loc> {
        self.names_lent(loc, budget, false)
    }

    /// [`names_of`](Self::names_of); with `again`, for a name already lent,
    /// without the links named below where they land themselves (`up` a
    /// link to `..`), which would lend every name below them again, without
    /// end.
    fn names_lent(&self, loc: &Loc, budget: &Budget, again: bool) -> Vec<Loc> {
        let mut names = Vec::new();
        let Some(mut at) = landed_root(&self.landed_roots, &loc.root) else {
            return names;
        };
        for (depth, part) in loc.parts.iter().enumerate() {
            if !budget.spend(1) {
                return names;
            }
            let Some(child) = find(
                &self.landed[at as usize].children,
                &self.key(part, &loc.root),
            ) else {
                return names;
            };
            at = child;
            for alias in &self.aliases[at as usize] {
                if !budget.spend(1) {
                    return names;
                }
                let below_itself = alias.root.same(&loc.root)
                    && alias.parts.len() > depth
                    && alias.parts[..=depth]
                        .iter()
                        .zip(&loc.parts[..=depth])
                        .all(|(a, b)| self.key(a, &loc.root) == self.key(b, &loc.root));
                if again && below_itself {
                    continue;
                }
                let mut name = alias.clone();
                name.parts.extend(loc.parts[depth + 1..].iter().cloned());
                names.push(name);
            }
        }
        names
    }

    /// Work out what each folder holds through the links at or below it,
    /// for a tool that follows them: for each link, what it lands on (judged
    /// on the directories without the links), and what the links at or
    /// below where it lands hold, round after round until nothing changes.
    /// A link still changing after [`MOST_ROUNDS`] holds a place only known
    /// when it runs.
    fn hold(
        &mut self,
        paths: &Paths,
        named: &[(Loc, Target)],
        places: &[Option<Loc>],
        lands: &[Option<Loc>],
        mounts: &Mounts,
        budget: &Budget,
    ) {
        let mut plain = paths.clone();
        plain.links = crate::paths::Links::default();
        let resolver = Resolver::new(&plain);
        let flavour = resolver.flavour();
        let unknown = Held {
            place: Place::Unknown,
            reaches: false,
        };
        // Each link's node, and what it lands on.
        let mut links: Vec<(u32, Held, Option<Loc>)> = Vec::with_capacity(named.len());
        for (((spelled, _), place), landed) in named.iter().zip(places).zip(lands) {
            let at = place.as_ref().unwrap_or(spelled);
            let Some(node) = self.node_of(at, mounts, budget) else {
                continue;
            };
            let own = match landed {
                Some(loc) => Held {
                    place: resolver.judge(loc, flavour, true),
                    reaches: resolver.reaches_at(loc, &[], flavour, true, true),
                },
                None => unknown,
            };
            links.push((node, own, landed.clone()));
        }
        let mut held: Vec<Held> = links.iter().map(|(_, own, _)| *own).collect();
        let mut settled = false;
        for _ in 0..MOST_ROUNDS {
            self.gather(&links, &held);
            let next: Vec<Held> = links
                .iter()
                .map(|(_, own, landed)| {
                    let below = landed
                        .as_ref()
                        .and_then(|loc| self.node_of(loc, mounts, budget))
                        .and_then(|node| self.nodes[node as usize].held);
                    below.map_or(*own, |below| own.max(below))
                })
                .collect();
            if next == held {
                settled = true;
                break;
            }
            held = next;
        }
        // Still changing after the last round: what each folder holds is
        // only known when it runs, and it may reach a key.
        if !settled {
            held.fill(Held {
                place: Place::Unknown,
                reaches: true,
            });
        }
        self.gather(&links, &held);
    }

    /// Set what each node holds from what each link holds.
    fn gather(&mut self, links: &[(u32, Held, Option<Loc>)], held: &[Held]) {
        for node in &mut self.nodes {
            node.held = None;
        }
        for ((node, _, _), each) in links.iter().zip(held) {
            if each.matters() {
                let node = &mut self.nodes[*node as usize];
                node.held = Some(node.held.map_or(*each, |known| known.max(*each)));
            }
        }
        // Children always come after their parents in `nodes`, so one pass
        // from the end carries each up.
        for at in (0..self.nodes.len()).rev() {
            let mut held = self.nodes[at].held;
            for &(_, child) in &self.nodes[at].children {
                if let Some(below) = self.nodes[child as usize].held {
                    held = Some(held.map_or(below, |known| known.max(below)));
                }
            }
            self.nodes[at].held = held;
        }
    }

    /// The node `loc` (already landed) is, when it is in the tree.
    fn node_of(&self, loc: &Loc, _mounts: &Mounts, budget: &Budget) -> Option<u32> {
        let mut at = self.root(&loc.root)?;
        for part in &loc.parts {
            at = self.child(at, part, &loc.root, budget)?;
        }
        Some(at)
    }

    /// What the links at or below `loc` (already landed) hold.
    pub(super) fn held(&self, loc: &Loc, budget: &Budget) -> Option<Held> {
        if self.overflow {
            return Some(Held {
                place: Place::Unknown,
                reaches: false,
            });
        }
        let node = self.node_of(loc, &Mounts::default(), budget)?;
        self.nodes[node as usize].held
    }

    /// Whether a link's name holds a wildcard character.
    pub(super) fn wild(&self) -> bool {
        self.wild
    }

    /// Whether no link is held, so every path is only known when it runs.
    pub(super) fn overflow(&self) -> bool {
        self.overflow
    }

    /// Mark each name a link is at or below.
    fn mark_links(&mut self) {
        // Children always come after their parents in `nodes`, so one pass
        // from the end carries each mark up.
        for at in (0..self.nodes.len()).rev() {
            let below = self.nodes[at].target != NONE
                || self.nodes[at]
                    .children
                    .iter()
                    .any(|&(_, child)| self.nodes[child as usize].links);
            self.nodes[at].links = below;
        }
    }

    /// The spellings a link at `at` is kept under: on a Mac, also through
    /// each of its links to the root (`/System/Volumes/Data`) and the other
    /// side of its link into `/private` (`/tmp` and `/private/tmp`), so a
    /// path spelled either way goes through it; on a machine with drive
    /// mounts, a link on a drive also under each mount's folder (`C:\x` is
    /// `/mnt/c/x`), and one under a mount's folder also on the drive.
    fn spellings(&self, at: &Loc, mounts: &Mounts) -> Vec<Loc> {
        let mut spellings = vec![at.clone()];
        if let Some(drive) = self.on_drive(at, mounts) {
            spellings.push(drive);
        }
        for folder in mounts.folders() {
            if let Root::Drive(letter) = at.root {
                let mut parts = folder.parts.clone();
                parts.push(letter.to_ascii_lowercase().to_string());
                parts.extend(at.parts.iter().cloned());
                spellings.push(Loc {
                    root: folder.root.clone(),
                    parts,
                });
            }
        }
        if !self.machine.mac || !matches!(at.root, Root::Unix) {
            return spellings;
        }
        spellings.extend(at.other_spelling());
        let plain = spellings.clone();
        for spelling in &plain {
            for link in super::MAC_LINKS {
                let mut parts: Vec<String> = link.iter().map(|part| (*part).to_string()).collect();
                parts.extend(spelling.parts.iter().cloned());
                spellings.push(Loc {
                    root: Root::Unix,
                    parts,
                });
            }
        }
        spellings
    }

    /// `at` on the drive a mount's folder shows, when it is under one.
    fn on_drive(&self, at: &Loc, mounts: &Mounts) -> Option<Loc> {
        if !matches!(at.root, Root::Unix) {
            return None;
        }
        let budget = Budget::new(at.parts.len() * 2 + 2);
        let mut node = mounts.root_node(&at.root)?;
        for (depth, part) in at.parts.iter().enumerate() {
            if mounts.is_mount(node) {
                if let Some(letter) = letter(part) {
                    return Some(Loc {
                        root: Root::Drive(letter),
                        parts: at.parts[depth + 1..].to_vec(),
                    });
                }
            }
            node = mounts.child_node(node, part, &at.root, &budget)?;
        }
        None
    }

    /// The target `text` of a link at `link`, spelled as the machine spells
    /// paths: on a POSIX machine a POSIX path (from `/`, or from the folder
    /// the link is in), a link on a mounted drive included; on Windows a
    /// Windows one, the raw forms a junction holds read too (`\??\C:\x`,
    /// `\\?\C:\x`), a root with no drive the link's own drive. `None`, an
    /// empty text, one longer than any system keeps, and one that names no
    /// drive or share (a volume, a device) are lost.
    fn target(&self, text: Option<&Path>, link: &Loc) -> Target {
        let lost = Target {
            start: Start::Lost,
            parts: Vec::new(),
            posix: false,
        };
        let Some(text) = text.map(|text| text.to_string_lossy().into_owned()) else {
            return lost;
        };
        if text.is_empty() || text.len() > MOST_TARGET {
            return lost;
        }
        if !self.machine.windows {
            // On WSL, a link on a Windows drive Windows made holds a Windows
            // path: a drive and a separator.
            if link.windows() {
                if let Some((root @ Root::Drive(_), rest)) = windows_root(&text) {
                    if rest.starts_with(Flavour::Windows.separators()) {
                        return Target {
                            start: Start::Root(root),
                            parts: split(rest, Flavour::Windows),
                            posix: false,
                        };
                    }
                }
            }
            let start = if text.starts_with('/') {
                Start::Root(Root::Unix)
            } else {
                Start::Parent
            };
            return Target {
                start,
                parts: split(&text, Flavour::Posix),
                posix: true,
            };
        }
        // The NT prefix a junction holds is the object namespace a long
        // path's `\\?\` is.
        let text = match text.strip_prefix(r"\??\") {
            Some(rest) => format!(r"\\?\{rest}"),
            None => text,
        };
        // The device namespace, which names no drive or share.
        if super::prefix(&text, '.').is_some() {
            return lost;
        }
        if let Some((root, rest)) = windows_root(&text) {
            // `C:x` is from that drive's own working directory, which no link
            // shows.
            if matches!(root, Root::Drive(_))
                && !rest.is_empty()
                && !rest.starts_with(Flavour::Windows.separators())
            {
                return lost;
            }
            return Target {
                start: Start::Root(root),
                parts: split(rest, Flavour::Windows),
                posix: false,
            };
        }
        // A long path to no drive or share.
        if verbatim(&text).is_some() {
            return lost;
        }
        let start = if text.starts_with(Flavour::Windows.separators()) {
            Start::Root(link.root.clone())
        } else {
            Start::Parent
        };
        Target {
            start,
            parts: split(&text, Flavour::Windows),
            posix: false,
        }
    }

    /// The node of a root, when anything is below it.
    fn root(&self, root: &Root) -> Option<u32> {
        self.roots
            .iter()
            .find(|(known, _)| known.same(root))
            .map(|(_, node)| *node)
    }

    /// What a name is looked up by on `root`: itself where names compare
    /// with case, and folded where they do not (a drive or a share, and a
    /// Mac): by the widest fold, in either canonical spelling.
    fn key(&self, name: &str, root: &Root) -> String {
        if !self.machine.mac && matches!(root, Root::Unix) {
            return name.to_string();
        }
        if name.is_ascii() {
            return name.to_ascii_lowercase();
        }
        canonical::decomposed(name).into_iter().map(fold).collect()
    }

    /// The node below `node` that `name` is, on `root`: by its key, and on
    /// Windows by its 8.3 short name too (`MYSECR~1` for `mysecretkeys`),
    /// each name below counted against the budget.
    fn child(&self, node: u32, name: &str, root: &Root, budget: &Budget) -> Option<u32> {
        let children = &self.nodes[node as usize].children;
        if let Some(child) = find(children, &self.key(name, root)) {
            return Some(child);
        }
        if !matches!(root, Root::Unix) && name.contains('~') {
            for &(_, child) in children {
                if !budget.spend(1) {
                    return None;
                }
                if short_name(name, &self.nodes[child as usize].name) {
                    return Some(child);
                }
            }
        }
        None
    }

    /// The node of each part of `loc`, from its root: `None` from the first
    /// name that has none.
    fn nodes_of(&self, loc: &Loc, budget: &Budget) -> (Option<u32>, Vec<Option<u32>>) {
        let base = self.root(&loc.root);
        let mut nodes = Vec::with_capacity(loc.parts.len());
        let mut at = base;
        for part in &loc.parts {
            at = at.and_then(|node| self.child(node, part, &loc.root, budget));
            nodes.push(at);
        }
        (base, nodes)
    }

    /// Where `raw` lands: its parts walked in order from its root, `..` kept
    /// where it was written, each name looked up as it comes. A link is
    /// replaced by its target, whose parts are walked next, and a `..` after
    /// it climbs from there, as a POSIX system climbs. Under a mount (see
    /// `mount`), a folder of one letter is that drive, where `mapping` says
    /// a POSIX path is read, and a `..` above the drive's root is the
    /// mount's folder again; `entered` says the walk starts on a drive read
    /// through that folder (a relative path in Git Bash). `None` for a path
    /// through more links than [`MOST_HOPS`], through a lost link, or past
    /// the budget.
    pub(super) fn land(
        &self,
        mounts: &Mounts,
        raw: Loc,
        mut mapping: Option<Root>,
        mut entered: Option<(Loc, Root)>,
        budget: &Budget,
    ) -> Option<Landed> {
        if self.overflow {
            return None;
        }
        let raw_len = raw.parts.len();
        let mut out = Loc::at(raw.root);
        let mut walk = Walk::of(self, mounts, &out, budget);
        let mut queue: VecDeque<String> = raw.parts.into();
        let mut raw_left = raw_len;
        let mut itself: Option<Loc> = None;
        let mut names = Vec::new();
        let (mut hops, mut hopped, mut first_hop) = (0, false, None);
        while let Some(part) = queue.pop_front() {
            if queue.len() < raw_left {
                raw_left -= 1;
            }
            if !budget.spend(1) {
                return None;
            }
            if part == ".." {
                if out.parts.pop().is_some() {
                    walk.pop();
                } else if let Some((folder, root)) = entered.take() {
                    if !budget.spend(folder.parts.len()) {
                        return None;
                    }
                    walk = Walk::of(self, mounts, &folder, budget);
                    out = folder;
                    mapping = Some(root);
                }
                continue;
            }
            if let Some(root) = &mapping {
                if walk.at_mount(mounts) && out.root.same(root) {
                    if let Some(letter) = letter(&part) {
                        entered = Some((out, root.clone()));
                        out = Loc::at(Root::Drive(letter));
                        walk = Walk::of(self, mounts, &out, budget);
                        mapping = None;
                        hopped = true;
                        continue;
                    }
                }
            }
            let node = walk.push(self, mounts, &part, &out.root, budget);
            out.parts.push(part);
            let Some(target) = node
                .map(|node| self.nodes[node as usize].target)
                .filter(|&t| t != NONE)
            else {
                continue;
            };
            hops += 1;
            if hops > MOST_HOPS {
                return None;
            }
            if !hopped {
                first_hop = Some(raw_len - raw_left);
            }
            hopped = true;
            // The path as it reads here, the rest applied by its spelling.
            let mut name = out.clone();
            if !budget.spend(queue.len()) {
                return None;
            }
            for part in &queue {
                if part == ".." {
                    name.parts.pop();
                } else {
                    name.parts.push(part.clone());
                }
            }
            names.push(name);
            // The path ends at this link: the first of a chain that does is
            // the link itself.
            if queue.is_empty() && itself.is_none() {
                itself = Some(out.clone());
            }
            let target = &self.targets[target as usize];
            if !budget.spend(target.parts.len()) {
                return None;
            }
            match &target.start {
                Start::Lost => return None,
                Start::Parent => {
                    out.parts.pop();
                    walk.pop();
                }
                Start::Root(root) => {
                    out = Loc::at(root.clone());
                    walk = Walk::of(self, mounts, &out, budget);
                    mapping = target.posix.then(|| root.clone());
                    entered = None;
                }
            }
            for part in target.parts.iter().rev() {
                queue.push_front(part.clone());
            }
        }
        // Where it lands may be where a link lands too: that link's name is
        // lent to it, and to each name it has on the way.
        let mut lent = Vec::new();
        if !self.landed.is_empty() {
            lent = self.names_of(&out, budget);
            for name in &names {
                lent.extend(self.names_of(name, budget));
            }
            // A name lent may itself be where another link lands, named
            // there: that link lends the name its own name too, one hop
            // after another, each once.
            let mut seen: std::collections::HashSet<String> = lent.iter().map(Loc::key).collect();
            // At most as many as the links a path is followed through: a
            // link to a folder above itself lends every name below it again,
            // without end.
            let mut next = 0;
            while next < lent.len() && lent.len() <= MOST_HOPS {
                let more = self.names_lent(&lent[next], budget, true);
                next += 1;
                for name in more {
                    if lent.len() > MOST_HOPS {
                        break;
                    }
                    if seen.insert(name.key()) {
                        lent.push(name);
                    }
                }
            }
        }
        Some(Landed {
            loc: out,
            hopped,
            itself,
            names,
            lent,
            first_hop,
        })
    }

    /// The readings of a pattern whose parts `tail`, from the folder it
    /// starts in (`folder`, already landed), can pick a link or a drive
    /// under a mount: a part is matched against a link's name (`matches`
    /// says how, with whether the name is on Windows), one part to one name,
    /// a part of two or more stars (`**`) to any number of them, and the
    /// link's target then lands with the plain parts that follow, and what
    /// is left of the pattern from its next wildcard part, which is read
    /// again for the links below where it lands. A drive is read as each of
    /// `letters`, where `mapping` says a POSIX path is read. Each name is
    /// matched once for each part, and every match and landing is counted
    /// against the budget: past it, the reading is `None`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the pattern, where it is read and how its parts match"
    )]
    pub(super) fn picked(
        &self,
        mounts: &Mounts,
        folder: &Loc,
        tail: &[String],
        mapping: Option<&Root>,
        letters: &[char],
        matches: &dyn Fn(&str, &str, bool) -> bool,
        budget: &Budget,
    ) -> Vec<Picked> {
        let mut readings = Vec::new();
        let mut patterns: Vec<(Loc, Vec<String>, Option<Root>, usize)> =
            vec![(folder.clone(), tail.to_vec(), mapping.cloned(), 0)];
        while let Some((folder, tail, mapping, level)) = patterns.pop() {
            for (reading, mapping) in self.picked_once(
                mounts,
                &folder,
                &tail,
                mapping.as_ref(),
                letters,
                matches,
                budget,
            ) {
                if let Some((loc, Some(rest))) = &reading {
                    if level < MOST_HOPS {
                        patterns.push((loc.clone(), rest.clone(), mapping, level + 1));
                    }
                }
                readings.push(reading);
            }
        }
        readings
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the pattern, where it is read and how its parts match"
    )]
    fn picked_once(
        &self,
        mounts: &Mounts,
        folder: &Loc,
        tail: &[String],
        mapping: Option<&Root>,
        letters: &[char],
        matches: &dyn Fn(&str, &str, bool) -> bool,
        budget: &Budget,
    ) -> Vec<(Picked, Option<Root>)> {
        let mut readings = Vec::new();
        let start = Walk::of(self, mounts, folder, budget);
        let (link, mount) = (start.link(), start.mount());
        if link.is_none() && mount.is_none() {
            return readings;
        }
        let windows = folder.windows();
        let on_mapping = mapping.is_some_and(|root| folder.root.same(root));
        let mut seen: std::collections::HashSet<(Option<u32>, Option<usize>, usize)> =
            std::collections::HashSet::new();
        let mut picked: std::collections::HashSet<(char, usize)> = std::collections::HashSet::new();
        let mut stack: Vec<(Option<u32>, Option<usize>, usize, Loc)> =
            vec![(link, mount.filter(|_| on_mapping), 0, folder.clone())];
        while let Some((link, mount, depth, at)) = stack.pop() {
            if !seen.insert((link, mount, depth)) {
                continue;
            }
            let Some(part) = tail.get(depth) else {
                continue;
            };
            let globstar = is_globstar(part);
            if globstar {
                // The stars may take no name at all.
                stack.push((link, mount, depth + 1, at.clone()));
            }
            let pattern = if globstar { "*" } else { part.as_str() };
            let from = if globstar { depth } else { depth + 1 };
            let rest = &tail[from..];
            if mount.is_some_and(|node| mounts.is_mount(node)) {
                for &letter in letters {
                    if !budget.spend(1) {
                        readings.push((None, None));
                        return readings;
                    }
                    let name = letter.to_ascii_lowercase().to_string();
                    if matches(pattern, &name, windows) && picked.insert((letter, from)) {
                        readings.push((
                            self.reading(mounts, Loc::at(Root::Drive(letter)), rest, None, budget),
                            None,
                        ));
                    }
                }
            }
            // The names below, of either tree, each once.
            let mut below: Vec<(&str, Option<u32>, Option<usize>)> = Vec::new();
            if let Some(node) = link {
                for &(_, child) in &self.nodes[node as usize].children {
                    if self.nodes[child as usize].links {
                        below.push((&self.nodes[child as usize].name, Some(child), None));
                    }
                }
            }
            if let Some(node) = mount {
                for (name, child) in mounts.children_of(node) {
                    match below
                        .iter_mut()
                        .find(|(known, ..)| self.key(known, &at.root) == self.key(name, &at.root))
                    {
                        Some(entry) => entry.2 = Some(child),
                        None => below.push((name, None, Some(child))),
                    }
                }
            }
            for (name, link_child, mount_child) in below {
                // A link that lands somewhere harmless, with nothing serious
                // at or below where it lands (what the build worked out),
                // gives a reading no answer is more serious for: it is not
                // matched or read again, and costs the budget nothing.
                if mount_child.is_none()
                    && link_child.is_some_and(|child| {
                        let node = &self.nodes[child as usize];
                        node.target != NONE && node.held.is_none()
                    })
                {
                    continue;
                }
                if !budget.spend(1) {
                    readings.push((None, None));
                    return readings;
                }
                if !matches(pattern, name, windows) {
                    continue;
                }
                let mut next = at.clone();
                next.parts.push(name.to_string());
                match link_child
                    .map(|child| self.nodes[child as usize].target)
                    .filter(|&target| target != NONE)
                {
                    Some(target) => {
                        let target = &self.targets[target as usize];
                        let mapping = match &target.start {
                            Start::Root(root) => target.posix.then(|| root.clone()),
                            _ => mapping.cloned(),
                        };
                        readings.push((
                            self.through(mounts, &at, target, rest, mapping.clone(), budget),
                            mapping,
                        ));
                    }
                    None => stack.push((
                        link_child,
                        mount_child,
                        if globstar { depth } else { depth + 1 },
                        next,
                    )),
                }
            }
        }
        readings
    }

    /// Where the link in the folder `at` with the target `target` lands,
    /// with `rest` after it.
    fn through(
        &self,
        mounts: &Mounts,
        at: &Loc,
        target: &Target,
        rest: &[String],
        mapping: Option<Root>,
        budget: &Budget,
    ) -> Picked {
        let (from, mapping) = match &target.start {
            Start::Lost => return None,
            Start::Parent => (at.clone(), mapping),
            Start::Root(root) => (Loc::at(root.clone()), target.posix.then(|| root.clone())),
        };
        let mut raw = from;
        raw.parts.extend(target.parts.iter().cloned());
        self.reading(mounts, raw, rest, mapping, budget)
    }

    /// `raw` with the plain parts of `rest` up to its next wildcard part,
    /// landed, and the parts from that one on.
    fn reading(
        &self,
        mounts: &Mounts,
        mut raw: Loc,
        rest: &[String],
        mapping: Option<Root>,
        budget: &Budget,
    ) -> Picked {
        if !budget.spend(rest.len()) {
            return None;
        }
        let wild = rest
            .iter()
            .position(|part| part.contains(WILDCARDS))
            .unwrap_or(rest.len());
        raw.parts.extend(rest[..wild].iter().cloned());
        let landed = self.land(mounts, raw, mapping, None, budget)?;
        let left = (wild < rest.len()).then(|| rest[wild..].to_vec());
        Some((landed.loc, left))
    }

    /// Whether a link is at or below `loc` (already landed).
    pub(super) fn links_at_or_below(&self, loc: &Loc, budget: &Budget) -> bool {
        let (base, nodes) = self.nodes_of(loc, budget);
        match nodes.last() {
            Some(node) => node.is_some_and(|node| self.nodes[node as usize].links),
            None => base.is_some_and(|node| self.nodes[node as usize].links),
        }
    }
}

/// Where a walk is in both trees: the link tree's node of each part of the
/// path so far, and the mount tree's.
struct Walk {
    link_base: Option<u32>,
    links: Vec<Option<u32>>,
    mount_base: Option<usize>,
    mounts: Vec<Option<usize>>,
}

impl Walk {
    /// The nodes of `loc` in both trees.
    fn of(tree: &Tree, mounts: &Mounts, loc: &Loc, budget: &Budget) -> Self {
        let (link_base, links) = tree.nodes_of(loc, budget);
        let mount_base = mounts.root_node(&loc.root);
        let mut at = mount_base;
        let mut nodes = Vec::with_capacity(loc.parts.len());
        for part in &loc.parts {
            at = at.and_then(|node| mounts.child_node(node, part, &loc.root, budget));
            nodes.push(at);
        }
        Self {
            link_base,
            links,
            mount_base,
            mounts: nodes,
        }
    }

    fn link(&self) -> Option<u32> {
        match self.links.last() {
            Some(node) => *node,
            None => self.link_base,
        }
    }

    fn mount(&self) -> Option<usize> {
        match self.mounts.last() {
            Some(node) => *node,
            None => self.mount_base,
        }
    }

    /// Whether the walk is at a mount's folder.
    fn at_mount(&self, mounts: &Mounts) -> bool {
        self.mount().is_some_and(|node| mounts.is_mount(node))
    }

    /// One part more: the link tree's node of it.
    fn push(
        &mut self,
        tree: &Tree,
        mounts: &Mounts,
        part: &str,
        root: &Root,
        budget: &Budget,
    ) -> Option<u32> {
        let link = self
            .link()
            .and_then(|node| tree.child(node, part, root, budget));
        let mount = self
            .mount()
            .and_then(|node| mounts.child_node(node, part, root, budget));
        self.links.push(link);
        self.mounts.push(mount);
        link
    }

    fn pop(&mut self) {
        self.links.pop();
        self.mounts.pop();
    }
}

/// The child `key` names among `children`, in order of their keys.
fn find(children: &[(Box<str>, u32)], key: &str) -> Option<u32> {
    children
        .binary_search_by(|(known, _)| known.as_ref().cmp(key))
        .ok()
        .map(|at| children[at].1)
}

/// The parts of a link's target, `.` and empty parts dropped and each `..`
/// kept, a Windows name read as Windows reads it.
fn split(text: &str, flavour: Flavour) -> Vec<String> {
    let names: Vec<&str> = text.split(flavour.separators()).collect();
    names
        .iter()
        .enumerate()
        .map(|(at, part)| match flavour {
            Flavour::Windows => windows_name(part, at + 1 == names.len()),
            Flavour::Posix => part,
        })
        .filter(|part| !matches!(*part, "" | "."))
        .map(str::to_string)
        .collect()
}

/// The node of `root` among `roots`, when anything is below it.
fn landed_root(roots: &[(Root, u32)], root: &Root) -> Option<u32> {
    roots
        .iter()
        .find(|(known, _)| known.same(root))
        .map(|(_, node)| *node)
}
