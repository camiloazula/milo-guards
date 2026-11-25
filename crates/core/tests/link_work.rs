//! The work of placing a path through the links the caller names, held to
//! a count, not to the clock: one judged call has one budget of counted work
//! for every walk it makes, a path is followed through no more links than
//! any system follows, a link's target is read up to the longest any system
//! keeps, and past any of these the path is only known when it runs, never
//! a place. The tree of the links is built once, the first time a guard
//! judges with them, and kept, so a call costs a lookup for each part of a
//! path, however many links are named; its build has a budget of its own,
//! holds at most so many links and places links named below links in so
//! many rounds, and past any of these the links are lost, whatever the
//! order of the list. A count is the same on every machine, so this runs in
//! every build. It reads the counts through core's `testing` feature.
//!
//! Each bound is held to the number written here, so a bound that is
//! removed, or made ten times larger, fails.

use milo_guards_core::testing::{
    link_work, posix, work_of_each, MOST_BUILD, MOST_HOPS, MOST_LINKS, MOST_PARTS, MOST_ROUNDS,
    MOST_TARGET, MOST_WORK, PART_BYTES,
};
use milo_guards_core::{Flavour, Link, Paths, Place, Resolver, Sensitivity, Spelling};

/// The most work one judged call spends on links, as written here.
const WORK: usize = 1_048_576;

/// The most links a path is followed through, as written here: Windows's.
const HOPS: usize = 63;

/// The longest target read, in bytes, as written here: Linux's `PATH_MAX`.
const TARGET: usize = 4_096;

/// The most links held, as written here.
const LINKS: usize = 262_144;

/// The most parts of the links' names and targets held, as written here,
/// and the bytes of a part that count as one part more.
const PARTS: usize = 1_048_576;
const BYTES: usize = 64;

/// The most work the build of the tree spends, as written here.
const BUILD: usize = 33_554_432;

/// The most rounds links named below links are placed in, as written here.
const ROUNDS: usize = 8;

fn place(paths: &Paths, path: &str) -> Place {
    Resolver::new(paths).place(Spelling::Plain(path), Flavour::Posix)
}

const KEY: Place = Place::Sensitive("your SSH keys", Sensitivity::Secret);

/// `count` links in the workspace, none of them on the paths below.
fn many_links(count: usize) -> Paths {
    posix().with_links(
        (0..count).map(|at| Link::new(format!("/home/me/work/repo/l{at}"), format!("/data/{at}"))),
    )
}

#[test]
fn the_bounds_are_the_ones_written_here() {
    assert_eq!(MOST_WORK, WORK);
    assert_eq!(MOST_HOPS, HOPS);
    assert_eq!(MOST_TARGET, TARGET);
    assert_eq!(MOST_LINKS, LINKS);
    assert_eq!(MOST_PARTS, PARTS);
    assert_eq!(PART_BYTES, BYTES);
    assert_eq!(MOST_BUILD, BUILD);
    assert_eq!(MOST_ROUNDS, ROUNDS);
}

#[test]
fn a_path_costs_the_same_whatever_the_number_of_links() {
    for parts in [1, 10, 100, 1_000] {
        let path = vec!["d"; parts].join("/");
        let alone = link_work(&many_links(1), &path, Flavour::Posix);
        for count in [10, 100, 1_000, 10_000] {
            let work = link_work(&many_links(count), &path, Flavour::Posix);
            assert_eq!(work.work, alone.work, "{count} links, {parts} parts");
            assert_eq!(place(&many_links(count), &path), Place::Inside);
        }
        // Each landing reads each part once: the path as walked and with
        // its `..` applied first, from the working directory's four parts.
        assert!(alone.work <= 3 * (4 + parts), "{parts} parts: {alone:?}");
    }
}

#[test]
fn the_tree_is_built_once_and_kept_whatever_the_working_directory() {
    let paths = many_links(50_000);
    // Built on the first call, and kept for every later one and every copy.
    assert_eq!(paths.links.as_slice().len(), 50_000);
    let _ = link_work(&paths, "src/main.rs", Flavour::Posix);
    assert!(link_work(&paths, "src/main.rs", Flavour::Posix).kept);
    // A working directory changed by hand reads the same tree.
    let mut moved = paths.clone();
    moved.cwd = "/home/me/work/repo/src".into();
    assert!(link_work(&moved, "main.rs", Flavour::Posix).kept);
    // A workspace changed by hand is not what it was built for.
    let mut other = paths.clone();
    other.workspaces.push("/data".into());
    assert!(!link_work(&other, "src/main.rs", Flavour::Posix).kept);
    // Mounts named after the links build it again, for them, on first use.
    let mounted = paths.with_drive_mounts(["/mnt"]);
    let _ = link_work(&mounted, "src/main.rs", Flavour::Posix);
    assert!(link_work(&mounted, "src/main.rs", Flavour::Posix).kept);
}

#[test]
fn naming_links_one_at_a_time_costs_what_naming_them_at_once_does() {
    // A loop of `with_links([link])` builds nothing until a guard judges.
    let mut paths = posix();
    for at in 0..50_000 {
        paths = paths.with_links([Link::new(
            format!("/home/me/work/repo/l{at}"),
            format!("/data/{at}"),
        )]);
    }
    assert_eq!(paths.links.len(), 50_000);
    let once = many_links(50_000);
    assert_eq!(
        link_work(&paths, "l7/x", Flavour::Posix).work,
        link_work(&once, "l7/x", Flavour::Posix).work
    );
    assert_eq!(place(&paths, "l7/x"), place(&once, "l7/x"));
}

/// `l0` points to `l1`, which points to `l2`, and so on, and the last to
/// `~/.ssh`.
fn chain(count: usize) -> Paths {
    posix().with_links((0..count).map(|at| {
        let target = if at + 1 == count {
            "/home/me/.ssh".to_string()
        } else {
            format!("l{}", at + 1)
        };
        Link::new(format!("/home/me/work/repo/l{at}"), target)
    }))
}

#[test]
fn a_chain_is_followed_as_far_as_any_system_follows_and_no_further() {
    // Each link of the chain is one hop; the last lands on the keys.
    for count in [1, 10, HOPS] {
        assert_eq!(place(&chain(count), "l0/id_rsa"), KEY, "{count} links");
    }
    for count in [HOPS + 1, 500] {
        assert_eq!(
            place(&chain(count), "l0/id_rsa"),
            Place::Unknown,
            "{count} links"
        );
    }
    // The work of the longest chain followed: each hop reads the link and
    // its one-part target, and the path as it reads there, in two landings,
    // and each name a link of the chain lends the file once.
    let work = link_work(&chain(HOPS), "l0/id_rsa", Flavour::Posix);
    assert!(work.work <= 3 * (6 + HOPS * 8), "{work:?}");
}

#[test]
fn a_target_longer_than_any_system_keeps_is_not_followed() {
    // `/home/me/.ssh` with `/.` added up to the length, read as the folder.
    let at = |length: usize| {
        let base = "/home/me/.ssh";
        format!("{base}{}", "/.".repeat((length - base.len()) / 2))
    };
    let kept = at(TARGET);
    assert!(kept.len() <= TARGET);
    let paths = posix().with_links([Link::new("/home/me/work/repo/k", kept.as_str())]);
    assert_eq!(place(&paths, "k/id_rsa"), KEY);
    let long = format!("{kept}/./.");
    assert!(long.len() > TARGET);
    let paths = posix().with_links([Link::new("/home/me/work/repo/k", long.as_str())]);
    assert_eq!(place(&paths, "k/id_rsa"), Place::Unknown);
}

/// 100 links in `d`, each into a chain of 39 links whose targets are as
/// long as a link's can be: every pattern in `d` picks each of them. (With
/// ten times as many, building the tree alone would pass its own budget.)
fn costly() -> Paths {
    let long = vec!["t"; 600].join("/");
    let mut links: Vec<Link> = (0..39)
        .map(|at| {
            Link::new(
                format!("/home/me/work/repo/c{at}"),
                format!("{long}/../{}c{}", "../".repeat(599), at + 1),
            )
        })
        .collect();
    links.extend((0..100).map(|at| Link::new(format!("/home/me/work/repo/d/e{at}"), "../c0")));
    // The chain ends at a link that cannot be read, so each link of `d`
    // lands on a place a pattern through it must read.
    links.push(Link::unknown("/home/me/work/repo/c39"));
    posix().with_links(links)
}

#[test]
fn one_call_spends_no_more_than_its_budget() {
    let paths = costly();
    // One pattern alone runs out of the budget, and is then only known
    // when it runs.
    let work = link_work(&paths, "d/*/y", Flavour::Posix);
    assert!(work.work <= WORK, "{work:?}");
    assert!(work.work > WORK / 2, "{work:?}");
    assert_eq!(place(&paths, "d/*/y"), Place::Unknown);
    // Twenty of them in one call share one budget: what is past it is only
    // known when it runs, never safe.
    let twenty = vec!["d/*/y"; 20];
    let (each, places) = work_of_each(&paths, &twenty, Flavour::Posix);
    assert!(each.iter().sum::<usize>() <= WORK, "{each:?}");
    assert!(
        places.iter().all(|place| *place == Place::Unknown),
        "{places:?}"
    );
    // A plain path after the budget is spent is only known when it runs too.
    let (_, places) = work_of_each(&paths, &["d/*/y", "src/main.rs"], Flavour::Posix);
    assert_eq!(places[1], Place::Unknown);
}

#[test]
fn a_pattern_reads_each_link_it_can_pick_once() {
    for count in [1, 10, 100, 1_000] {
        let paths = many_links(count);
        // Every link is one the pattern can pick, and each is read once in
        // each of the two landings of the pattern's folder (one, here).
        let work = link_work(&paths, "*/x", Flavour::Posix);
        assert!(work.readings >= count, "{count} links: {work:?}");
        assert!(work.readings <= 2 * count + 4, "{count} links: {work:?}");
        assert_eq!(place(&paths, "*/x"), Place::Outside, "{count} links");
        // A pattern in a folder no link is below matches none.
        let work = link_work(&paths, "src/*/x", Flavour::Posix);
        assert!(work.readings <= 2, "{count} links: {work:?}");
    }
}

/// `l0/l1/l2/...`, `depth` links each named through the ones above it, the
/// last to `~/.ssh`, and the path through all of them to a key.
fn nested(depth: usize) -> (Vec<Link>, String) {
    let links: Vec<Link> = (1..=depth)
        .map(|at| {
            let path: Vec<String> = (0..at).map(|n| format!("l{n}")).collect();
            let target = if at == depth {
                "/home/me/.ssh".to_string()
            } else {
                format!("/data/{at}")
            };
            Link::new(format!("/home/me/work/repo/{}", path.join("/")), target)
        })
        .collect();
    let path: Vec<String> = (0..depth).map(|n| format!("l{n}")).collect();
    (links, format!("{}/id_rsa", path.join("/")))
}

#[test]
fn links_nested_deeper_than_the_rounds_are_lost_in_any_order() {
    // The first link is placed as named, and each round places one more
    // level of nesting: the link the last round places is kept, and one
    // still moving past it is lost.
    for depth in [ROUNDS + 1, ROUNDS + 2, ROUNDS + 5] {
        let (links, path) = nested(depth);
        let mut reversed = links.clone();
        reversed.reverse();
        let mut shuffled = links.clone();
        shuffled.rotate_left(depth / 2);
        let want = if depth <= ROUNDS + 1 {
            KEY
        } else {
            Place::Unknown
        };
        for list in [links, reversed, shuffled] {
            assert_eq!(
                place(&posix().with_links(list), &path),
                want,
                "{depth} deep"
            );
        }
    }
}

#[test]
fn a_build_past_its_budget_holds_no_link_in_any_order() {
    // A thousand links into the chain of long targets: placing where each
    // lands passes the build's budget, so no link is held and every path is
    // only known when it runs, in any order. A hundred fit.
    let long = vec!["t"; 600].join("/");
    let chain: Vec<Link> = (0..39)
        .map(|at| {
            Link::new(
                format!("/home/me/work/repo/c{at}"),
                format!("{long}/../{}c{}", "../".repeat(599), at + 1),
            )
        })
        .collect();
    for (count, want) in [(100, Place::Inside), (1_000, Place::Unknown)] {
        let mut links = chain.clone();
        links
            .extend((0..count).map(|at| Link::new(format!("/home/me/work/repo/d/e{at}"), "../c0")));
        let mut reversed = links.clone();
        reversed.reverse();
        for list in [links, reversed] {
            assert_eq!(
                place(&posix().with_links(list), "src/main.rs"),
                want,
                "{count}"
            );
        }
    }
}

#[test]
fn more_links_than_are_held_hold_none() {
    let paths = many_links(LINKS + 1);
    assert_eq!(place(&paths, "src/main.rs"), Place::Unknown);
    assert_eq!(place(&many_links(1_000), "src/main.rs"), Place::Inside);
}

#[test]
fn links_of_more_parts_than_are_held_hold_none() {
    // Links of 21 parts each: the four of `/home/me/work/repo`, a name of
    // 16 (its bytes count once for each 64, and once more), and a target
    // of one; then one in `/data` of four parts to `/`, which has none, to
    // make up the bound, and one of five to pass it. Past the bound no link
    // is held, in any order; at it, every one is.
    let name = format!("{:0>width$}", "", width = 15 * BYTES);
    let count = (PARTS - 4) / 21;
    assert_eq!(count * 21 + 4, PARTS);
    let links: Vec<Link> = (0..count)
        .map(|at| {
            Link::new(
                format!("/home/me/work/repo/{at:0>6}{name}"),
                format!("/d{at}"),
            )
        })
        .collect();
    for (last, want) in [
        ("/data/a/b/c", Place::Inside),
        ("/data/a/b/c/d", Place::Unknown),
    ] {
        let mut list = links.clone();
        list.push(Link::new(last, "/"));
        assert_eq!(
            place(&posix().with_links(list.clone()), "src/main.rs"),
            want,
            "{last}"
        );
        if want == Place::Unknown {
            list.reverse();
            assert_eq!(
                place(&posix().with_links(list), "src/main.rs"),
                want,
                "{last}"
            );
        }
    }
}

#[test]
fn a_long_honest_list_gives_the_same_answers_in_any_order() {
    // A package manager's tree of links (pnpm's): sixty thousand, each
    // folder's links into the store, one of them to a key's folder.
    let mut links: Vec<Link> = (0..60_000)
        .map(|at| {
            Link::new(
                format!(
                    "/home/me/work/repo/node_modules/p{}/node_modules/q{at}",
                    at % 600
                ),
                format!("../../.pnpm/q{at}@1.0.0/node_modules/q{at}"),
            )
        })
        .collect();
    links.push(Link::new(
        "/home/me/work/repo/node_modules/p7/node_modules/keys",
        "/home/me/.ssh",
    ));
    let mut reversed = links.clone();
    reversed.reverse();
    let forward = posix().with_links(links);
    let backward = posix().with_links(reversed);
    for path in [
        "node_modules/p7/node_modules/keys/id_rsa",
        "node_modules/p0/node_modules/q600/index.js",
        "node_modules/p0/node_modules/q600/../../../../../.ssh/id_rsa",
        "node_modules/*/node_modules/keys/id_rsa",
        "src/main.rs",
    ] {
        assert_eq!(place(&forward, path), place(&backward, path), "{path}");
    }
    assert_eq!(
        place(&forward, "node_modules/p7/node_modules/keys/id_rsa"),
        KEY
    );
    assert_eq!(place(&forward, "src/main.rs"), Place::Inside);
}

#[test]
fn links_below_links_are_placed_once_whatever_the_order() {
    // `l0/l1/l2/...`, each named through the ones above it, in both orders.
    for depth in [2, 8] {
        let links: Vec<Link> = (1..=depth)
            .map(|at| {
                let path: Vec<String> = (0..at).map(|n| format!("l{n}")).collect();
                let target = if at == depth {
                    "/home/me/.ssh".to_string()
                } else {
                    format!("/data/{at}")
                };
                Link::new(format!("/home/me/work/repo/{}", path.join("/")), target)
            })
            .collect();
        let mut reversed = links.clone();
        reversed.reverse();
        let path: Vec<String> = (0..depth).map(|n| format!("l{n}")).collect();
        let path = format!("{}/id_rsa", path.join("/"));
        let forward = place(&posix().with_links(links), &path);
        let backward = place(&posix().with_links(reversed), &path);
        assert_eq!(forward, KEY, "{depth} deep");
        assert_eq!(forward, backward, "{depth} deep");
    }
}

/// `l0` in the workspace lands in `/d/0`, where `l1` lands in `/d/1`, and so
/// on: what the last lands on (`~/.ssh`) is held by each folder above it,
/// one link more for each round of working out what folders hold.
fn holding_chain(count: usize) -> Paths {
    let mut links = vec![Link::new("/home/me/work/repo/l0", "/d/0")];
    links.extend((1..count).map(|at| {
        let target = if at + 1 == count {
            "/home/me/.ssh".to_string()
        } else {
            format!("/d/{at}")
        };
        Link::new(format!("/d/{}/l{at}", at - 1), target)
    }));
    posix().with_links(links)
}

#[test]
fn what_a_folder_holds_is_worked_out_in_so_many_rounds() {
    let holder =
        |paths: &Paths| Resolver::new(paths).linked_holder(Spelling::Plain("."), Flavour::Posix);
    // A chain a round can carry up to the workspace, link by link, holds
    // the key; one longer than the rounds holds a place only known when it
    // runs, never nothing.
    assert_eq!(holder(&holding_chain(ROUNDS)), Some("your SSH keys"));
    assert_eq!(
        holder(&holding_chain(ROUNDS + 3)),
        Some("a path only known when it runs")
    );
}
