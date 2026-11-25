//! The links the caller has resolved (`Paths::links`), in every shell: a
//! path through one is judged where it lands, by every rule that places a
//! path, and a pattern that can pick one is read through it. The cases are
//! in `tests/cases/resolved_links.cases`.

mod common;

#[test]
fn every_case_holds() {
    common::cases::check("resolved_links");
}

use milo_guards_shell::{classify, effect, Effect, Link, Paths, Reach, Rule, Shell};

fn repo() -> Paths {
    Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"])
}

/// A pattern over a package manager's links into its store: each lands in
/// the workspace on nothing serious, so the pattern reads none of them
/// again, and however many there are it is the workspace's to read.
#[test]
fn a_pattern_over_many_harmless_links_reads_the_workspace() {
    for count in [3_000, 30_000] {
        let paths = repo().with_links((0..count).map(|at| {
            Link::new(
                format!("/home/me/work/repo/node_modules/pkg{at}"),
                format!(".pnpm/pkg{at}@1.0.0/node_modules/pkg{at}"),
            )
        }));
        let line = ["node_modules/*/package.json"; 12].join(" ");
        let line = format!("cat {line}");
        assert_eq!(
            effect(&line, Shell::Posix, &paths),
            Effect::ReadsOnly(Reach::Workspace),
            "{count} links"
        );
        assert!(
            classify(&line, Shell::Posix, &paths).is_safe(),
            "{count} links"
        );
    }
}

/// A read whose walk through the links passes the work a line may spend is
/// of a place only known when it runs: its effect is unknown, never a
/// place beyond the workspace.
#[test]
fn a_read_past_the_budget_is_unknown() {
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
    links.push(Link::unknown("/home/me/work/repo/c39"));
    let paths = repo().with_links(links);
    assert_eq!(effect("cat d/*/y", Shell::Posix, &paths), Effect::Unknown);
    assert!(classify("cat d/*/y", Shell::Posix, &paths)
        .findings()
        .iter()
        .any(|finding| finding.rule == Rule::Unknown));
}
