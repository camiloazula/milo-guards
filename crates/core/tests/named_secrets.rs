//! The secrets a caller names (`Paths::secrets`): `place` answers each as a
//! key, in the caller's words, before the workspace it sits in, and a pattern
//! or a folder read whole reaches it as it does a key; `named_secret` gives
//! it where `place` answers a protected path. The cases are in
//! `tests/cases/named_secrets.cases`; what the API itself does is tested
//! here.

mod common;

use milo_guards_core::{Flavour, Paths, Place, Resolver, Secret, Sensitivity, Spelling};

#[test]
fn a_named_secret_is_read_as_a_key() {
    common::cases::check("named_secrets");
}

#[test]
fn secrets_are_added_by_each_call() {
    let paths = common::cases::posix();
    assert!(paths.secrets.is_empty());
    let paths = paths
        .with_secrets([Secret::file("/home/me/work/repo/.env", "one")])
        .with_secrets([Secret::folder("/home/me/.vault", "two")]);
    assert_eq!(
        paths.secrets,
        [
            Secret::file("/home/me/work/repo/.env", "one"),
            Secret::folder("/home/me/.vault", "two"),
        ]
    );
    let resolver = Resolver::new(&paths);
    let place = |path| resolver.place(Spelling::Plain(path), Flavour::Posix);
    assert_eq!(place(".env"), Place::Sensitive("one", Sensitivity::Secret));
    assert_eq!(
        place("/home/me/.vault/x"),
        Place::Sensitive("two", Sensitivity::Secret)
    );
}

/// A secret the caller names changes the answer only where a path can reach
/// it: every question about a path that cannot gets the answer it gets with
/// no secret named.
#[test]
fn a_named_secret_changes_only_what_can_reach_it() {
    let plain = Resolver::new(&common::cases::posix());
    let named = Resolver::new(&common::cases::posix().with_secrets([
        Secret::file("/home/me/work/repo/.env", "the project's environment file"),
        Secret::folder("/home/me/.vault", "your password vault"),
    ]));
    let flavour = Flavour::Posix;
    for path in [
        "src/main.rs",
        "*.rs",
        "src/*",
        ".envrc",
        ".env.example",
        "/home/me/.ssh/id_rsa",
        "/home/me/.s*/id_rsa",
        "/tmp/x",
        "/etc/shadow",
        "/home/me/.vaultx/x",
        "..",
    ] {
        let spelled = Spelling::Plain(path);
        assert_eq!(
            plain.place(spelled, flavour),
            named.place(spelled, flavour),
            "{path}"
        );
        assert_eq!(
            plain.place_into(spelled, flavour, true),
            named.place_into(spelled, flavour, true),
            "{path}"
        );
        assert_eq!(
            plain.picks_secret(spelled, flavour, true),
            named.picks_secret(spelled, flavour, true),
            "{path}"
        );
        assert_eq!(
            plain.reaches_secret(spelled, flavour, false, false),
            named.reaches_secret(spelled, flavour, false, false),
            "{path}"
        );
        assert_eq!(named.named_secret(spelled, flavour), None, "{path}");
    }
    // A path that can reach one does change.
    for path in [".env", ".e*", "/home/me/.vault/x", "/home/me/.va*t/x"] {
        let spelled = Spelling::Plain(path);
        assert_ne!(
            plain.reaches_secret(spelled, flavour, false, false),
            named.reaches_secret(spelled, flavour, false, false),
            "{path}"
        );
    }
}

/// After a `cd` the guard cannot follow, a relative name may be a named
/// secret wherever the folder is: one that spells its last names, or a
/// pattern that can pick them, and below a named folder.
#[test]
fn a_name_from_an_unknown_folder_is_matched_by_the_named_paths_last_names() {
    let paths = common::cases::posix().with_secrets([
        Secret::file("/home/me/work/repo/deploy/token.json", "the deploy token"),
        Secret::folder("/home/me/work/repo/keys", "the project's keys"),
        Secret::file("/home/me/work/repo/.env", "the project's environment file"),
    ]);
    let resolver = Resolver::new(&paths);
    let named =
        |rest, hidden| resolver.named_secret_in_unknown_folder(rest, Flavour::Posix, hidden);
    assert_eq!(named("token.json", false), Some("the deploy token"));
    assert_eq!(named("deploy/token.json", false), Some("the deploy token"));
    assert_eq!(
        named("./deploy/TOKEN.json", false),
        Some("the deploy token")
    );
    assert_eq!(named("deploy/tok*", false), Some("the deploy token"));
    assert_eq!(named("keys", false), Some("the project's keys"));
    assert_eq!(named("keys/signing.pem", false), Some("the project's keys"));
    assert_eq!(named("keys/*", false), Some("the project's keys"));
    assert_eq!(named(".env", false), Some("the project's environment file"));
    assert_eq!(named(".e*", false), Some("the project's environment file"));
    // A pattern of nothing but wildcards may be any of them.
    assert_eq!(named("*", false), Some("the deploy token"));
    assert_eq!(named("*.pem", false), None);
    // A name that does not spell a named path's own last name, a file with
    // something below it, and what has a root or a `~`, are not; a `..` is
    // applied, and one above the first name climbs to another such folder.
    assert_eq!(named("signing.pem", false), None);
    assert_eq!(named("token.json/x", false), None);
    assert_eq!(named("other/token.json", false), None);
    assert_eq!(named("/home/me/work/repo/.env", false), None);
    assert_eq!(named("~/.env", false), None);
    assert_eq!(
        named("../.env", false),
        Some("the project's environment file")
    );
    assert_eq!(
        named("src/../.env", false),
        Some("the project's environment file")
    );
    assert_eq!(named("..", false), None);
    assert_eq!(named("", false), None);
    // With none named, none.
    let plain = Resolver::new(&common::cases::posix());
    assert_eq!(
        plain.named_secret_in_unknown_folder(".env", Flavour::Posix, false),
        None
    );
    // On Windows names compare without case, the dots and spaces a name
    // ends in are dropped, and either separator is one.
    let windows = common::cases::windows().with_secrets([Secret::file(
        r"C:\Users\me\dev\repo\deploy\token.json",
        "the deploy token",
    )]);
    let resolver = Resolver::new(&windows);
    let named = |rest| resolver.named_secret_in_unknown_folder(rest, Flavour::Windows, false);
    assert_eq!(named(r"DEPLOY\token.json."), Some("the deploy token"));
    assert_eq!(named("deploy/token.json"), Some("the deploy token"));
    assert_eq!(named(r"C:\x\token.json"), None);
}

/// A plain name in a workspace that holds a secret the caller named may be
/// that secret, so the working directory is not clear; a secret outside the
/// workspace leaves it clear.
#[test]
fn a_workspace_holding_a_named_secret_is_not_clear() {
    let held = |secret: Secret| {
        Resolver::new(&Paths::with_secrets(common::cases::posix(), [secret])).cwd_is_clear()
    };
    assert!(!held(Secret::file("/home/me/work/repo/.env", "x")));
    assert!(!held(Secret::folder("/home/me/work/repo/sub/keys", "x")));
    assert!(!held(Secret::folder("/home/me/work", "x")));
    assert!(held(Secret::folder("/home/me/.vault", "x")));
    assert!(held(Secret::file("/home/me/work/other/.env", "x")));
}
