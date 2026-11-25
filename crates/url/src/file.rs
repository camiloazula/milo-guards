//! A `file:` URL: the path it names, placed through core's resolver like any
//! other path.

use milo_guards_core::{Flavour, Paths, Place, Resolver, Sensitivity, Spelling};
use percent_encoding::percent_decode_str;
use url::Url;

/// Whether the machine `paths` describes is a Windows one: its home directory
/// starts with a drive (`C:`) or a share (`\\server`). The resolver decides
/// the same way, and this is what tells a `file:///C:/Users/me` path from a
/// POSIX one that happens to start with a folder called `C:`.
fn flavour(paths: &Paths) -> Flavour {
    let home = paths.home.to_string_lossy();
    let mut chars = home.chars();
    let drive = chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':');
    if drive || home.starts_with("\\\\") {
        Flavour::Windows
    } else {
        Flavour::Posix
    }
}

/// The path a `file:` URL names, as text the resolver reads: percent-escapes
/// undone (`%2e%2e` is `..`, `%2f` a separator, both read as what they
/// become), and on a Windows machine `/C:/x` is `C:/x`.
fn path_of(url: &Url, flavour: Flavour) -> String {
    let decoded = percent_decode_str(url.path()).decode_utf8_lossy();
    let mut path = decoded.into_owned();
    if flavour == Flavour::Windows {
        let b = path.as_bytes();
        if b.len() >= 3 && b[0] == b'/' && b[1].is_ascii_alphabetic() && matches!(b[2], b':' | b'|')
        {
            path.remove(0);
            path.replace_range(1..2, ":");
        }
    }
    path
}

/// The path as a prompt shows it: a control character is a mark, not a byte.
fn shown(path: String) -> String {
    path.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// The reason a `file:` URL is risky, and the path it is about.
///
/// A `file:` URL is always a finding, since a page fetch is not how a file is
/// meant to be read; where the path lands only sharpens the words. A `file:`
/// URL with a host names a file on another machine, which a Windows client
/// reaches over the network.
pub(crate) fn judge(url: &Url, paths: &Paths) -> (String, String) {
    let flavour = flavour(paths);
    let path = path_of(url, flavour);
    if url.host().is_some() {
        return ("reads a file from another machine".to_string(), shown(path));
    }
    // A control character cannot be placed: the name is not what it reads as.
    let words = if path.chars().any(char::is_control) {
        "a path only known when it runs"
    } else {
        let (place, words) = placed(&Resolver::new(paths), &path, flavour);
        // With a drive mount or a Windows home named, the path is also
        // placed as spelled, and the more telling words are kept: a key's,
        // then any other sensitive or protected place's, then any place's
        // that is not the agent's own.
        match paths.as_spelled() {
            Some(as_spelled) => {
                let (other, other_words) = placed(&Resolver::new(&as_spelled), &path, flavour);
                if telling(other) > telling(place) {
                    other_words
                } else {
                    words
                }
            }
            None => words,
        }
    };
    (format!("reads {words}"), shown(path))
}

/// How much a place's words tell: a key's most, then any other sensitive
/// or protected place's, then any place's that is not the agent's own.
fn telling(place: Place) -> u8 {
    match place {
        Place::Sensitive(_, Sensitivity::Secret) => 3,
        Place::Sensitive(..) | Place::Protected(_) => 2,
        place if !place.harmless() => 1,
        _ => 0,
    }
}

/// Where `path` lands on `resolver`, and the words a reason gives it: a
/// path the caller named both protected and secret is protected to the
/// resolver, and a fetch of it reads the secret.
fn placed(resolver: &Resolver, path: &str, flavour: Flavour) -> (Place, &'static str) {
    let spelled = Spelling::Plain(path);
    match resolver.place(spelled, flavour) {
        place @ Place::Protected(_) => match resolver.named_secret(spelled, flavour) {
            Some(words) => (Place::Sensitive(words, Sensitivity::Secret), words),
            None => (place, place.words()),
        },
        place => (place, place.words()),
    }
}
