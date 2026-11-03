//! The unpackers other than `tar`, `unzip`, `7z` and `Expand-Archive`, read
//! for the folder they fill: `cpio -i` (`-D`) and `cpio -p`, `ditto -x`,
//! `pax -r` and `pax -rw`, `unrar x` and `rar x`, `unar -o`, `jar x`
//! (`-C`), and Python's `zipfile` and `tarfile` modules (`python -m
//! zipfile -e`). Each gives the folders as written, with `.` for the
//! working directory, which the caller judges as the destination of `cp`.

use super::{long_option, readable, unknown_long, Unpack};
use crate::path::within;
use crate::unit::{could_be, may_split, unknown_start, Arg};
use crate::Shell;

/// Where the unpacker `key` writes, or `None` when it is not one or its
/// arguments ask for no write (a listing, a test, an archive it makes).
pub(super) fn unpack(key: &str, args: &[Arg], shell: Shell) -> Option<Unpack> {
    match key {
        "cpio" | "gcpio" | "bsdcpio" => cpio(args, shell),
        "ditto" => ditto(args),
        "pax" => pax(args),
        // WinRAR.exe takes the commands and switches of `rar`.
        "unrar" | "rar" | "winrar" => rar(args),
        "unar" => unar(args, shell),
        "jar" => jar(args),
        _ if key == "py" || key.starts_with("python") => {
            let (module, args) = python_module(args)?;
            match module {
                "zipfile" => zipfile(args),
                "tarfile" => tarfile(args),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The working directory, as a folder.
fn here() -> Arg {
    Arg::Known(".".to_string())
}

/// An unpack that copies files into `folders` rather than out of an
/// archive.
fn copies(folders: Vec<Arg>) -> Unpack {
    Unpack {
        verb: "copies into",
        ..Unpack::filling(folders)
    }
}

/// What `cpio` is asked to do. Copy-in (`-i`, `--extract`) unpacks into the
/// folder `-D` (`--directory`) names, or the working directory; listing
/// (`-t`), writing to the screen (`--to-stdout`) and checking
/// (`--only-verify-crc`) write nothing. Pass-through (`-p`) copies the files
/// its input names into the folder of its first operand, under the one `-D`
/// names. Copy-out (`-o`) writes an archive. A mode only known when it runs
/// may be copy-in. `--absolute-filenames` (GNU) and `--insecure` (bsdcpio)
/// keep the stored paths as they are.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is one thing an argument of cpio may say, read in any order"
)]
#[derive(Default)]
struct Cpio {
    extract: bool,
    pass: bool,
    other_mode: bool,
    writes_nothing: bool,
    absolute: bool,
    unknown: bool,
    folders: Vec<Arg>,
    operands: Vec<Arg>,
}

impl Cpio {
    /// The long option `name`, with its value attached with `=` if any;
    /// GNU cpio takes a unique prefix, and the modes and the options that
    /// write nothing are read only from a prefix no other option starts
    /// with.
    fn long<'a>(
        &mut self,
        name: &str,
        attached: Option<Arg>,
        iter: &mut impl Iterator<Item = &'a Arg>,
    ) {
        const VALUES: [&str; 11] = [
            "file",
            "format",
            "pattern-file",
            "message",
            "owner",
            "io-size",
            "block-size",
            "rsh-command",
            "rename-batch-file",
            "passphrase",
            "warning",
        ];
        let mut value = |attached: Option<Arg>| attached.or_else(|| iter.next().cloned());
        if long_option(name, "extract", 2) {
            self.extract = true;
        } else if long_option(name, "pass-through", 3) {
            self.pass = true;
        } else if long_option(name, "create", 2) || long_option(name, "list", 3) {
            self.other_mode = true;
        } else if long_option(name, "to-stdout", 2) || long_option(name, "only-verify-crc", 2) {
            self.writes_nothing = true;
        } else if long_option(name, "absolute-filenames", 2) || long_option(name, "insecure", 3) {
            self.absolute = true;
        } else if long_option(name, "directory", 2) {
            self.folders.extend(value(attached));
        } else if attached.is_none() && VALUES.iter().any(|full| long_option(name, full, 3)) {
            value(None);
        }
    }

    /// A bundle of one-letter options (`-idm`, `-iD dir`, `-iDdir`).
    fn short<'a>(&mut self, letters: &str, iter: &mut impl Iterator<Item = &'a Arg>) {
        // The letters that take a value, which ends the bundle.
        const VALUES: &str = "CDEFHIMORW";
        for (at, letter) in letters.char_indices() {
            if VALUES.contains(letter) {
                let rest = &letters[at + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                if letter == 'D' {
                    self.folders.extend(value);
                }
                return;
            }
            match letter {
                'i' => self.extract = true,
                'p' => self.pass = true,
                'o' | 't' => self.other_mode = true,
                _ => {}
            }
        }
    }
}

fn cpio(args: &[Arg], shell: Shell) -> Option<Unpack> {
    let mut read = Cpio::default();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            if let Some((name, value)) = unknown_long(arg) {
                read.long(name, Some(value), &mut iter);
            } else {
                read.unknown |= arg.is_unknown();
                read.operands.push(arg.clone());
            }
            continue;
        };
        if text == "--" {
            read.operands.extend(iter.by_ref().cloned());
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
                None => (long, None),
            };
            read.long(name, attached, &mut iter);
        } else if let Some(letters) = text.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            read.short(letters, &mut iter);
        } else {
            read.operands.push(arg.clone());
        }
    }
    if read.pass && !read.extract && !read.other_mode {
        // GNU cpio moves to `-D` first, so the folder is under it.
        let target = read.operands.first()?;
        let folders = if read.folders.is_empty() {
            vec![target.clone()]
        } else {
            read.folders
                .iter()
                .map(|folder| within(Some(folder), target, shell))
                .collect()
        };
        return Some(copies(folders));
    }
    let mode_unknown = read.unknown && !read.extract && !read.pass && !read.other_mode;
    if !(read.extract || mode_unknown) || read.other_mode || read.writes_nothing {
        return None;
    }
    if read.folders.is_empty() {
        read.folders.push(here());
    }
    Some(Unpack::filling(read.folders).absolute(read.absolute))
}

/// The folder `ditto -x` unpacks into: its last operand, after the archives.
/// `ditto` with neither `-x` nor `-c` copies its sources into the last
/// operand, which is judged as the destination of `cp`. `ditto -c` makes an
/// archive, which this rule does not read; a mode only known when it runs
/// may be `-x`.
fn ditto(args: &[Arg]) -> Option<Unpack> {
    const VALUES: [&str; 3] = ["--arch", "--bom", "--zlibCompressionLevel"];
    let mut extract = false;
    let mut create = false;
    let mut unknown = false;
    let mut operands = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            operands.push(arg);
            continue;
        };
        if text == "--" {
            operands.extend(iter.by_ref());
            break;
        }
        if VALUES.contains(&text) {
            iter.next();
        } else if let Some(letters) = text.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            // A long option (`--keepParent`) holds no mode.
            if !letters.starts_with('-') {
                extract |= letters.contains('x');
                create |= letters.contains('c');
            }
        } else {
            operands.push(arg);
        }
    }
    if create || operands.len() < 2 {
        return None;
    }
    let folder = vec![(*operands.last()?).clone()];
    Some(if extract || unknown {
        Unpack::filling(folder)
    } else {
        copies(folder)
    })
}

/// What `pax` is asked to do: `-r` unpacks into the working directory,
/// `-r -w` copies its operands into the folder of the last one, `-w` alone
/// makes an archive and neither lists. `-s` renames each path by a rule the
/// archive's names meet only when it runs, so they land anywhere. A mode
/// only known when it runs may be `-r`, or `-rw`.
fn pax(args: &[Arg]) -> Option<Unpack> {
    // The letters that take a value, which ends the bundle.
    const VALUES: &str = "bfopsxBEGTU";
    let mut reads = false;
    let mut writes = false;
    let mut renames = false;
    let mut unknown = false;
    let mut operands = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            operands.push(arg);
            continue;
        };
        if text == "--" {
            operands.extend(iter.by_ref());
            break;
        }
        let Some(letters) = text.strip_prefix('-').filter(|rest| !rest.is_empty()) else {
            operands.push(arg);
            continue;
        };
        for (at, letter) in letters.char_indices() {
            if VALUES.contains(letter) {
                if at + letter.len_utf8() == letters.len() {
                    iter.next();
                }
                renames |= letter == 's';
                break;
            }
            reads |= letter == 'r';
            writes |= letter == 'w';
        }
    }
    let mode_unknown = unknown && !reads && !writes;
    let mut folders = Vec::new();
    if (reads && !writes) || mode_unknown {
        folders.push(here());
    }
    if (reads && writes) || (mode_unknown && operands.len() >= 2) {
        folders.extend(operands.last().map(|folder| (*folder).clone()));
    }
    if folders.is_empty() {
        return None;
    }
    let mut unpack = if reads && writes {
        copies(folders)
    } else {
        Unpack::filling(folders)
    };
    if renames {
        unpack.anywhere = Some(if reads && writes {
            "copies to paths only known when it runs"
        } else {
            "unpacks to paths only known when it runs"
        });
    }
    Some(unpack)
}

/// The folders `unrar`, `rar` and `WinRAR.exe` unpack into with `x` and `e`: an operand
/// after the archive's name that ends with a separator is the folder, and
/// any other may be one that exists, which the line does not show, so each
/// is a folder; with none that ends with a separator, and no `-op`, the
/// working directory too. `-op<path>` names it as well, and `-ep3` restores
/// the full paths stored in the archive. Switches are single words, not
/// case-sensitive, anywhere before `--`; a command only known when it runs
/// may be `x`, and a switch only known when it runs may be `-op`.
fn rar(args: &[Arg]) -> Option<Unpack> {
    let mut positional: Vec<&Arg> = Vec::new();
    let mut folders = Vec::new();
    let mut absolute = false;
    let mut options_done = false;
    for arg in args {
        let start = readable(arg);
        if options_done || !start.starts_with('-') || start.len() < 2 {
            positional.push(arg);
            continue;
        }
        let Some(text) = arg.known() else {
            let lower = start.to_ascii_lowercase();
            let letter = lower[1..].chars().next();
            if letter.is_none_or(|c| !c.is_ascii_alphabetic())
                || lower == "-o"
                || lower.starts_with("-op")
            {
                folders.push(Arg::Unknown(arg.text().to_string()));
            }
            continue;
        };
        let lower = text.to_ascii_lowercase();
        if lower == "--" {
            options_done = true;
        } else if lower == "-ep3" {
            absolute = true;
        } else if lower.starts_with("-op") {
            folders.push(Arg::Known(text[3..].to_string()));
        }
    }
    let (command, rest) = positional.split_first()?;
    let extracts = command
        .known()
        .is_none_or(|command| matches!(command.to_ascii_lowercase().as_str(), "x" | "e"));
    if !extracts {
        return None;
    }
    let named = !folders.is_empty();
    let mut separator = false;
    for operand in rest.iter().skip(1) {
        match operand.known() {
            Some(text) if text.starts_with('@') => {}
            Some(text) => {
                separator |= text.ends_with(['/', '\\']);
                folders.push((*operand).clone());
            }
            None => folders.push((*operand).clone()),
        }
    }
    if !named && !separator {
        folders.push(here());
    }
    Some(Unpack::filling(folders).absolute(absolute))
}

/// The folder `unar` unpacks into: `-o` (`-output-directory`), or the
/// working directory; `-o -` writes to the screen. Its options take one
/// dash or two. A word only known when it runs that may be `-o` takes the
/// word after it as the folder (`unar "$o" ~ a.zip`), and one that may split
/// into words (`unar $OPTS a.zip`) may hold `-o` and a folder only known
/// when it runs.
fn unar(args: &[Arg], shell: Shell) -> Option<Unpack> {
    const VALUES: [&str; 8] = [
        "p",
        "password",
        "e",
        "encoding",
        "E",
        "password-encoding",
        "k",
        "forks",
    ];
    let mut folders = Vec::new();
    let mut maybe = Vec::new();
    let mut to_screen = false;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            if may_split(arg, shell) {
                maybe.push(Arg::Unknown(arg.text().to_string()));
            } else if unknown_start(arg, shell).is_none_or(|start| {
                (start.is_empty() || start.starts_with('-'))
                    && could_be(&start, Some('o'), Some("output-directory"))
            }) {
                maybe.extend(
                    iter.peek()
                        .filter(|next| !next.known().is_some_and(|t| t.starts_with('-')))
                        .map(|next| (*next).clone()),
                );
            }
            continue;
        };
        if text == "--" {
            break;
        }
        let Some(name) = text
            .strip_prefix("--")
            .or_else(|| text.strip_prefix('-'))
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if matches!(name, "o" | "output-directory") {
            match iter.next() {
                Some(folder) if folder.known() == Some("-") => to_screen = true,
                Some(folder) => folders.push(folder.clone()),
                None => {}
            }
        } else if VALUES.contains(&name) {
            iter.next();
        }
    }
    if folders.is_empty() && !to_screen {
        folders.push(here());
    }
    folders.extend(maybe);
    if folders.is_empty() {
        return None;
    }
    Some(Unpack::filling(folders))
}

/// What `jar` is asked to do. `x` (`-x`, `--extract`) unpacks into the
/// working directory, and into the folder `-C` (`--dir`) names, which a JDK
/// from 21 on unpacks into instead; `P` keeps the stored paths as they are.
/// The first argument may be a bundle without a dash (`jar xf a.jar`), and
/// its letters that take a value (`f`, `m`, `e`) take the arguments after
/// it, in order. A mode only known when it runs may be `x`.
fn jar(args: &[Arg]) -> Option<Unpack> {
    const LONG_VALUES: [&str; 9] = [
        "--file",
        "--manifest",
        "--main-class",
        "--module-version",
        "--hash-modules",
        "--module-path",
        "--release",
        "--date",
        "--generate-index",
    ];
    let mut extract = false;
    let mut other_mode = false;
    let mut absolute = false;
    let mut unknown = false;
    let mut folders = vec![here()];
    let mut iter = args.iter().enumerate();
    while let Some((at, arg)) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            continue;
        };
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
                None => (long, None),
            };
            match name {
                "extract" => extract = true,
                "create" | "list" | "update" | "describe-module" | "validate" => {
                    other_mode = true;
                }
                "generate-index" => {
                    other_mode = true;
                    if attached.is_none() {
                        iter.next();
                    }
                }
                "dir" => folders.extend(attached.or_else(|| iter.next().map(|(_, v)| v.clone()))),
                _ if attached.is_none() && LONG_VALUES.contains(&text) => {
                    iter.next();
                }
                _ => {}
            }
            continue;
        }
        if text == "-C" {
            folders.extend(iter.next().map(|(_, folder)| folder.clone()));
            continue;
        }
        let old_style = at == 0 && !text.starts_with('-');
        let Some(letters) = text
            .strip_prefix('-')
            .or(old_style.then_some(text))
            .filter(|letters| !letters.is_empty())
        else {
            continue;
        };
        for letter in letters.chars() {
            match letter {
                'x' => extract = true,
                'c' | 't' | 'u' | 'i' | 'd' => other_mode = true,
                'P' => absolute = true,
                // The value of each comes in the arguments after the bundle.
                'f' | 'm' | 'e' | 'p' => {
                    iter.next();
                }
                _ => {}
            }
        }
    }
    let mode_unknown = unknown && !extract && !other_mode;
    if !(extract || mode_unknown) || other_mode {
        return None;
    }
    Some(Unpack::filling(folders).absolute(absolute))
}

/// The module `python -m` runs and the arguments it is given, when the
/// interpreter's own options come before it (`python3 -I -m zipfile`,
/// `-mzipfile`); `None` for code (`-c`), a script or the input. An option
/// only known when it runs is passed over.
fn python_module(args: &[Arg]) -> Option<(&str, &[Arg])> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        let Some(text) = arg.known() else { continue };
        if text == "--check-hash-based-pycs" {
            at += 1;
            continue;
        }
        if text.starts_with("--") {
            if text == "--" {
                return None;
            }
            continue;
        }
        let letters = text.strip_prefix('-').filter(|rest| !rest.is_empty())?;
        for (position, letter) in letters.char_indices() {
            let rest = &letters[position + letter.len_utf8()..];
            match letter {
                'c' => return None,
                'm' if !rest.is_empty() => return Some((rest, &args[at..])),
                'm' => return Some((args.get(at)?.known()?, args.get(at + 1..)?)),
                'W' | 'X' | 'Q' => {
                    at += usize::from(rest.is_empty());
                    break;
                }
                _ => {}
            }
        }
    }
    None
}

/// The folder `python -m zipfile -e ARCHIVE FOLDER` (`--extract`) unpacks
/// into. `-l`, `-c` and `-t` write no folder; argparse takes a unique
/// prefix of a long option. A mode only known when it runs may be `-e`,
/// into a folder only known then.
fn zipfile(args: &[Arg]) -> Option<Unpack> {
    let mut unknown = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            continue;
        };
        if text == "-e"
            || text
                .strip_prefix("--")
                .is_some_and(|name| long_option(name, "extract", 1))
        {
            iter.next()?;
            return Some(Unpack::filling(vec![iter.next()?.clone()]));
        }
        if matches!(text, "-l" | "-c" | "-t")
            || ["list", "create", "test"].iter().any(|mode| {
                text.strip_prefix("--")
                    .is_some_and(|name| long_option(name, mode, 1))
            })
        {
            return None;
        }
        if text
            .strip_prefix("--")
            .is_some_and(|name| long_option(name, "metadata-encoding", 1))
        {
            iter.next();
        }
    }
    unknown.then(|| Unpack::filling(vec![Arg::Unknown("<a folder>".to_string())]))
}

/// The folder `python -m tarfile -e ARCHIVE [FOLDER]` (`--extract`) unpacks
/// into: the one named, or the working directory. A value attached to the
/// option (`--extract=a.tar`, `-ea.tar`) is the archive, and argparse then
/// takes no other, so it unpacks into the working directory. `--filter
/// fully_trusted` keeps the stored paths as they are, and so may a filter
/// only known when it runs. `-l`, `-c` and `-t` write no folder. Short
/// options may be bundled (`-ve a.tar`). A mode only known when it runs may
/// be `-e`.
fn tarfile(args: &[Arg]) -> Option<Unpack> {
    let long = |text: &str, full: &str| {
        text.strip_prefix("--")
            .is_some_and(|name| long_option(name.split('=').next().unwrap_or(name), full, 1))
    };
    let mut unknown = false;
    let mut absolute = false;
    let mut values: Option<Vec<Arg>> = None;
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            continue;
        };
        // What follows `-e` or `--extract`: `None` for a word that is
        // neither, a value attached to it, or nothing.
        let extract = if long(text, "extract") {
            Some(text.split_once('=').map(|(_, value)| value))
        } else if text.starts_with("--") {
            None
        } else if let Some(letters) = text.strip_prefix('-') {
            let mut found = None;
            for (at, letter) in letters.char_indices() {
                match letter {
                    'e' => {
                        let rest = &letters[at + 1..];
                        found = Some((!rest.is_empty()).then_some(rest));
                        break;
                    }
                    'l' | 'c' | 't' => return None,
                    'v' => {}
                    _ => break,
                }
            }
            found
        } else {
            None
        };
        if let Some(attached) = extract {
            values = Some(if let Some(archive) = attached {
                vec![Arg::Known(archive.to_string())]
            } else {
                // Every word up to the next option: the archive and the folder.
                let mut taken = Vec::new();
                while let Some(next) =
                    iter.next_if(|next| !next.known().is_some_and(|t| t.starts_with('-')))
                {
                    taken.push(next.clone());
                }
                taken
            });
        } else if ["list", "create", "test"]
            .iter()
            .any(|mode| long(text, mode))
        {
            return None;
        } else if long(text, "filter") {
            let filter = match text.split_once('=') {
                Some((_, value)) => Some(Arg::Known(value.to_string())),
                None => iter.next().cloned(),
            };
            absolute |= filter.is_none_or(|filter| {
                filter
                    .known()
                    .is_none_or(|filter| long_option(filter, "fully_trusted", 1))
            });
        }
    }
    let folders = match values.as_deref() {
        Some([_]) => vec![here()],
        Some([_, folder]) => vec![folder.clone()],
        Some(_) => return None,
        None if unknown => vec![Arg::Unknown("<a folder>".to_string())],
        None => return None,
    };
    Some(Unpack::filling(folders).absolute(absolute))
}
