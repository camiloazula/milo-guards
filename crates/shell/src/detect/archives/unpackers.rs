//! The archivers other than `tar`, `zip`, `unzip`, `7z`, `Expand-Archive`
//! and `Compress-Archive`, read for the folder they fill: `cpio -i` (`-D`)
//! and `cpio -p`, `ditto -x`, `pax -r` and `pax -rw`, `unrar x` and `rar
//! x`, `unar -o`, `jar x` (`-C`), `aunpack -X`, and Python's `zipfile` and
//! `tarfile` modules (`python -m zipfile -e`); and for the archive they
//! write: `cpio -o -F`, `pax -w -f`, `rar a`, `jar cf`, `ditto -c`,
//! `apack` and `python -m zipfile -c`. Each gives the folders as written,
//! with `.` for the working directory, which the caller judges as the
//! destination of `cp`, and the archives as written, judged as any file
//! written.

use super::{long_option, rar_written, readable, unknown_long, Archiving, Unpack, ABSOLUTE};
use crate::launch::{is_python, options, own_args};
use crate::path::within;
use crate::unit::{could_be, may_split, unknown_start, Arg};
use crate::Shell;

/// Where the archiver `key` writes: the folder it unpacks into, if it
/// does, and the archives it writes.
pub(super) fn archiving(key: &str, args: &[Arg], shell: Shell) -> Archiving {
    match key {
        "cpio" | "gcpio" | "bsdcpio" => cpio(args, shell, key),
        "ditto" => ditto(args),
        "pax" => pax(args),
        "unrar" => Archiving::unpacking(rar(args)),
        // WinRAR.exe takes the commands and switches of `rar`.
        "rar" | "winrar" => {
            let (written, may_write) = rar_written(args);
            Archiving {
                unpack: rar(args),
                written,
                may_write,
                ..Archiving::default()
            }
        }
        "unar" => Archiving::unpacking(unar(args, shell)),
        "jar" => jar(args),
        "aunpack" | "atool" | "apack" => atool(key, args, shell),
        // Any Python of the interpreter table, past its own options.
        _ if is_python(key) => {
            let args = own_args(key, args);
            let Some((module, start)) = options(key, args).module else {
                return Archiving::default();
            };
            let args = args.get(start..).unwrap_or_default();
            match module.known() {
                Some("zipfile") => python_module(args, zipfile),
                Some("tarfile") => python_module(args, tarfile),
                _ => Archiving::default(),
            }
        }
        _ => Archiving::default(),
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
/// names. Copy-out (`-o`) writes the archive `-F` or `-O` (`--file`) names,
/// or its output. A mode only known when it runs may be copy-in, or
/// copy-out. GNU cpio keeps an absolute path stored in the archive unless
/// told not to (`--no-absolute-filenames`), and `--absolute-filenames`
/// (GNU) and `--insecure` (bsdcpio) keep the stored paths as they are.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is one thing an argument of cpio may say, read in any order"
)]
#[derive(Default)]
struct Cpio {
    extract: bool,
    pass: bool,
    create: bool,
    other_mode: bool,
    writes_nothing: bool,
    absolute: bool,
    relative: bool,
    unknown: bool,
    folders: Vec<Arg>,
    archives: Vec<Arg>,
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
        const VALUES: [&str; 10] = [
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
        } else if long_option(name, "create", 2) {
            self.create = true;
            self.other_mode = true;
        } else if long_option(name, "list", 3) {
            self.other_mode = true;
        } else if long_option(name, "to-stdout", 2) || long_option(name, "only-verify-crc", 2) {
            self.writes_nothing = true;
        } else if long_option(name, "absolute-filenames", 2) || long_option(name, "insecure", 3) {
            self.absolute = true;
        } else if long_option(name, "no-absolute-filenames", 4) {
            self.relative = true;
        } else if long_option(name, "file", 2) {
            self.archives.extend(value(attached));
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
                match letter {
                    'D' => self.folders.extend(value),
                    'F' | 'O' => self.archives.extend(value),
                    _ => {}
                }
                return;
            }
            match letter {
                'i' => self.extract = true,
                'p' => self.pass = true,
                'o' => {
                    self.create = true;
                    self.other_mode = true;
                }
                't' => self.other_mode = true,
                _ => {}
            }
        }
    }
}

fn cpio(args: &[Arg], shell: Shell, key: &str) -> Archiving {
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
        let Some(target) = read.operands.first() else {
            return Archiving::default();
        };
        let folders = if read.folders.is_empty() {
            vec![target.clone()]
        } else {
            read.folders
                .iter()
                .map(|folder| within(Some(folder), target, shell))
                .collect()
        };
        return Archiving::unpacking(Some(copies(folders)));
    }
    let mode_unknown = read.unknown && !read.extract && !read.pass && !read.other_mode;
    // Copy-out writes the archive `-F` or `-O` names; `-F` is the archive
    // read in the other modes.
    let written = if read.create || mode_unknown {
        std::mem::take(&mut read.archives)
    } else {
        Vec::new()
    };
    let may_write = mode_unknown && !read.create;
    if !(read.extract || mode_unknown) || read.other_mode || read.writes_nothing {
        return Archiving {
            written,
            may_write,
            ..Archiving::default()
        };
    }
    if read.folders.is_empty() {
        read.folders.push(here());
    }
    // GNU cpio (`cpio` may be it) restores a stored absolute path as it is,
    // unless `--no-absolute-filenames` says not to; bsdcpio strips it.
    let stored = key != "bsdcpio" && !read.relative;
    Archiving {
        unpack: Some(Unpack::filling(read.folders).absolute(read.absolute || stored)),
        written,
        may_write,
        ..Archiving::default()
    }
}

/// The folder `ditto -x` unpacks into: its last operand, after the archives.
/// `ditto` with neither `-x` nor `-c` copies its sources into the last
/// operand, which is judged as the destination of `cp`. `ditto -c` writes
/// the archive its last operand names; a mode only known when it runs may
/// be `-x`.
fn ditto(args: &[Arg]) -> Archiving {
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
    let last = match operands.as_slice() {
        [_, .., last] => (*last).clone(),
        _ => return Archiving::default(),
    };
    if create {
        return Archiving::writing(vec![last]);
    }
    let folder = vec![last];
    Archiving::unpacking(Some(if extract || unknown {
        Unpack::filling(folder)
    } else {
        copies(folder)
    }))
}

/// What `pax` is asked to do: `-r` unpacks into the working directory, and
/// restores a stored absolute path as it is; `-r -w` copies its operands
/// into the folder of the last one, `-w` alone writes the archive `-f`
/// names (or its output) and neither lists. `-s` renames each path by a
/// rule the archive's names meet only when it runs, so they land anywhere.
/// A mode only known when it runs may be `-r`, `-rw` or `-w`.
fn pax(args: &[Arg]) -> Archiving {
    // The letters that take a value, which ends the bundle.
    const VALUES: &str = "bfopsxBEGTU";
    let mut reads = false;
    let mut writes = false;
    let mut renames = false;
    let mut unknown = false;
    let mut operands = Vec::new();
    let mut archives = Vec::new();
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
                let rest = &letters[at + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                if letter == 'f' {
                    archives.extend(value);
                }
                renames |= letter == 's';
                break;
            }
            reads |= letter == 'r';
            writes |= letter == 'w';
        }
    }
    let mode_unknown = unknown && !reads && !writes;
    let written = if (writes && !reads) || mode_unknown {
        archives
    } else {
        Vec::new()
    };
    let may_write = mode_unknown;
    let mut folders = Vec::new();
    if (reads && !writes) || mode_unknown {
        folders.push(here());
    }
    if (reads && writes) || (mode_unknown && operands.len() >= 2) {
        folders.extend(operands.last().map(|folder| (*folder).clone()));
    }
    if folders.is_empty() {
        return Archiving::writing(written);
    }
    let copy = reads && writes;
    let mut unpack = if copy {
        copies(folders)
    } else {
        Unpack::filling(folders)
    };
    if renames {
        unpack.anywhere = Some(if copy {
            "copies to paths only known when it runs"
        } else {
            "unpacks to paths only known when it runs"
        });
    } else if !copy {
        // `pax -r` restores a stored absolute path as it is.
        unpack.anywhere = Some(ABSOLUTE);
    }
    Archiving {
        unpack: Some(unpack),
        written,
        may_write,
        ..Archiving::default()
    }
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

/// What atool is asked to do. `aunpack` (`atool -x`, `--extract`) unpacks
/// into the folder `-X` (`--extract-to`) names, or the working directory;
/// `apack` (`atool -a`, `--add`) writes the archive its first operand
/// names; `--save-outdir` writes the file it names; `-S` (`--simulate`)
/// writes nothing. A word only known when it runs may be a mode of
/// `atool`, and one that may be `-X` names a folder only known when it runs.
/// atool reads its options with Perl's `Getopt::Long`, which takes any
/// unique prefix of a long name (`--extract-t`, `--ad`, `--sav`): the
/// options that make it write are read from a prefix, and those that make
/// it write less (`--simulate`, `--list`) only from the whole name.
fn atool(key: &str, args: &[Arg], shell: Shell) -> Archiving {
    // The letters that take a value, which ends the bundle.
    const VALUES: &str = "XFOoV";
    const LONG_VALUES: [&str; 5] = ["format", "format-option", "option", "config", "verbosity"];
    let mut extract = key == "aunpack";
    let mut add = key == "apack";
    let mut other_mode = false;
    let mut simulate = false;
    let mut unknown = false;
    let mut folders = Vec::new();
    let mut maybe = Vec::new();
    let mut written = Vec::new();
    let mut operands = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            let start = unknown_start(arg, shell);
            let option = start.as_deref().is_some_and(|start| start.starts_with('-'));
            if may_split(arg, shell) {
                maybe.push(Arg::Unknown(arg.text().to_string()));
            } else if start
                .as_deref()
                .is_none_or(|start| option && could_be(start, Some('X'), Some("extract-to")))
            {
                // It may be `-X`, which takes the word after it.
                maybe.extend(
                    iter.peek()
                        .filter(|next| !next.known().is_some_and(|t| t.starts_with('-')))
                        .map(|next| (*next).clone()),
                );
            }
            if !option {
                operands.push(arg.clone());
            }
            continue;
        };
        if text == "--" {
            operands.extend(iter.by_ref().cloned());
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
                None => (long, None),
            };
            let mut value = || attached.clone().or_else(|| iter.next().cloned());
            // `--extract-` and longer is `--extract-to`; a shorter prefix is
            // `--extract`, or one Getopt::Long refuses as ambiguous.
            if long_option(name, "extract-to", "extract-".len()) {
                extract = true;
                folders.extend(value());
            } else if long_option(name, "extract", 1) {
                extract = true;
            } else if long_option(name, "add", 1) {
                add = true;
            } else if long_option(name, "save-outdir", 2) {
                written.extend(value());
            } else if matches!(name, "list" | "cat" | "diff" | "repack") {
                other_mode = true;
            } else if name == "simulate" {
                simulate = true;
            } else if attached.is_none() && LONG_VALUES.contains(&name) {
                value();
            }
            continue;
        }
        let Some(letters) = text.strip_prefix('-').filter(|rest| !rest.is_empty()) else {
            operands.push(arg.clone());
            continue;
        };
        for (at, letter) in letters.char_indices() {
            if VALUES.contains(letter) {
                let rest = &letters[at + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                if letter == 'X' {
                    extract = true;
                    folders.extend(value);
                }
                break;
            }
            match letter {
                'x' => extract = true,
                'a' => add = true,
                'l' | 'c' | 'd' | 'r' => other_mode = true,
                'S' => simulate = true,
                _ => {}
            }
        }
    }
    if simulate {
        return Archiving::default();
    }
    // `atool` with no mode read but a word only known when it runs may
    // unpack, or add.
    let mode_unknown = key == "atool" && unknown && !extract && !add && !other_mode;
    if add || mode_unknown {
        written.extend(operands.first().cloned());
    }
    let unpack = (extract || mode_unknown).then(|| {
        if folders.is_empty() {
            folders.push(here());
        }
        folders.extend(maybe);
        Unpack::filling(folders)
    });
    Archiving {
        unpack,
        written,
        may_write: mode_unknown,
        may_unpack: mode_unknown,
        ..Archiving::default()
    }
}

/// What `jar` is asked to do. `x` (`-x`, `--extract`) unpacks into the
/// working directory, and into the folder `-C` (`--dir`) names, which a JDK
/// from 21 on unpacks into instead; `P` keeps the stored paths as they are.
/// `c` and `u` (`--create`, `--update`) write the archive `f` (`--file`)
/// names, or its output. The first argument may be a bundle without a dash
/// (`jar xf a.jar`), and its letters that take a value (`f`, `m`, `e`) take
/// the arguments after it, in order. A mode only known when it runs may be
/// `x`, or `c`. An argument that starts with `@` names a file of more
/// arguments, which the line does not show.
fn jar(args: &[Arg]) -> Archiving {
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
    let mut writes = false;
    let mut absolute = false;
    let mut unknown = false;
    let mut folders = vec![here()];
    let mut archives = Vec::new();
    let unread = args.iter().any(|arg| readable(arg).starts_with('@'));
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
                "create" | "update" => {
                    other_mode = true;
                    writes = true;
                }
                "list" | "describe-module" | "validate" => other_mode = true,
                "generate-index" => {
                    other_mode = true;
                    if attached.is_none() {
                        iter.next();
                    }
                }
                "dir" => folders.extend(attached.or_else(|| iter.next().map(|(_, v)| v.clone()))),
                "file" => {
                    archives.extend(attached.or_else(|| iter.next().map(|(_, v)| v.clone())));
                }
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
                'c' | 'u' => {
                    other_mode = true;
                    writes = true;
                }
                't' | 'i' | 'd' => other_mode = true,
                'P' => absolute = true,
                // The value of each comes in the arguments after the bundle.
                'f' => archives.extend(iter.next().map(|(_, archive)| archive.clone())),
                'm' | 'e' | 'p' => {
                    iter.next();
                }
                _ => {}
            }
        }
    }
    let mode_unknown = unknown && !extract && !other_mode;
    let written = if writes || mode_unknown {
        archives
    } else {
        Vec::new()
    };
    let unpack = ((extract || mode_unknown) && !other_mode)
        .then(|| Unpack::filling(folders).absolute(absolute));
    Archiving {
        unpack,
        written,
        unread,
        may_write: mode_unknown && !writes,
        ..Archiving::default()
    }
}

/// What the arguments of `python -m zipfile` or `python -m tarfile` ask
/// for, read as `argparse` reads them: a long option may be a unique prefix
/// (`--ext`), a single-dash word is a bundle of letters (`-ve` is `-v -e`),
/// and the rest of the word after `-e` is the archive (`-ea.tar`).
struct ModuleArgs {
    /// What `-e` or `--extract` is given: the archive attached to it
    /// (`--extract=a.tar`, `-ea.tar`), if any, then every word up to the
    /// next option. `None` without `-e`.
    extract: Option<(bool, Vec<Arg>)>,
    /// Whether a word only known when it runs stands where `-e` may be.
    unknown: bool,
    /// Whether `--filter` (tarfile) is `fully_trusted`, which keeps the
    /// stored paths as they are, or a filter only known when it runs.
    trusted: bool,
    /// Whether `--filter` is given at all: without one, `tarfile` before
    /// Python 3.14 keeps a stored absolute path.
    filtered: bool,
}

/// What `python -m zipfile` or `python -m tarfile` writes: the folder
/// `unpack` reads from the module's arguments, or the archive `-c`
/// (`--create`) makes, the word after it (or attached to it).
fn python_module(args: &[Arg], unpack: fn(ModuleArgs) -> Option<Unpack>) -> Archiving {
    match module_args(args) {
        Ok(read) => Archiving::unpacking(unpack(read)),
        Err(created) => Archiving::writing(created),
    }
}

/// Read the module's arguments; for a listing, a test or an archive it
/// makes (`-l`, `-t`, `-c`, `--list`, `--test`, `--create`), the archive it
/// writes, if any.
fn module_args(args: &[Arg]) -> Result<ModuleArgs, Vec<Arg>> {
    let long = |text: &str, full: &str| {
        text.strip_prefix("--")
            .is_some_and(|name| long_option(name.split('=').next().unwrap_or(name), full, 1))
    };
    // The archive `-c` makes: the rest of its word, or the next one.
    let created = |rest: Option<&str>, next: Option<&Arg>| -> Vec<Arg> {
        match rest.filter(|rest| !rest.is_empty()) {
            Some(rest) => vec![Arg::Known(rest.to_string())],
            None => next.cloned().into_iter().collect(),
        }
    };
    let mut read = ModuleArgs {
        extract: None,
        unknown: false,
        trusted: false,
        filtered: false,
    };
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            read.unknown |= arg.is_unknown();
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
                    'c' => return Err(created(Some(&letters[at + 1..]), iter.next())),
                    'l' | 't' => return Err(Vec::new()),
                    'v' => {}
                    _ => break,
                }
            }
            found
        } else {
            None
        };
        if let Some(attached) = extract {
            let mut values: Vec<Arg> = attached
                .map(|archive| Arg::Known(archive.to_string()))
                .into_iter()
                .collect();
            // Every word up to the next option. After an attached archive
            // `argparse` refuses one, but it is read all the same.
            while let Some(next) =
                iter.next_if(|next| !next.known().is_some_and(|t| t.starts_with('-')))
            {
                values.push(next.clone());
            }
            read.extract = Some((attached.is_some(), values));
        } else if long(text, "create") {
            return Err(created(
                text.split_once('=').map(|(_, value)| value),
                iter.next(),
            ));
        } else if ["list", "test"].iter().any(|mode| long(text, mode)) {
            return Err(Vec::new());
        } else if long(text, "filter") {
            read.filtered = true;
            let filter = match text.split_once('=') {
                Some((_, value)) => Some(Arg::Known(value.to_string())),
                None => iter.next().cloned(),
            };
            read.trusted |= filter.is_none_or(|filter| {
                filter
                    .known()
                    .is_none_or(|filter| long_option(filter, "fully_trusted", 1))
            });
        } else if long(text, "metadata-encoding") && !text.contains('=') {
            iter.next();
        }
    }
    Ok(read)
}

/// The folder `python -m zipfile -e ARCHIVE FOLDER` (`--extract`) unpacks
/// into: every word after the archive. A mode only known when it runs may
/// be `-e`, into a folder only known then.
fn zipfile(read: ModuleArgs) -> Option<Unpack> {
    match read.extract {
        Some((_, values)) => {
            let folders = values.get(1..).unwrap_or_default().to_vec();
            (!folders.is_empty()).then(|| Unpack::filling(folders))
        }
        None => read
            .unknown
            .then(|| Unpack::filling(vec![Arg::Unknown("<a folder>".to_string())])),
    }
}

/// The folder `python -m tarfile -e ARCHIVE [FOLDER]` (`--extract`) unpacks
/// into: the one named, or the working directory. A value attached to the
/// option (`--extract=a.tar`, `-ea.tar`) is the archive, and argparse then
/// takes no other, so it unpacks into the working directory; a word after
/// it is judged too. `--filter fully_trusted` keeps the stored paths as
/// they are, and so may a filter only known when it runs; with no
/// `--filter`, a Python before 3.14 keeps a stored absolute path. A mode
/// only known when it runs may be `-e`.
fn tarfile(read: ModuleArgs) -> Option<Unpack> {
    let folders = match read.extract {
        Some((true, values)) => {
            let mut folders = vec![here()];
            folders.extend(values.into_iter().skip(1));
            folders
        }
        Some((false, values)) => match values.as_slice() {
            [] => return None,
            [_] => vec![here()],
            [_, folders @ ..] => folders.to_vec(),
        },
        None if read.unknown => vec![Arg::Unknown("<a folder>".to_string())],
        None => return None,
    };
    Some(Unpack::filling(folders).absolute(read.trusted || !read.filtered))
}
