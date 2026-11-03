//! The rules about archives. One unpacked into a folder is a write into that
//! folder, judged like the destination of `cp`; with no folder given it
//! unpacks into the working directory, and the paths stored in the archive
//! cannot be seen from the line and are not read, unless `tar -P` keeps them
//! absolute. One packed with an option that removes what it packs (`tar
//! --remove-files`, `zip -m`, `7z a -sdel`, `rar m`) deletes the members
//! named on the line, judged like the operands of `rm`. The commands `tar`
//! and `zip` run through a shell ([`commands`]) are read as lines of their
//! own when the line is split.

use super::Checker;
use crate::launch::{is_python, options, own_args};
use crate::path::within;
use crate::powershell::Params;
use crate::unit::{could_be, may_be_option, may_split, option_start, Arg, Flagged, Unit};
use crate::{Rule, Shell};

impl Checker<'_> {
    /// `tar -x`, `unzip`, `7z x`, `Expand-Archive`.
    pub(super) fn unpack(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let folders = match key {
            "tar" | "gtar" | "bsdtar" => {
                let tar = tar(args, unit.shell, key);
                // `-P` keeps the leading `/` and the `..` of the paths
                // stored in the archive: they land wherever those say.
                if tar.unpacks && tar.absolute {
                    self.add(
                        Rule::Overwrite,
                        "unpacks to absolute paths only known when it runs",
                        None,
                    );
                }
                tar.unpacks_into()
            }
            "unzip" => unzip(args),
            "7z" | "7za" | "7zr" | "7zz" => seven_zip(args),
            "expand-archive" => Some(expand_archive(args)),
            key if is_python(key) => python_unpack(key, args),
            _ => None,
        };
        for folder in folders.unwrap_or_default() {
            self.write_folder(unit.shell, unit.scope(), &folder, "unpacks into");
        }
    }

    /// `tar -c --remove-files`, `zip -m`, `7z a -sdel`, `rar m`: the program
    /// deletes each file it packs once it has packed it.
    pub(super) fn pack_and_remove(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let ((members, unread), matched) = match key {
            "tar" | "gtar" | "bsdtar" => (tar(args, unit.shell, key).removed(), false),
            "zip" => (zip(args, unit.shell).removed(), true),
            "7z" | "7za" | "7zr" | "7zz" => (seven_zip_removes(args, unit.shell), true),
            "rar" => ((rar_removes(args), false), true),
            _ => return,
        };
        let before = self.found.len();
        // `7z` and `rar` match a wildcard themselves, quoted or not, and so
        // does `zip` on Windows; `zip` on Unix does so only for `-x`, `-i`,
        // `-R` and names inside the archive, so `zip -m x.zip 'a*'` there
        // deletes nothing. A line cannot show which shell's expansion a name
        // went through, so every member is judged with names that start with
        // a dot among the matches: a cautious choice, not how `zip` behaves
        // on Unix.
        self.delete_matching(
            unit,
            &members.iter().collect::<Vec<_>>(),
            "deletes",
            matched,
        );
        // Only an argument that may be the option removes them.
        if unread {
            self.hedge(before);
        }
    }
}

/// The commands the archiver `key` runs through a shell, as its arguments
/// give them: `tar --to-command`, `-I` and `--use-compress-program`,
/// `--checkpoint-action=exec=`, `-F`, `--info-script`,
/// `--new-volume-script` and `--rsh-command`, and `zip -TT`
/// (`--unzip-command`). One only known when it runs comes as it is. With
/// them, whether `tar` changes folder (`-C`) before it may run one: a
/// filter or a checkpoint's command runs from where the `-C` before it left
/// `tar`.
pub(crate) fn commands(key: &str, args: &[Arg], shell: Shell) -> (Vec<Arg>, bool) {
    match key {
        "tar" | "gtar" | "bsdtar" => {
            let tar = tar(args, shell, key);
            let moves = !tar.folders.is_empty();
            (tar.commands, moves)
        }
        "zip" => (zip(args, shell).commands, false),
        _ => (Vec::new(), false),
    }
}

/// Whether `name`, a long option as written, is `full` or a prefix of it of
/// at least `least` letters: GNU tar and bsdtar take a unique prefix.
fn long_option(name: &str, full: &str, least: usize) -> bool {
    name.len() >= least && full.starts_with(name)
}

/// What a `tar` line does, as far as its arguments show.
struct Tar {
    /// Whether it extracts to the disk: `-x`, `--extract`, `--get` and no
    /// other mode and no `-O`; or a mode only known when it runs that no mode
    /// letter rules out.
    unpacks: bool,
    /// Whether `--remove-files` is given to a mode that makes or adds to an
    /// archive (`-c`, `-r`, `-u`), or to one only known when it runs that
    /// no mode letter rules out: `Unread` when only an argument only known
    /// when it runs may be `--remove-files` (`$OPTS`, `"--$X"`).
    removes: Flagged,
    /// Whether `-P` (`--absolute-names`) keeps the paths stored in the
    /// archive as they are, absolute and with their `..`.
    absolute: bool,
    /// The folders `-C`, `--directory` and `--one-top-level` name, in order.
    folders: Vec<Arg>,
    /// The files and folders it is asked to pack, each as seen from where
    /// the line runs (a member after `-C dir` is under `dir`). The value of
    /// an option that may split into words when it runs (`-f $A`) is one
    /// too: a word after the first is a member.
    members: Vec<Arg>,
    /// The commands it runs through a shell (see [`commands`]).
    commands: Vec<Arg>,
}

impl Tar {
    /// The folders `tar` unpacks into: `-C dir` (`-Cdir`, `--directory dir`,
    /// `--directory=dir`, wherever it stands), or the working directory.
    fn unpacks_into(mut self) -> Option<Vec<Arg>> {
        if !self.unpacks {
            return None;
        }
        if self.folders.is_empty() {
            self.folders.push(Arg::Known(".".to_string()));
        }
        Some(self.folders)
    }

    /// The members `--remove-files` deletes after packing them, and
    /// whether only an argument that may be it does.
    fn removed(self) -> (Vec<Arg>, bool) {
        match self.removes {
            Flagged::Absent => (Vec::new(), false),
            Flagged::Unread => (self.members, true),
            Flagged::Written => (self.members, false),
        }
    }
}

/// The long options of `tar` that take a value, which stands in the next
/// argument when it is not attached with `=`. The ones that name members
/// are read apart, and the one-letter forms are in [`tar`].
const TAR_LONG_VALUES: &[&str] = &[
    "after-date",
    "blocking-factor",
    "checkpoint-action",
    "exclude",
    "exclude-from",
    "exclude-ignore",
    "exclude-ignore-recursive",
    "exclude-tag",
    "exclude-tag-all",
    "exclude-tag-under",
    "file",
    "format",
    "group",
    "group-map",
    "hole-detection",
    "index-file",
    "info-script",
    "label",
    "level",
    "listed-incremental",
    "mode",
    "mtime",
    "new-volume-script",
    "newer",
    "newer-mtime",
    "owner",
    "owner-map",
    "pax-option",
    "quote-chars",
    "quoting-style",
    "record-size",
    "rmt-command",
    "rsh-command",
    "sort",
    "sparse-version",
    "starting-file",
    "strip-components",
    "suffix",
    "tape-length",
    "to-command",
    "transform",
    "use-compress-program",
    "volno-file",
    "warning",
    "xattrs-exclude",
    "xattrs-include",
    "xform",
    "include",
    "options",
    "newer-than",
    "newer-mtime-than",
    "gid",
    "gname",
    "uid",
    "uname",
    "passphrase",
];

/// Long options of `tar` that take none, and that a name could stand for as
/// well as for one that takes a value (`--sparse`, `--checkpoint[=N]`,
/// `--xattrs`; `--inc` is `--incremental` in GNU tar and `--include` in
/// bsdtar; `--mod` is `--mode` in GNU tar, which takes a value, and the only
/// prefix of `--modification-time` in bsdtar, which takes none). A name that
/// may be one of them is read as the flag, which takes no argument: the next
/// one is then a member, the riskier reading.
const TAR_LONG_FLAGS: [&str; 5] = [
    "sparse",
    "checkpoint",
    "xattrs",
    "incremental",
    "modification-time",
];

/// The longest folder, in bytes, that a chain of `-C` is followed to. Each
/// `-C` is joined to the one before it, so a longer chain is a path only
/// known when it runs; that bounds the cost of reading a long line of them.
const TAR_FOLDER_LIMIT: usize = 512;

/// Where `-C folder` moves the members that follow, from where `under` had
/// moved them.
fn moved(under: Option<&Arg>, folder: &Arg, shell: Shell) -> Arg {
    match within(under, folder, shell) {
        Arg::Known(text) if text.len() > TAR_FOLDER_LIMIT => Arg::Unknown(text),
        folder => folder,
    }
}

/// The value of an option, taken as a member when it may split into words
/// when it runs (see [`may_split`]): `-f $A`, with `A='x.tar /etc'`, packs
/// `/etc`. Whether it was.
fn split_member(value: &Arg, under: Option<&Arg>, shell: Shell, members: &mut Vec<Arg>) -> bool {
    let splits = may_split(value, shell);
    if splits {
        members.push(within(under, value, shell));
    }
    splits
}

/// What `tar` is asked to do. A mode that only the line's run shows (`tar
/// "$mode" -f x.tar`) counts as extracting, and as packing. `key` is the
/// program's name: `-I` is a command to GNU tar and a list of members to
/// bsdtar, and `tar` may be either.
fn tar(args: &[Arg], shell: Shell, key: &str) -> Tar {
    let mut read = TarRead {
        shell,
        key,
        extract: false,
        other_mode: false,
        pack: false,
        to_stdout: false,
        removes_files: false,
        absolute: false,
        unknown: false,
        folders: Vec::new(),
        under: None,
        members: Vec::new(),
        commands: Vec::new(),
    };
    let mut iter = args.iter().enumerate();
    while let Some((at, arg)) = iter.next() {
        let Some(text) = arg.known() else {
            // `--file="$OUT"`: an option whose value is only known when it
            // runs is that option, not a member, and not the mode.
            // Its value may still split into words (`--file=$A`), a member
            // among them.
            if let Some((name, value)) = unknown_long(arg) {
                read.split(&value);
                read.long(name, Some(value), &mut iter);
                continue;
            }
            read.unknown |= arg.is_unknown();
            // One that starts as an option (`"--$X"`) is no member, unless
            // it may split into words (`-cf$A`).
            if option_start(arg, shell).is_none() || may_split(arg, shell) {
                read.members.push(within(read.under.as_ref(), arg, shell));
            }
            continue;
        };
        if text == "--" {
            let under = read.under.clone();
            read.members.extend(
                iter.by_ref()
                    .map(|(_, arg)| within(under.as_ref(), arg, shell)),
            );
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
                None => (long, None),
            };
            read.long(name, attached, &mut iter);
            continue;
        }
        // The first argument may be a bundle without a dash: `tar xzf x.tgz`,
        // whose valued letters take the arguments after it, in order.
        let old_style = at == 0 && !text.starts_with('-');
        if !old_style && !text.starts_with('-') {
            read.members.push(within(read.under.as_ref(), arg, shell));
            continue;
        }
        let letters = text.strip_prefix('-').unwrap_or(text);
        if !old_style && letters.is_empty() {
            continue;
        }
        read.short(letters, old_style, &mut iter);
    }
    // With no mode read, an argument that is only known when it runs may be
    // `-x`, or `-c`.
    let mode_unknown = read.unknown && !read.other_mode && !read.extract;
    let removes = if read.pack || mode_unknown {
        Flagged::of(
            read.removes_files,
            may_be_option(args, shell, |start| {
                could_be(start, None, Some("remove-files"))
            }),
        )
    } else {
        Flagged::Absent
    };
    Tar {
        unpacks: (read.extract || mode_unknown) && !read.other_mode && !read.to_stdout,
        removes,
        absolute: read.absolute,
        folders: read.folders,
        members: read.members,
        commands: read.commands,
    }
}

/// The state of [`tar`] while it reads the arguments.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is one thing an argument of tar may say, read in any order"
)]
struct TarRead<'a> {
    shell: Shell,
    key: &'a str,
    extract: bool,
    other_mode: bool,
    pack: bool,
    to_stdout: bool,
    removes_files: bool,
    absolute: bool,
    /// An argument only known when it runs, which may hold the mode.
    unknown: bool,
    folders: Vec<Arg>,
    /// Where `-C` moved the members that follow: relative to the line's own
    /// folder, and to the `-C` before it.
    under: Option<Arg>,
    members: Vec<Arg>,
    commands: Vec<Arg>,
}

/// The modes of `tar` that pack or unpack, each with the fewest letters of
/// a prefix no other long option of GNU tar or bsdtar starts with (`--ex`
/// may be `--exclude`), and whether it extracts.
const TAR_MODES: [(&str, usize, bool); 5] = [
    ("create", 2, false),
    ("append", 2, false),
    ("update", 2, false),
    ("extract", 3, true),
    ("get", 2, true),
];

/// The long options of `tar` whose value is a command it runs through a
/// shell: a filter for each member, a compressor, a script at the end of a
/// volume, and the remote shell for an archive on another machine.
const TAR_COMMANDS: [&str; 5] = [
    "to-command",
    "use-compress-program",
    "info-script",
    "new-volume-script",
    "rsh-command",
];

impl TarRead<'_> {
    /// The value of an option, taken as a member when it may split into
    /// words when it runs (see [`split_member`]), which may then hold the
    /// mode.
    fn split(&mut self, value: &Arg) {
        self.unknown |= split_member(value, self.under.as_ref(), self.shell, &mut self.members);
    }

    /// The long option `name`, with the value attached with `=` if any;
    /// one that takes a value and has none attached takes the next argument.
    fn long<'b>(
        &mut self,
        name: &str,
        attached: Option<Arg>,
        iter: &mut impl Iterator<Item = (usize, &'b Arg)>,
    ) {
        // Each option may be written as a prefix of it, of at least three
        // letters (`--ext`, `--dir`), as the programs take the unique one.
        let is = |full: &str| long_option(name, full, 3);
        // A name that may be a flag (`--checkpoint`) takes no value of its
        // own: the next argument is then a member, the riskier reading.
        let flag = TAR_LONG_FLAGS.iter().any(|flag| is(flag));
        let mut value = |attached: Option<Arg>| match attached {
            Some(value) => Some(value),
            None => iter.next().map(|(_, value)| value.clone()),
        };
        if let Some((_, _, extracts)) = TAR_MODES
            .iter()
            .find(|(full, least, _)| long_option(name, full, *least))
        {
            if *extracts {
                self.extract = true;
            } else {
                self.other_mode = true;
                self.pack = true;
            }
        } else if ["list", "diff", "compare", "delete"]
            .iter()
            .any(|mode| is(mode))
        {
            self.other_mode = true;
        } else if long_option(name, "to-stdout", 4) {
            self.to_stdout = true;
        } else if is("remove-files") {
            self.removes_files = true;
        } else if is("absolute-names") || is("absolute-paths") {
            self.absolute = true;
        } else if long_option(name, "one-top-level", 7) {
            self.folders.extend(attached);
        } else if is("directory") {
            if let Some(folder) = value(attached) {
                self.split(&folder);
                self.under = Some(moved(self.under.as_ref(), &folder, self.shell));
                self.folders.push(folder);
            }
        } else if is("add-file") {
            // A member, named as the value of the option.
            if let Some(member) = value(attached) {
                self.members
                    .push(within(self.under.as_ref(), &member, self.shell));
            }
        } else if long_option(name, "files-from", 5) {
            // The members are in a file the line does not show.
            if let Some(list) = value(attached) {
                self.split(&list);
            }
            self.members.push(from_list());
        } else if (attached.is_some() || !flag) && TAR_COMMANDS.iter().any(|full| is(full)) {
            if let Some(command) = value(attached) {
                self.split(&command);
                self.commands.push(command);
            }
        } else if (attached.is_some() || !flag) && is("checkpoint-action") {
            if let Some(action) = value(attached) {
                self.split(&action);
                self.commands.extend(checkpoint_command(&action));
            }
        } else if attached.is_none() && !flag && TAR_LONG_VALUES.iter().any(|full| is(full)) {
            if let Some((_, value)) = iter.next() {
                self.split(value);
            }
        }
    }

    /// A bundle of one-letter options; `old_style` when it is the first
    /// argument, written without a dash, whose valued letters take the
    /// arguments after it in order.
    fn short<'b>(
        &mut self,
        letters: &str,
        old_style: bool,
        iter: &mut impl Iterator<Item = (usize, &'b Arg)>,
    ) {
        // Short options that take a value, whose bundle ends with it.
        const VALUES: &str = "CfbILKNTXFgHV";
        for (position, letter) in letters.char_indices() {
            if VALUES.contains(letter) {
                let rest = &letters[position + letter.len_utf8()..];
                let value = if !old_style && !rest.is_empty() {
                    Some(Arg::Known(rest.to_string()))
                } else {
                    iter.next().map(|(_, value)| value.clone())
                };
                if let Some(value) = &value {
                    self.split(value);
                }
                match (letter, value) {
                    ('C', Some(folder)) => {
                        self.under = Some(moved(self.under.as_ref(), &folder, self.shell));
                        self.folders.push(folder);
                    }
                    // The members are in a file the line does not show.
                    ('T', _) => self.members.push(from_list()),
                    // A compressor to GNU tar, the file of members to
                    // bsdtar; `tar` may be either, unless the value names a
                    // compressor (`-I zstd`, `-I 'xz -9'`).
                    ('I', value) => {
                        let compressor = value.as_ref().is_some_and(names_compressor);
                        if self.key != "gtar" && !compressor {
                            self.members.push(from_list());
                        }
                        if self.key != "bsdtar" {
                            self.commands.extend(value);
                        }
                    }
                    // The script GNU tar runs at the end of each volume.
                    ('F', value) => self.commands.extend(value),
                    _ => {}
                }
                if !old_style {
                    break;
                }
                continue;
            }
            match letter {
                'x' => self.extract = true,
                'c' | 'r' | 'u' => {
                    self.other_mode = true;
                    self.pack = true;
                }
                't' | 'A' | 'd' => self.other_mode = true,
                'O' => self.to_stdout = true,
                'P' => self.absolute = true,
                _ => {}
            }
        }
    }
}

/// Whether `value`, given to `tar -I`, is a command that runs a compressor
/// (`zstd`, `xz -9`, `/usr/bin/pigz`): GNU tar's reading, and not a file of
/// members bsdtar would read.
fn names_compressor(value: &Arg) -> bool {
    const COMPRESSORS: [&str; 18] = [
        "brotli", "bzip2", "bzip3", "compress", "gzip", "lbzip2", "lrzip", "lz4", "lzip", "lzma",
        "lzop", "pbzip2", "pigz", "pixz", "plzip", "xz", "zstd", "pzstd",
    ];
    let Some(text) = value.known() else {
        return false;
    };
    let program = text.split_whitespace().next().unwrap_or_default();
    let name = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    COMPRESSORS.contains(&name)
}

/// Members read from a list the line does not show.
fn from_list() -> Arg {
    Arg::Unknown("<files from a list>".to_string())
}

/// An argument only known when it runs that starts as a long option with
/// a value (`--file="$OUT"`), with its name and its value.
fn unknown_long(arg: &Arg) -> Option<(&str, Arg)> {
    let (name, _) = readable(arg).strip_prefix("--")?.split_once('=')?;
    let plain = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    // The value as written, for the reason.
    let value = arg
        .text()
        .split_once('=')
        .map_or(arg.text(), |(_, value)| value);
    plain.then(|| (name, Arg::Unknown(value.to_string())))
}

/// The command `--checkpoint-action` runs: the one after `exec=`. A value
/// only known when it runs may be one, unless it starts with the name of
/// an action that runs nothing.
fn checkpoint_command(value: &Arg) -> Option<Arg> {
    const HARMLESS: [&str; 8] = [
        "bell", "dot", ".", "echo", "sleep", "totals", "ttyout", "wait",
    ];
    if let Some(text) = value.known() {
        return text
            .strip_prefix("exec=")
            .map(|command| Arg::Known(command.to_string()));
    }
    let start = readable(value).trim_start_matches(['"', '\'']);
    let harmless = HARMLESS.iter().any(|action| {
        start
            .strip_prefix(action)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('='))
    });
    (!harmless).then(|| Arg::Unknown(value.text().to_string()))
}

/// The folder `python -m zipfile -e ARCHIVE FOLDER` and `python -m tarfile
/// -e ARCHIVE [FOLDER]` unpack into (`--extract`, and any prefix of it
/// `argparse` takes); `tarfile` unpacks into the working directory when it
/// names none. Any other module, or a line without `-e`, unpacks nothing.
fn python_unpack(key: &str, args: &[Arg]) -> Option<Vec<Arg>> {
    let args = own_args(key, args);
    let read = options(key, args);
    let (module, start) = read.module?;
    let module = module.known()?;
    if module != "zipfile" && module != "tarfile" {
        return None;
    }
    let mut words = args.get(start..)?.iter().skip_while(|arg| {
        !arg.known()
            .is_some_and(|text| text == "-e" || (text.len() >= 3 && "--extract".starts_with(text)))
    });
    words.next()?;
    let operands: Vec<&Arg> = words
        .filter(|arg| !arg.known().is_some_and(|text| text.starts_with('-')))
        .collect();
    match (module, operands.get(1)) {
        (_, Some(folder)) => Some(vec![(*folder).clone()]),
        ("tarfile", None) => Some(vec![Arg::Known(".".to_string())]),
        _ => None,
    }
}

/// The folder `unzip` unpacks into: `-d dir` (`-ddir`, in a bundle such as
/// `-od dir`), or the working directory. Listing, testing and unpacking to
/// the screen write nothing.
fn unzip(args: &[Arg]) -> Option<Vec<Arg>> {
    let mut folders = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let Some(letters) = text.strip_prefix('-').filter(|letters| !letters.is_empty()) else {
            continue;
        };
        for (at, letter) in letters.char_indices() {
            match letter {
                'd' | 'P' => {
                    let rest = &letters[at + 1..];
                    let value = if rest.is_empty() {
                        iter.next().cloned()
                    } else {
                        Some(Arg::Known(rest.to_string()))
                    };
                    if letter == 'd' {
                        folders.extend(value);
                    }
                    break;
                }
                'l' | 'v' | 't' | 'Z' | 'p' | 'c' | 'z' => return None,
                _ => {}
            }
        }
    }
    if folders.is_empty() {
        folders.push(Arg::Known(".".to_string()));
    }
    Some(folders)
}

/// The folders `7z x` and `7z e` unpack into: `-oDIR`, or the working
/// directory.
fn seven_zip(args: &[Arg]) -> Option<Vec<Arg>> {
    let command = args.iter().find_map(|arg| {
        arg.known()
            .filter(|text| !text.starts_with('-'))
            .map(str::to_ascii_lowercase)
    })?;
    if !matches!(command.as_str(), "x" | "e") {
        return None;
    }
    let mut folders = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (text, known) = match arg {
            Arg::Known(text) => (text.as_str(), true),
            Arg::Unknown(_) | Arg::Template { .. } => (arg.text(), false),
            Arg::Input | Arg::Null => continue,
        };
        // Switches are not case-sensitive; `-ao` is another switch.
        let Some(folder) = text
            .get(..2)
            .filter(|prefix| prefix.eq_ignore_ascii_case("-o"))
            .map(|_| &text[2..])
            .filter(|folder| !folder.is_empty())
        else {
            continue;
        };
        // PowerShell reads `-oC:\Windows` as `-oC:` and `\Windows`; the
        // program may get either, so the folder is the two together.
        let folder = match iter.clone().next() {
            Some(rest) if folder.ends_with(':') && known => format!("{folder}{}", rest.text()),
            _ => folder.to_string(),
        };
        folders.push(if known {
            Arg::Known(folder)
        } else {
            Arg::Unknown(folder)
        });
    }
    if folders.is_empty() {
        folders.push(Arg::Known(".".to_string()));
    }
    Some(folders)
}

/// The folder `Expand-Archive` unpacks into: `-DestinationPath`, or the
/// second positional argument (the first when `-Path` is named), or the
/// working directory.
fn expand_archive(args: &[Arg]) -> Vec<Arg> {
    let params = Params::read(args);
    let named = params.values(&["destinationpath"]);
    if let Some(folder) = named.first() {
        return vec![(*folder).clone()];
    }
    let path_named = !params.values(&["path", "literalpath"]).is_empty();
    let folder = params
        .positional
        .get(usize::from(!path_named))
        .map_or_else(|| Arg::Known(".".to_string()), |folder| (*folder).clone());
    vec![folder]
}

/// What the arguments of `zip` after the archive's name stand for, while
/// they are read.
#[derive(Clone, Copy, PartialEq)]
enum ZipList {
    /// Files that stay out (`-x`, `--exclude`).
    Exclude,
    /// Patterns that choose among the files (`-i`, `--include`).
    Include,
}

/// The long options of `zip` that take a value in the next argument.
const ZIP_LONG_VALUES: &[&str] = &[
    "temp-path",
    "suffixes",
    "from-date",
    "before-date",
    "output-file",
    "password",
    "split-size",
    "compression-method",
    "unzip-command",
    "dot-size",
    "logfile-path",
    "unicode",
];

/// What a `zip` line does, as far as its arguments show.
struct Zip {
    /// Whether `-m` (`--move`) asks it to delete what it adds.
    moves: bool,
    /// Whether an argument only known when it runs may be `-m` (see
    /// [`may_be_option`]).
    unread: bool,
    /// The files it adds: see [`zip`].
    members: Vec<Arg>,
    /// The commands `-TT` (`--unzip-command`) gives it to test the archive.
    commands: Vec<Arg>,
}

impl Zip {
    /// The files `-m` deletes after adding them, and whether only an
    /// argument that may be it does.
    fn removed(self) -> (Vec<Arg>, bool) {
        if self.moves || self.unread {
            (self.members, !self.moves)
        } else {
            (Vec::new(), false)
        }
    }
}

/// What `zip` is asked to do. Its members are the operands after the
/// archive's name, and the names it reads from its input (`-@`). The
/// patterns that follow a bare `-x` stay, up to a lone `@`; those that
/// follow a bare `-i` only choose among the files under each operand, and
/// stand in for them when none is given. With no operand and no pattern,
/// `-u`, `-f` and `-FS` take the files the archive lists, which are under
/// the working directory (`*`). `-xpat` and `--exclude=pat` are one value
/// and open no list. An argument that only a run can show, inside a list,
/// may end it (it may start with `-` or be `@`), so the list is closed
/// after it. The value of an option that may split into words when it runs
/// is a member too (see [`may_split`]).
fn zip(args: &[Arg], shell: Shell) -> Zip {
    let unread = may_be_option(args, shell, |start| {
        could_be(start, Some('m'), Some("move"))
    });
    let mut moves = false;
    let mut split = Vec::new();
    let mut from_input = false;
    // `-u`, `-f` or `-FS`: the archive's own entries, with no names given.
    let mut listed = false;
    let mut positional = Vec::new();
    let mut included = Vec::new();
    let mut commands = Vec::new();
    let mut list = None;
    let mut options_done = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let option = arg
            .known()
            .filter(|text| !options_done && text.starts_with('-') && text.len() > 1);
        let Some(text) = option else {
            // A lone `@` ends a list and is no operand.
            if list.is_some() && arg.known() == Some("@") {
                list = None;
                continue;
            }
            match list {
                Some(ZipList::Exclude) => {}
                Some(ZipList::Include) => included.push(arg.clone()),
                None => positional.push(arg.clone()),
            }
            // An argument only known when it runs may start with `-` or be
            // a lone `@`, which end the list: the names after it are
            // operands again.
            if list.is_some() && may_be_switch(arg) {
                list = None;
            }
            continue;
        };
        list = None;
        if text == "--" {
            options_done = true;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let is = |full: &str| long_option(name, full, 3);
            if is("move") {
                moves = true;
            } else if is("names-stdin") {
                from_input = true;
            } else if is("update") || is("freshen") || is("filesync") {
                listed = true;
            } else if is("exclude") {
                // `--exclude=pat` is the one pattern; a list starts only
                // when nothing is attached.
                list = attached.is_none().then_some(ZipList::Exclude);
            } else if is("include") {
                list = attached.is_none().then_some(ZipList::Include);
            } else if is("unzip-command") {
                commands.extend(match attached {
                    Some(command) => Some(Arg::Known(command.to_string())),
                    None => iter.next().cloned(),
                });
            } else if attached.is_none() && ZIP_LONG_VALUES.iter().any(|full| is(full)) {
                split.extend(iter.next().filter(|value| may_split(value, shell)).cloned());
            }
            continue;
        }
        let letters = &text[1..];
        let mut before = None;
        for (at, letter) in letters.char_indices() {
            let rest = &letters[at + letter.len_utf8()..];
            // `-db`, `-sb`, `-ws` and `-li` are flags, not letters with a
            // value or a list.
            let flag = matches!(
                (before, letter),
                (Some('d' | 's'), 'b') | (Some('w'), 's') | (Some('l'), 'i')
            );
            let after_f = before == Some('F');
            before = Some(letter);
            if flag {
                continue;
            }
            // A value stands in the next argument when nothing follows the
            // option's name, and is the rest of this one when something does;
            // either way it ends the bundle.
            let mut separate = false;
            let mut inside = false;
            match letter {
                'm' => moves = true,
                '@' => from_input = true,
                'u' | 'f' => listed = true,
                'S' if after_f => listed = true,
                // Bare, they open a list; with something after the letter
                // (`-xpat`, `-x=pat`) that is the one value, and it ends the
                // bundle.
                'x' | 'i' => {
                    list = rest.is_empty().then_some(if letter == 'x' {
                        ZipList::Exclude
                    } else {
                        ZipList::Include
                    });
                    inside = !rest.is_empty();
                }
                'b' | 'O' | 'P' | 'Z' => separate = rest.is_empty(),
                // `-t date` and `-tt date`.
                't' => separate = rest.is_empty() || rest == "t",
                // `-TT command`, `-TTcommand` and `-TT=command`: the
                // command that tests the archive.
                'T' => {
                    separate = rest == "T";
                    inside = rest.starts_with('T') && !separate;
                    if inside {
                        let command = &rest[1..];
                        let command = command.strip_prefix('=').unwrap_or(command);
                        commands.push(Arg::Known(command.to_string()));
                    }
                }
                // `-s size` and `-s100m` (`-sf` and its kin are flags).
                's' => {
                    separate = rest.is_empty();
                    inside = rest.starts_with(|c: char| c.is_ascii_digit());
                }
                // `-n suffixes` and `-n.mp3` (`-nw` is a flag).
                'n' => {
                    separate = rest.is_empty();
                    inside = !rest.is_empty() && !rest.starts_with('w');
                }
                // `-UN warn`, `-UN=warn` and `-UNwarn`: the Unicode option,
                // whose value is a word that ends in a letter that is an
                // option of its own.
                'U' => {
                    if let Some(after) = rest.strip_prefix('N') {
                        separate = after.is_empty();
                        inside = !after.is_empty();
                    }
                }
                // `-ds size` and `-ds10m`, `-lf file` and `-lfout`.
                'd' | 'l' => {
                    let name = if letter == 'd' { 's' } else { 'f' };
                    if let Some(after) = rest.strip_prefix(name) {
                        separate = after.is_empty();
                        inside = !after.is_empty();
                    }
                }
                _ => {}
            }
            if separate {
                let value = iter.next();
                split.extend(value.filter(|value| may_split(value, shell)).cloned());
                if letter == 'T' {
                    commands.extend(value.cloned());
                }
            }
            if separate || inside || matches!(letter, 'b' | 'O' | 'P' | 'Z' | 't') {
                break;
            }
        }
    }
    // The first operand is the archive, unless it is not known which it is.
    let skip = usize::from(
        positional
            .first()
            .is_some_and(|first| first.known().is_some()),
    );
    let operands: Vec<Arg> = positional.split_off(skip.min(positional.len()));
    let mut members = if operands.is_empty() {
        included
    } else if included.is_empty() || !pairs_fit(&operands, &included) {
        // Past the bound each operand stands for all it holds, which is no
        // less than the patterns pick under it.
        operands
    } else {
        // Each pattern picks files under each operand.
        operands
            .iter()
            .flat_map(|operand| {
                included
                    .iter()
                    .map(move |pattern| within(Some(operand), pattern, shell))
            })
            .collect()
    };
    if members.is_empty() && listed && !from_input {
        members.push(Arg::Known("*".to_string()));
    }
    if from_input {
        members.push(Arg::Unknown("<names read from input>".to_string()));
    }
    members.extend(split);
    Zip {
        moves,
        unread,
        members,
        commands,
    }
}

/// The most pairs of an operand and a pattern of `zip -i` judged one by
/// one, and the most bytes they come to: each pair is a path, so a line of
/// many of both would make a number of paths that grows as their product.
const ZIP_PAIRS_LIMIT: usize = 1024;
const ZIP_PAIRS_BYTES: usize = 256 * 1024;

/// Whether every operand can be joined to every pattern within
/// [`ZIP_PAIRS_LIMIT`] and [`ZIP_PAIRS_BYTES`].
fn pairs_fit(operands: &[Arg], patterns: &[Arg]) -> bool {
    let bytes = |args: &[Arg]| args.iter().map(|arg| arg.text().len()).sum::<usize>();
    let pairs = operands.len().saturating_mul(patterns.len());
    let joined = bytes(operands)
        .saturating_mul(patterns.len())
        .saturating_add(bytes(patterns).saturating_mul(operands.len()));
    pairs <= ZIP_PAIRS_LIMIT && joined <= ZIP_PAIRS_BYTES
}

/// What can be read of the start of an argument, as far as it is text: the
/// value of one that is known, and the text as written of one only known
/// when it runs (`-p"$PASS"` starts with `-p`).
fn readable(arg: &Arg) -> &str {
    match arg {
        Arg::Known(text) | Arg::Unknown(text) | Arg::Template { text, .. } => text,
        Arg::Input | Arg::Null => "",
    }
}

/// Whether an argument can be nothing but a switch, however it expands: it
/// is only known when it runs and no letter of its start is plain text that
/// rules a switch out.
fn may_be_switch(arg: &Arg) -> bool {
    arg.known().is_none()
        && !readable(arg)
            .starts_with(|c: char| c.is_alphanumeric() || matches!(c, '.' | '/' | '~' | '\\' | '_'))
}

/// The files `7z a` and `7z u` delete after adding them, which `-sdel`
/// asks for: the operands after the archive's name, the patterns of `-i`,
/// and the lists named with `@`; with none of them, `*`. `-si` packs its
/// input, not files, so with it there is no `*`. An argument whose
/// readable start is `-` is a switch whatever follows (`-p"$PASS"`); one
/// that may be `-i` adds a member only known when it runs. An argument
/// wholly unknown (`$OPTS`) may be a switch too, so the default `*` stays
/// among the members when the operands that are known leave none. One that
/// may be `-sdel` (see [`may_be_option`]) may delete them; with the members,
/// whether only such an argument does.
fn seven_zip_removes(args: &[Arg], shell: Shell) -> (Vec<Arg>, bool) {
    let list = || Arg::Unknown("<files from a list>".to_string());
    let unread = may_be_option(args, shell, |start| {
        let start = start.to_ascii_lowercase();
        "-sdel".starts_with(&start) || start.starts_with("-sdel")
    });
    let mut deletes = false;
    let mut adds = false;
    let mut included = false;
    let mut input = false;
    let mut positional = 0;
    // The operands that cannot be a switch: the command, the archive and
    // the names after it.
    let mut definite = 0;
    let mut members = Vec::new();
    let mut options_done = false;
    for arg in args {
        let start = readable(arg);
        let is_switch = !options_done && start.starts_with('-') && start.len() > 1;
        let text = match arg.known() {
            Some(text) if is_switch => text,
            None if is_switch => {
                // Only known when it runs: a switch, which may be `-i`.
                let letter = start[1..].chars().next();
                if letter.is_none_or(|c| c.eq_ignore_ascii_case(&'i') || !c.is_ascii_alphabetic()) {
                    included = true;
                    members.push(Arg::Unknown(arg.text().to_string()));
                }
                continue;
            }
            _ => {
                positional += 1;
                definite += usize::from(!may_be_switch(arg));
                match positional {
                    // The command: one that is not known may add.
                    1 => {
                        adds = arg.known().is_none_or(|text| {
                            matches!(text.to_ascii_lowercase().as_str(), "a" | "u")
                        });
                    }
                    2 => {}
                    _ => members.push(match arg.known() {
                        Some(text) if text.starts_with('@') => list(),
                        _ => arg.clone(),
                    }),
                }
                continue;
            }
        };
        if text == "--" {
            options_done = true;
        } else if text.eq_ignore_ascii_case("-sdel") {
            deletes = true;
        } else if text
            .get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("-si"))
        {
            // `-si` and `-si{name}`: what it packs is its input.
            input = true;
        } else if text
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("-i"))
        {
            // `-i!pattern`, `-ir!pattern`, `-ir0!pattern`, `-i@list`.
            included = true;
            let rest = text[2..]
                .trim_start_matches(|c: char| matches!(c, 'r' | 'R' | '-') || c.is_ascii_digit());
            if let Some(pattern) = rest.strip_prefix('!') {
                members.push(Arg::Known(pattern.to_string()));
            } else if rest.starts_with('@') {
                members.push(list());
            }
        }
    }
    // Given no names and no `-i`, `a` and `u` pack everything under the
    // working directory (the default wildcard `*`). An argument that may be
    // a switch leaves it as one reading, so it stays when the operands that
    // are certain are no more than the command and the archive.
    let all_known = members.iter().all(|member| member.known().is_some());
    if !included && !input && positional >= 2 && definite <= 2 && all_known {
        members.push(Arg::Known("*".to_string()));
    }
    if (deletes || unread) && adds {
        (members, !deletes)
    } else {
        (Vec::new(), false)
    }
}

/// The files `rar` deletes after adding them: those of `m` and `mf`, and of
/// `a`, `u` and `f` given `-df`, `-dr` (to the recycle bin) or `-dw` (wiped).
/// They are the operands after the archive's name, and the lists named with
/// `@`; with none, everything under the working directory (`*`). Switches
/// are single words, not case-sensitive, and may stand anywhere before
/// `--`. A command only known when it runs may be `m`, and a switch only
/// known when it runs may be `-df`.
fn rar_removes(args: &[Arg]) -> Vec<Arg> {
    let mut deletes = false;
    let mut positional: Vec<&Arg> = Vec::new();
    let mut options_done = false;
    for arg in args {
        let start = readable(arg);
        if options_done || !start.starts_with('-') || start.len() < 2 {
            positional.push(arg);
            continue;
        }
        match arg.known().map(str::to_ascii_lowercase).as_deref() {
            Some("--") => options_done = true,
            Some("-df" | "-dr" | "-dw") => deletes = true,
            Some(_) => {}
            None => {
                let letter = start[1..].chars().next();
                deletes |=
                    letter.is_none_or(|c| c.eq_ignore_ascii_case(&'d') || !c.is_ascii_alphabetic());
            }
        }
    }
    let Some((command, rest)) = positional.split_first() else {
        return Vec::new();
    };
    let removes =
        command
            .known()
            .is_none_or(|command| match command.to_ascii_lowercase().as_str() {
                "m" | "mf" => true,
                "a" | "u" | "f" => deletes,
                _ => false,
            });
    if !removes {
        return Vec::new();
    }
    // The first operand after the command is the archive, unless it is not
    // known which it is.
    let skip = usize::from(rest.first().is_some_and(|first| first.known().is_some()));
    let mut members: Vec<Arg> = rest
        .iter()
        .skip(skip)
        .map(|arg| match arg.known() {
            Some(text) if text.starts_with('@') => from_list(),
            _ => (*arg).clone(),
        })
        .collect();
    if members.is_empty() && !rest.is_empty() {
        members.push(Arg::Known("*".to_string()));
    }
    members
}
