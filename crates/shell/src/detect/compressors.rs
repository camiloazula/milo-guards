//! The rule about compressors: `gzip x` writes `x.gz` and deletes `x`, so a
//! compressor run on a file deletes that file and writes the one it makes,
//! and both are judged where they land, as `rm` judges what it deletes and
//! any write what it writes. `-c` (`--stdout`) writes to the screen and
//! deletes nothing, `-k` (`--keep`) keeps the file, and `zstd`, `lz4`,
//! `lzop` and `brotli` keep it unless told not to (`--rm`). Decompressing
//! (`-d`, `gunzip`) deletes `x.gz` and writes `x`.

use super::Checker;
use crate::path::within;
use crate::unit::{could_be, may_split, option_start, Arg, Flagged, Unit};
use crate::Shell;
use std::collections::HashSet;

/// How one compressor reads its arguments and names what it writes.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is one way a compressor's own behaviour differs"
)]
pub(super) struct Spec {
    /// The suffix it adds to the name of a file it compresses.
    suffix: &'static str,
    /// The suffixes it takes off a file it decompresses, each with what
    /// stands in its place (`.tgz` is `.tar`).
    strips: &'static [(&'static str, &'static str)],
    /// What it adds to a name with none of them when it decompresses
    /// (`bzip2 -d x` writes `x.out`); without one it writes nothing new.
    fallback: Option<&'static str>,
    /// Whether its name decompresses (`gunzip`).
    decompresses: bool,
    /// Whether it deletes what it compresses unless told to keep it.
    removes: bool,
    /// Whether `-k` (`--keep`) keeps it.
    keeps: bool,
    /// The option that deletes what it compresses, when it keeps it by
    /// default: a letter and long names (`zstd --rm`, `lzop -U`).
    remove: (Option<char>, &'static [&'static str]),
    /// The option that names the file it writes (`-o`).
    output: (Option<char>, &'static [&'static str]),
    /// The option that names the folder it writes into (`zstd
    /// --output-dir-flat`, `lzop -p`).
    folder: (Option<char>, &'static [&'static str]),
    /// The option that gives its suffix (`-S`, `--suffix`).
    suffix_option: (Option<char>, &'static [&'static str]),
    /// The letters of its other options that take a value, which ends the
    /// bundle, and their long names.
    valued: (&'static str, &'static [&'static str]),
    /// The letters and long names that test or list, and write nothing.
    nothing: (&'static str, &'static [&'static str]),
    /// The long options that take the files from a list the line does not
    /// show (`xz --files`, `zstd --filelist`).
    lists: &'static [&'static str],
    /// Whether a second operand is the file it writes (`lz4 in out`),
    /// unless `-m` (`--multiple`) or `-r` makes every operand an input.
    positional_output: bool,
}

/// A compressor with none of the options: what each one is built from.
const BASE: Spec = Spec {
    suffix: "",
    strips: &[],
    fallback: None,
    decompresses: false,
    removes: true,
    keeps: true,
    remove: (None, &[]),
    output: (None, &[]),
    folder: (None, &[]),
    suffix_option: (None, &[]),
    valued: ("", &[]),
    nothing: ("t", &["test"]),
    lists: &[],
    positional_output: false,
};

const GZIP: Spec = Spec {
    suffix: ".gz",
    strips: &[
        (".gz", ""),
        ("-gz", ""),
        (".z", ""),
        ("-z", ""),
        ("_z", ""),
        (".tgz", ".tar"),
        (".taz", ".tar"),
    ],
    suffix_option: (Some('S'), &["suffix"]),
    // `pigz -b`, `-p`, `-I`, `-J` and `-C` too.
    valued: (
        "bpIJC",
        &[
            "blocksize",
            "processes",
            "iterations",
            "maxsplits",
            "comment",
        ],
    ),
    nothing: ("tl", &["test", "list"]),
    ..BASE
};

const XZ: Spec = Spec {
    suffix: ".xz",
    strips: &[
        (".xz", ""),
        (".txz", ".tar"),
        (".lzma", ""),
        (".tlz", ".tar"),
        (".lz", ""),
    ],
    suffix_option: (Some('S'), &["suffix"]),
    valued: (
        "FCMT",
        &[
            "format",
            "check",
            "memlimit",
            "memlimit-compress",
            "memlimit-decompress",
            "memlimit-mt",
            "memory",
            "threads",
            "block-size",
            "block-list",
            "filters",
            "flush-timeout",
        ],
    ),
    nothing: ("tl", &["test", "list"]),
    lists: &["files", "files0"],
    ..BASE
};

const BZIP2: Spec = Spec {
    suffix: ".bz2",
    strips: &[
        (".bz2", ""),
        (".bz", ""),
        (".tbz2", ".tar"),
        (".tbz", ".tar"),
    ],
    fallback: Some(".out"),
    // `lbzip2 -n`.
    valued: ("n", &[]),
    ..BASE
};

const ZSTD: Spec = Spec {
    suffix: ".zst",
    strips: &[
        (".zst", ""),
        (".tzst", ".tar"),
        (".gz", ""),
        (".tgz", ".tar"),
        (".xz", ""),
        (".txz", ".tar"),
        (".lzma", ""),
        (".lz4", ""),
    ],
    removes: false,
    remove: (None, &["rm"]),
    output: (Some('o'), &[]),
    folder: (None, &["output-dir-flat", "output-dir-mirror"]),
    // `pzstd -p`.
    valued: ("Dp", &["patch-from", "filelist", "trace"]),
    nothing: ("tl", &["test", "list"]),
    lists: &["filelist"],
    ..BASE
};

const LZ4: Spec = Spec {
    suffix: ".lz4",
    strips: &[(".lz4", ""), (".tlz4", ".tar")],
    removes: false,
    remove: (None, &["rm"]),
    nothing: ("t", &["test", "list"]),
    positional_output: true,
    ..BASE
};

const COMPRESS: Spec = Spec {
    suffix: ".Z",
    strips: &[(".Z", ""), (".taZ", ".tar")],
    keeps: false,
    valued: ("b", &[]),
    nothing: ("", &[]),
    ..BASE
};

const LZIP: Spec = Spec {
    suffix: ".lz",
    strips: &[(".lz", ""), (".tlz", ".tar")],
    output: (Some('o'), &["output"]),
    valued: (
        "bmsSBn",
        &[
            "member-size",
            "match-length",
            "dictionary-size",
            "volume-size",
            "data-size",
            "threads",
        ],
    ),
    nothing: ("tl", &["test", "list"]),
    ..BASE
};

const LZOP: Spec = Spec {
    suffix: ".lzo",
    strips: &[(".lzo", ""), (".tzo", ".tar")],
    removes: false,
    remove: (Some('U'), &["unlink", "delete"]),
    output: (Some('o'), &["output"]),
    folder: (Some('p'), &["path"]),
    suffix_option: (Some('S'), &["suffix"]),
    nothing: ("tl", &["test", "list", "ls", "info"]),
    ..BASE
};

const BROTLI: Spec = Spec {
    suffix: ".br",
    strips: &[(".br", "")],
    removes: false,
    remove: (Some('j'), &["rm"]),
    output: (Some('o'), &["output"]),
    suffix_option: (Some('S'), &["suffix"]),
    valued: ("qwD", &["quality", "lgwin", "dictionary", "large_window"]),
    ..BASE
};

/// How the compressor `key` reads its arguments, or `None` for any other
/// program. `compress` and `uncompress` are the POSIX programs; in cmd and
/// PowerShell `compress` is Windows' own, which writes the file it is given
/// second and keeps the first.
pub(super) fn spec(key: &str, shell: Shell) -> Option<Spec> {
    let decompressing = |spec: Spec| Spec {
        decompresses: true,
        ..spec
    };
    Some(match key {
        "gzip" | "pigz" => GZIP,
        "gunzip" | "unpigz" => decompressing(GZIP),
        "xz" => XZ,
        "lzma" => Spec {
            suffix: ".lzma",
            ..XZ
        },
        "unxz" | "unlzma" => decompressing(XZ),
        "bzip2" | "pbzip2" | "lbzip2" => BZIP2,
        "bunzip2" => decompressing(BZIP2),
        "zstd" | "pzstd" => ZSTD,
        "unzstd" => decompressing(ZSTD),
        "lz4" => LZ4,
        "unlz4" => decompressing(LZ4),
        "compress" if shell == Shell::Posix => COMPRESS,
        "uncompress" if shell == Shell::Posix => decompressing(COMPRESS),
        "lzip" | "plzip" => LZIP,
        "lunzip" => decompressing(LZIP),
        "lzop" => LZOP,
        "brotli" => BROTLI,
        _ => return None,
    })
}

/// Whether `name`, a long option as written, is `full`, or a prefix of it
/// of three letters or more when `prefix`: the programs that read long
/// options with `getopt_long` take a unique prefix, so one that may raise
/// what the line does is read from a prefix, and one that may lower it only
/// from the whole name.
fn long_is(name: &str, fulls: &[&str], prefix: bool) -> bool {
    fulls
        .iter()
        .any(|full| name == *full || (prefix && name.len() >= 3 && full.starts_with(name)))
}

/// What a compressor's arguments ask for.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each is one thing an argument of a compressor may say, read in any order"
)]
#[derive(Default)]
struct Run {
    /// Decompress (`-d`), as the name or the last of `-d` and `-z` says.
    decompress: bool,
    /// An argument only known when it runs may be `-d`.
    maybe_decompress: bool,
    /// Write to the screen (`-c`).
    screen: bool,
    /// Keep the files (`-k`).
    keep: bool,
    /// Delete the files, for one that keeps them by default (`--rm`).
    remove: bool,
    /// An argument only known when it runs may be the option that deletes
    /// them.
    maybe_remove: bool,
    /// An argument only known when it runs may name the file or the folder
    /// it writes, or its suffix.
    maybe_output: bool,
    /// Test or list (`-t`, `-l`): write nothing.
    nothing: bool,
    /// Every operand is a folder whose files it compresses (`-r`).
    recursive: bool,
    /// Every operand is an input (`lz4 -m`).
    multiple: bool,
    /// The files `-o` names.
    outputs: Vec<Arg>,
    /// The folder `--output-dir-flat` (`lzop -p`) names.
    folder: Option<Arg>,
    /// The suffix `-S` gives.
    suffix: Option<Arg>,
    /// The files it is given, `-` (its input) among them, and a file
    /// only known when it runs for each list of them it reads.
    operands: Vec<Arg>,
}

impl Run {
    /// The long option `name`, with its value attached with `=` if any.
    fn long<'a>(
        &mut self,
        spec: &Spec,
        name: &str,
        attached: Option<Arg>,
        iter: &mut impl Iterator<Item = &'a Arg>,
    ) {
        let mut value = |attached: Option<Arg>| attached.or_else(|| iter.next().cloned());
        if long_is(name, &["decompress", "uncompress"], true) {
            self.decompress = true;
        } else if long_is(name, &["compress"], false) {
            self.decompress = false;
        } else if long_is(name, &["stdout", "to-stdout"], false) {
            self.screen = true;
        } else if spec.keeps && long_is(name, &["keep"], false) {
            self.keep = true;
        } else if long_is(name, spec.remove.1, true) {
            self.remove = true;
        } else if long_is(name, spec.nothing.1, false) {
            self.nothing = true;
        } else if long_is(name, &["recursive"], true) {
            self.recursive = true;
        } else if long_is(name, &["multiple"], true) {
            self.multiple = true;
        } else if long_is(name, spec.lists, true) {
            // `--files=list` and `--filelist list`: the files are in a
            // list the line does not show. `xz --files` takes its list
            // only attached, and reads its input without one.
            if !spec.lists.contains(&"files") {
                value(attached);
            }
            self.operands
                .push(Arg::Unknown("<files from a list>".to_string()));
        } else if long_is(name, spec.output.1, true) {
            self.outputs.extend(value(attached));
        } else if long_is(name, spec.folder.1, true) {
            self.folder = value(attached);
        } else if long_is(name, spec.suffix_option.1, true) {
            self.suffix = value(attached);
        } else if attached.is_none() && long_is(name, spec.valued.1, false) {
            value(None);
        }
    }

    /// A bundle of one-letter options (`-kd9`, `-S.x`, `-o out`).
    fn short<'a>(&mut self, spec: &Spec, letters: &str, iter: &mut impl Iterator<Item = &'a Arg>) {
        for (at, letter) in letters.char_indices() {
            let is = |option: (Option<char>, &[&str])| option.0 == Some(letter);
            if is(spec.output)
                || is(spec.folder)
                || is(spec.suffix_option)
                || spec.valued.0.contains(letter)
            {
                let rest = &letters[at + letter.len_utf8()..];
                let value = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                if is(spec.output) {
                    self.outputs.extend(value);
                } else if is(spec.folder) {
                    self.folder = value;
                } else if is(spec.suffix_option) {
                    self.suffix = value;
                }
                return;
            }
            match letter {
                'd' => self.decompress = true,
                'z' => self.decompress = false,
                'c' => self.screen = true,
                'k' if spec.keeps => self.keep = true,
                'r' => self.recursive = true,
                'm' if spec.positional_output => self.multiple = true,
                _ if spec.remove.0 == Some(letter) => self.remove = true,
                _ if spec.nothing.0.contains(letter) => self.nothing = true,
                _ => {}
            }
        }
    }

    /// An argument only known when it runs that starts as an option
    /// (`"-$L"`): it may be any option its start allows.
    fn unknown_option(&mut self, spec: &Spec, start: &str) {
        let any = |(letter, longs): (Option<char>, &[&str])| {
            could_be(start, letter, None)
                || longs.iter().any(|long| could_be(start, None, Some(long)))
        };
        self.maybe_decompress |= any((Some('d'), &["decompress", "uncompress"]));
        self.maybe_remove |= any(spec.remove);
        self.maybe_output |= any(spec.output) || any(spec.folder) || any(spec.suffix_option);
    }
}

/// Read a compressor's arguments as `spec` says.
fn read(spec: &Spec, args: &[Arg], shell: Shell) -> Run {
    let mut run = Run {
        decompress: spec.decompresses,
        ..Run::default()
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            // One that may split into words may be options and files; one
            // that starts as an option is one. What a pipeline hands it
            // (`xargs gzip`) is the files the stage before lists.
            let split = may_split(arg, shell) && *arg != Arg::Input;
            let start = option_start(arg, shell);
            if split || start.is_some() {
                run.unknown_option(spec, start.as_deref().unwrap_or(""));
            }
            if split || start.is_none() {
                run.operands.push(arg.clone());
            }
            continue;
        };
        if text == "--" {
            run.operands.extend(iter.by_ref().cloned());
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
                None => (long, None),
            };
            run.long(spec, name, attached, &mut iter);
        } else if let Some(letters) = text.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            run.short(spec, letters, &mut iter);
        } else {
            run.operands.push(arg.clone());
        }
    }
    run
}

/// The file a compressor writes for the file `input`: with the suffix
/// added, or taken off when `decompress`. `suffix` is the one `-S` gives.
fn written_for(spec: &Spec, input: &Arg, decompress: bool, suffix: Option<&Arg>) -> Arg {
    let Some(text) = input.known() else {
        return Arg::Unknown(input.text().to_string());
    };
    let unknown = || Arg::Unknown(format!("{text}{}", suffix.map_or("", Arg::text)));
    if !decompress {
        return match suffix {
            None => Arg::Known(format!("{text}{}", spec.suffix)),
            Some(Arg::Known(suffix)) => Arg::Known(format!("{text}{suffix}")),
            Some(_) => unknown(),
        };
    }
    match suffix {
        Some(Arg::Known(suffix)) if !suffix.is_empty() && text.len() > suffix.len() => {
            if let Some(stem) = text.strip_suffix(suffix.as_str()) {
                return Arg::Known(stem.to_string());
            }
        }
        Some(Arg::Known(_)) | None => {}
        Some(_) => return unknown(),
    }
    for (from, to) in spec.strips {
        if let Some(stem) = text.strip_suffix(from).filter(|stem| !stem.is_empty()) {
            return Arg::Known(format!("{stem}{to}"));
        }
    }
    Arg::Known(match spec.fallback {
        Some(fallback) => format!("{text}{fallback}"),
        None => text.to_string(),
    })
}

/// The last part of a path, which a folder the output goes into takes.
fn file_name(arg: &Arg) -> Arg {
    match arg {
        Arg::Known(text) => Arg::Known(text.rsplit(['/', '\\']).next().unwrap_or(text).to_string()),
        other => Arg::Unknown(other.text().to_string()),
    }
}

impl Checker<'_> {
    /// A compressor (`gzip`, `xz`, `zstd`, …) run on files: it deletes each
    /// unless it keeps it, and writes the file it makes, each judged where
    /// it lands.
    pub(super) fn compress(&mut self, unit: &Unit, key: &str) {
        let shell = unit.shell;
        let Some(spec) = spec(key, shell) else {
            return;
        };
        let mut run = read(&spec, &unit.args, shell);
        if run.nothing || run.screen {
            return;
        }
        // `lz4 in out` writes `out`; `-` is the input or the screen.
        let positional = spec.positional_output && !run.multiple && !run.recursive;
        if positional && run.operands.len() >= 2 {
            run.outputs.extend(run.operands.drain(1..));
        }
        let stdin = |arg: &Arg| arg.known() == Some("-");
        let inputs: Vec<Arg> = run
            .operands
            .iter()
            .filter(|arg| !stdin(arg))
            .cloned()
            .collect();
        if inputs.is_empty() {
            return;
        }
        let removes = if spec.removes {
            Flagged::of(!run.keep, false)
        } else {
            Flagged::of(run.remove, run.maybe_remove)
        };
        let scope = unit.scope();
        self.flagged(removes, |checker| {
            checker.delete(unit, &inputs.iter().collect::<Vec<_>>(), "deletes");
        });
        if run.recursive {
            // The files it writes are in the folders it is given.
            for folder in &inputs {
                self.write_folder(shell, scope, folder, "writes into");
            }
        } else if !run.outputs.is_empty() {
            for output in run.outputs.iter().filter(|arg| !stdin(arg)) {
                self.write(shell, scope, output, "writes to");
            }
        } else {
            let mut seen = HashSet::new();
            let mut written = Vec::new();
            for input in &inputs {
                for found in self.expand(unit, input).0 {
                    let modes: &[bool] = if run.maybe_decompress {
                        &[run.decompress, !run.decompress]
                    } else {
                        std::slice::from_ref(&run.decompress)
                    };
                    for &decompress in modes {
                        let name = written_for(&spec, &found, decompress, run.suffix.as_ref());
                        let name = match &run.folder {
                            Some(folder) => within(Some(folder), &file_name(&name), shell),
                            None => name,
                        };
                        if seen.insert(name.clone()) {
                            written.push(name);
                        }
                    }
                }
            }
            for name in &written {
                self.write(shell, scope, name, "writes to");
            }
        }
        if run.maybe_output {
            let before = self.found.len();
            self.write(
                shell,
                scope,
                &Arg::Unknown("<a file named by an option>".to_string()),
                "writes to",
            );
            self.hedge(before);
        }
    }
}
