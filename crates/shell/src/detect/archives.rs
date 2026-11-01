//! The rules about unpacking archives: an archive unpacked into a folder is
//! a write into that folder, judged like the destination of `cp`. With no
//! folder given it unpacks into the working directory. The paths stored in
//! the archive cannot be seen from the line and are not read.

use super::Checker;
use crate::powershell::Params;
use crate::unit::{Arg, Unit};

impl Checker<'_> {
    /// `tar -x`, `unzip`, `7z x`, `Expand-Archive`.
    pub(super) fn unpack(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let folders = match key {
            "tar" | "gtar" | "bsdtar" => tar(args),
            "unzip" => unzip(args),
            "7z" | "7za" | "7zr" | "7zz" => seven_zip(args),
            "expand-archive" => Some(expand_archive(args)),
            _ => None,
        };
        for folder in folders.unwrap_or_default() {
            self.write_folder(unit.shell, unit.scope(), &folder, "unpacks into");
        }
    }
}

/// Whether `name`, a long option as written, is `full` or a prefix of it of
/// at least `least` letters: GNU tar and bsdtar take a unique prefix.
fn long_option(name: &str, full: &str, least: usize) -> bool {
    name.len() >= least && full.starts_with(name)
}

/// The folders `tar` unpacks into, when it extracts: `-C dir` (`-Cdir`,
/// `--directory dir`, `--directory=dir`, wherever it stands), or the
/// working directory. A mode that only the line's run shows (`tar "$mode"
/// -f x.tar`) counts as extracting.
fn tar(args: &[Arg]) -> Option<Vec<Arg>> {
    // Short options that take a value, whose bundle ends with it.
    const VALUES: &str = "CfbILKNTXFgHV";
    let mut extract = false;
    let mut other_mode = false;
    let mut to_stdout = false;
    // An argument only known when it runs, which may hold the mode.
    let mut unknown = false;
    let mut folders = Vec::new();
    let mut iter = args.iter().enumerate();
    while let Some((at, arg)) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            continue;
        };
        if text == "--" {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            // Each option may be written as a prefix of it, of at least three
            // letters (`--ext`, `--dir`), as the programs take the unique one.
            let is = |full: &str| long_option(name, full, 3);
            if name == "get" || is("extract") {
                extract = true;
            } else if [
                "create", "list", "append", "update", "diff", "compare", "delete",
            ]
            .iter()
            .any(|mode| is(mode))
            {
                other_mode = true;
            } else if long_option(name, "to-stdout", 4) {
                to_stdout = true;
            } else if long_option(name, "one-top-level", 7) {
                folders.extend(attached.map(|folder| Arg::Known(folder.to_string())));
            } else if is("directory") {
                match attached {
                    Some(folder) => folders.push(Arg::Known(folder.to_string())),
                    None => folders.extend(iter.next().map(|(_, folder)| folder.clone())),
                }
            }
            continue;
        }
        // The first argument may be a bundle without a dash: `tar xzf x.tgz`,
        // whose valued letters take the arguments after it, in order.
        let old_style = at == 0 && !text.starts_with('-');
        if !old_style && !text.starts_with('-') {
            continue;
        }
        let letters = text.strip_prefix('-').unwrap_or(text);
        if !old_style && letters.is_empty() {
            continue;
        }
        for (position, letter) in letters.char_indices() {
            if VALUES.contains(letter) {
                let rest = &letters[position + letter.len_utf8()..];
                let value = if !old_style && !rest.is_empty() {
                    Some(Arg::Known(rest.to_string()))
                } else {
                    iter.next().map(|(_, value)| value.clone())
                };
                if letter == 'C' {
                    folders.extend(value);
                }
                if !old_style {
                    break;
                }
                continue;
            }
            match letter {
                'x' => extract = true,
                'c' | 't' | 'r' | 'u' | 'A' | 'd' => other_mode = true,
                'O' => to_stdout = true,
                _ => {}
            }
        }
    }
    // With no mode read, an argument that is only known when it runs may be
    // `-x`.
    extract |= unknown && !other_mode;
    if !extract || other_mode || to_stdout {
        return None;
    }
    if folders.is_empty() {
        folders.push(Arg::Known(".".to_string()));
    }
    Some(folders)
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
            Arg::Known(text) => (text, true),
            Arg::Unknown(text) | Arg::Template { source: text, .. } => (text, false),
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
