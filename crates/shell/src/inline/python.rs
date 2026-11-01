//! Inline Python: the calls that delete, write, move and run, with the
//! paths they name, found with tree-sitter-python.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::{
    environment, join, mode, named_path, path, read_path, walk, writes, Act, Ancestor, Constants,
    Expansion, Holds, Language, Parts, Reading, MAX_ROUNDS,
};
use crate::unit::{self, Arg, MAX_TREE_DEPTH};

pub(super) fn read(code: &str) -> Reading {
    // CPython turns CRLF and a lone CR into a newline before it reads code
    // (`translate_newlines`); tree-sitter-python does not, so a comment that
    // ends at a CR would swallow the code after it.
    let translated = translate_newlines(code);
    let code = translated.as_str();
    let mut reader = Reader::new(code, HashMap::new(), HashSet::new(), 0);
    let Some(tree) = parse(code) else {
        reader.reading.unread(code);
        return reader.reading;
    };
    let root = tree.root_node();
    if root.has_error() {
        reader.reading.unread(code);
    }
    reader.collect_imports(root);
    reader.walk_all(root);
    reader.reading
}

fn parse(code: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .ok()
        .and_then(|()| parser.parse(code, None))
}

/// `code` with CRLF and a lone CR read as a newline, as Python itself does.
fn translate_newlines(code: &str) -> String {
    code.replace("\r\n", "\n").replace('\r', "\n")
}

/// The encodings whose bytes, when all ASCII, decode to the same text as
/// UTF-8 does: the reader always reads UTF-8. UTF-7, UTF-16 and 32, EBCDIC
/// and the stateful East Asian encodings are not among them (`+AGk-` is an
/// `i` in UTF-7).
const ASCII_ENCODINGS: [&str; 14] = [
    "ascii",
    "us-ascii",
    "646",
    "latin-1",
    "latin1",
    "latin",
    "l1",
    "iso-8859-1",
    "iso8859-1",
    "8859",
    "iso-latin-1",
    "cp819",
    "windows-1252",
    "cp1252",
];

/// The encoding a PEP 263 line (`# coding: NAME`, `# -*- coding=NAME -*-`)
/// in the first two lines of `code` names, lower-cased with `_` as `-`.
fn coding_declared(code: &str) -> Option<String> {
    let translated = translate_newlines(code);
    translated.lines().take(2).find_map(|line| {
        let comment = line
            .trim_start_matches([' ', '\t', '\x0c'])
            .strip_prefix('#')?;
        // The first `coding:` or `coding=` that is followed by a name.
        comment.match_indices("coding").find_map(|(at, word)| {
            let rest = comment[at + word.len()..].strip_prefix([':', '='])?;
            let name: String = rest
                .trim_start_matches([' ', '\t'])
                .chars()
                .take_while(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            (!name.is_empty()).then(|| name.to_lowercase().replace('_', "-"))
        })
    })
}

/// Whether Python, when it reads `code` as bytes (from its input, or the
/// bytes literal given to `exec`, `eval` or `compile`), honours a coding
/// declaration that decodes it to other text than the reader sees: it
/// always reads the text as UTF-8. UTF-8 itself, and the ASCII-compatible
/// encodings for a text that is all ASCII, read the same.
pub(super) fn declares_other_encoding(code: &str) -> bool {
    let Some(name) = coding_declared(code) else {
        return false;
    };
    let utf8 = name == "utf-8" || name == "utf8" || name.starts_with("utf-8-");
    !(utf8 || (code.is_ascii() && ASCII_ENCODINGS.contains(&name.as_str())))
}

/// What a call to a qualified name does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Remove,
    /// The destination (second argument) is written.
    Copy,
    Move,
    Link,
    /// The first argument is written, made or truncated.
    Write,
    Chmod,
    /// `shutil.copymode(src, dst)` and `shutil.copystat(src, dst)`: the
    /// permission bits of the second argument are set, as `chmod` does.
    CopyMode,
    /// `fileinput.input(files, inplace)` and `fileinput.FileInput(…)`: with
    /// `inplace` on, each file is rewritten, as `sed -i` does.
    FileInput,
    /// `os.kill(pid, sig)` and `os.killpg(pgid, sig)`.
    Kill,
    Chown,
    Chdir,
    /// `os.fchdir(fd)`: a directory only known when it runs.
    Fchdir,
    /// `open(path, mode)` and the calls that open a file the same way.
    Open,
    /// `os.open(path, flags)`.
    OsOpen,
    /// `shutil.make_archive(base_name, format, root_dir, base_dir)`: the
    /// archive is written, and what it packs (`root_dir` and `base_dir`
    /// joined) is read, all the way down.
    Archive,
    /// `linecache.getline(filename, …)`, `getlines(filename)`: the first
    /// argument is a file read.
    ReadFile,
    /// `netrc.netrc(file)`: reads the file, or `~/.netrc` when none is given.
    NetRc,
    /// Runs a command line.
    Script,
    /// Runs a program from an argument list or a command line.
    Subprocess,
    /// Runs a program from its arguments.
    Exec,
    /// Starts a program or loads code the reader cannot follow.
    Unread,
    /// `eval` and `exec`.
    Eval,
    /// A library call that runs the code it is given as a string
    /// (`timeit.timeit`, `cProfile.run`): a literal is read as
    /// Python, a callable is walked where it is written, and anything else
    /// is code only known when it runs.
    Code,
    /// `__import__` and `importlib.import_module`.
    Import,
    Getattr,
}

/// The modules whose names a dotted name can be started again from: a
/// module that imported another holds it as an attribute (`shutil.os`),
/// `posix` and `nt` are what `os` is, and `builtins` holds the builtins.
const MODULES: [&str; 21] = [
    "sys",
    "os",
    "shutil",
    "subprocess",
    "pathlib",
    "builtins",
    "pty",
    "sqlite3",
    "tarfile",
    "zipfile",
    "codecs",
    "gzip",
    "bz2",
    "lzma",
    "asyncio",
    "importlib",
    "runpy",
    "ctypes",
    "io",
    "posix",
    "nt",
];

/// The module a name stands for when a module holds it: `os`, and `_os` as
/// `tempfile` and others import it.
fn module_named(name: &str) -> Option<&'static str> {
    let bare = name.strip_prefix('_').unwrap_or(name);
    MODULES.iter().find(|module| **module == bare).copied()
}

/// `name` with the module that really holds the call first: `shutil.os.remove`
/// is `os.remove`, `posix.remove` is `os.remove`, `builtins.exec` is `exec`.
fn rebase(name: &str) -> String {
    let parts: Vec<&str> = name.split('.').collect();
    let start = parts
        .iter()
        .rposition(|part| module_named(part).is_some())
        .unwrap_or(0);
    let mut parts = parts[start..].to_vec();
    if let Some(module) = parts.first().and_then(|part| module_named(part)) {
        parts[0] = module;
    }
    let rest = parts.join(".");
    if let Some(call) = rest
        .strip_prefix("posix.")
        .or_else(|| rest.strip_prefix("nt."))
    {
        format!("os.{call}")
    } else if let Some(call) = rest.strip_prefix("builtins.") {
        call.to_string()
    } else {
        rest
    }
}

/// `object.attribute` with the module that really holds the call first, for
/// an `object` that is already so (`rebase` of it): the same as `rebase` of
/// the two together, without splitting the whole name again.
fn extend(object: &str, attribute: &str) -> String {
    if let Some(module) = module_named(attribute) {
        return module.to_string();
    }
    match object {
        "posix" | "nt" => format!("os.{attribute}"),
        "builtins" => attribute.to_string(),
        _ => format!("{object}.{attribute}"),
    }
}

fn kind(name: &str) -> Option<Kind> {
    Some(match name {
        "os.remove"
        | "os.unlink"
        | "os.rmdir"
        | "os.removedirs"
        | "shutil.rmtree"
        | "send2trash.send2trash"
        | "distutils.dir_util.remove_tree" => Kind::Remove,
        "shutil.copy"
        | "shutil.copy2"
        | "shutil.copyfile"
        | "shutil.copytree"
        | "shutil.unpack_archive"
        | "distutils.dir_util.copy_tree"
        | "distutils.file_util.copy_file"
        | "urllib.request.urlretrieve"
        | "wget.download" => Kind::Copy,
        "shutil.move"
        | "os.rename"
        | "os.replace"
        | "os.renames"
        | "distutils.file_util.move_file" => Kind::Move,
        "os.symlink" | "os.link" => Kind::Link,
        "os.truncate"
        | "os.mkdir"
        | "os.makedirs"
        | "os.mkfifo"
        | "sqlite3.connect" => Kind::Write,
        "shutil.make_archive" => Kind::Archive,
        "linecache.getline" | "linecache.getlines" => Kind::ReadFile,
        "netrc.netrc" => Kind::NetRc,
        "os.chmod" | "os.lchmod" => Kind::Chmod,
        "shutil.copymode" | "shutil.copystat" => Kind::CopyMode,
        "fileinput.input" | "fileinput.FileInput" => Kind::FileInput,
        "os.kill" | "os.killpg" => Kind::Kill,
        "os.chown" | "os.lchown" | "shutil.chown" => Kind::Chown,
        "os.chdir" | "contextlib.chdir" => Kind::Chdir,
        "os.fchdir" => Kind::Fchdir,
        "open" | "builtins.open" | "io.open" | "io.FileIO" | "codecs.open" | "gzip.open"
        | "bz2.open" | "lzma.open" | "tarfile.open" | "zipfile.ZipFile" => Kind::Open,
        "os.open" => Kind::OsOpen,
        "os.system"
        | "os.popen"
        | "subprocess.getoutput"
        | "subprocess.getstatusoutput"
        | "asyncio.create_subprocess_shell"
        // `asyncio.subprocess` is read as `subprocess` (the last module in a
        // name holds the call), which is where these two really are.
        | "subprocess.create_subprocess_shell"
        | "commands.getoutput"
        | "commands.getstatusoutput"
        | "pexpect.run"
        | "pexpect.spawn" => Kind::Script,
        "subprocess.run"
        | "subprocess.call"
        | "subprocess.check_call"
        | "subprocess.check_output"
        | "subprocess.Popen" => Kind::Subprocess,
        "asyncio.create_subprocess_exec" | "subprocess.create_subprocess_exec" => Kind::Exec,
        "pty.spawn"
        | "sys.modules"
        // Read commands, and run what they say, from the input.
        | "breakpoint"
        | "sys.breakpointhook"
        | "compile"
        | "globals"
        | "locals"
        | "vars"
        | "importlib.reload"
        | "__builtins__"
        | "code.interact"
        | "code.InteractiveInterpreter"
        | "code.InteractiveConsole"
        | "cProfile.Profile"
        | "profile.Profile"
        | "pickle.loads"
        | "pickle.load"
        | "pickle.Unpickler"
        | "marshal.loads"
        | "marshal.load"
        | "pkgutil.resolve_name"
        | "importlib.util.module_from_spec"
        | "imp.load_source"
        | "imp.load_module"
        | "imp.load_compiled"
        | "imp.load_dynamic" => Kind::Unread,
        "timeit.timeit" | "timeit.repeat" | "timeit.Timer" | "cProfile.run" | "cProfile.runctx"
        | "profile.run" | "profile.runctx" => Kind::Code,
        "eval" | "exec" => Kind::Eval,
        "__import__" | "importlib.import_module" | "importlib.__import__" => Kind::Import,
        "getattr" => Kind::Getattr,
        name if name.starts_with("os.exec")
            || name.starts_with("os.spawn")
            || name.starts_with("os.posix_spawn")
            || name.starts_with("runpy.")
            // Every `pdb` call starts the debugger (`run`, `runeval`,
            // `runcall`, `main`, `Pdb`), which reads commands, and runs what
            // they say, from the input.
            || name.starts_with("pdb.")
            || name.starts_with("ctypes.")
            // The system's store of secrets, which is no file the reader
            // names: what a call asks it for is a read of a key.
            || name.starts_with("keyring.")
            || name.starts_with("keyrings.") =>
        {
            Kind::Unread
        }
        _ => return None,
    })
}

/// The `pathlib` classes, which `Path(…)` is read as when `Path` is not
/// imported.
const PATHS: [&str; 4] = ["Path", "PurePath", "PosixPath", "PurePosixPath"];

/// The calls that give a method of a `pathlib.Path` away when named without
/// being called (`map(Path.unlink, paths)`).
const METHODS: [&str; 10] = [
    "unlink",
    "rmdir",
    "write_text",
    "write_bytes",
    "symlink_to",
    "hardlink_to",
    "extractall",
    "read_text",
    "read_bytes",
    "open",
];

/// The calls of a module, by the start of their name, that touch nothing:
/// they only look at a name, compute, or give back a string made of it. A
/// call of a module the reader has no row for that is not one of these (or of
/// [`NAMES_ONLY_MORE`]) may read, write or delete a file or run anything, so
/// the line is unknown.
const NAMES_ONLY: &[&str] = &[
    "os.path.",
    "posixpath.",
    "ntpath.",
    "genericpath.",
    "sys.",
    "str.",
    "bytes.",
    "dict.",
    "list.",
    "set.",
    "tuple.",
    "frozenset.",
    "csv.",
    "copy.",
    "pprint.",
    "decimal.",
    "fractions.",
    "statistics.",
    "bisect.",
    "heapq.",
    "enum.",
    "dataclasses.",
    "abc.",
    "traceback.",
    "ipaddress.",
    "calendar.",
    "zlib.",
    "difflib.",
    "unicodedata.",
    "types.",
    "html.",
    "int.",
    "float.",
    "bool.",
    "re.",
    "json.",
    "math.",
    "time.",
    "datetime.",
    "random.",
    "string.",
    "textwrap.",
    "base64.",
    "binascii.",
    "hashlib.",
    "struct.",
    "itertools.",
    "functools.",
    "collections.",
    "operator.",
    "typing.",
    "shlex.",
    "fnmatch.",
    "glob.",
    "uuid.",
    "secrets.",
    "platform.",
    "locale.",
    // Not `argparse.FileType`: what it makes opens the file it is given (for
    // writing, with `'w'`) when the parser or the caller calls it.
    "argparse.Argument",
    "argparse.Namespace",
    "argparse.Action",
    "argparse.BooleanOptionalAction",
    "argparse.HelpFormatter",
    "argparse.Raw",
    "argparse.MetavarTypeHelpFormatter",
    "warnings.",
    "urllib.parse.",
    "logging.getLogger",
    "logging.debug",
    "logging.info",
    "logging.warning",
    "logging.error",
    "logging.critical",
    "logging.exception",
    "os.environ.",
    "os.getenv",
    "os.get",
    "os.fs",
    "shutil.which",
];

/// More of them, by their whole name: a listing or a look at the metadata of
/// a file opens none of it.
const NAMES_ONLY_MORE: &[&str] = &[
    "pathlib.Path",
    "pathlib.PurePath",
    "pathlib.PosixPath",
    "pathlib.PurePosixPath",
    "pathlib.Path.home",
    "pathlib.Path.cwd",
    "configparser.ConfigParser",
    "configparser.RawConfigParser",
    "configparser.SafeConfigParser",
    "ConfigParser.ConfigParser",
    "ConfigParser.RawConfigParser",
    "ConfigParser.SafeConfigParser",
    "io.StringIO",
    "io.BytesIO",
    "os.listdir",
    "os.scandir",
    "os.walk",
    "os.fwalk",
    "os.stat",
    "os.lstat",
    "os.access",
    "os.statvfs",
    "os.readlink",
    "shutil.disk_usage",
    "shutil.get_terminal_size",
    "os.cpu_count",
    "os.name",
    "os.sep",
    "os.linesep",
    "os.pathsep",
    "os.curdir",
    "os.pardir",
    "os.devnull",
    "os.environ",
    "os.urandom",
];

/// The methods of strings, lists, dictionaries, paths and loggers that are
/// given a path as text or as an argument and open nothing: they cut it,
/// compare it, hold it, or write it as a message.
const METHODS_OF_TEXT: &[&str] = &[
    "startswith",
    "endswith",
    "split",
    "rsplit",
    "splitlines",
    "partition",
    "rpartition",
    "strip",
    "lstrip",
    "rstrip",
    "removeprefix",
    "removesuffix",
    "replace",
    "join",
    "format",
    "format_map",
    "get",
    "setdefault",
    "pop",
    "append",
    "extend",
    "insert",
    "index",
    "add",
    "discard",
    "rindex",
    "find",
    "rfind",
    "count",
    "encode",
    "decode",
    "lower",
    "upper",
    "title",
    "write",
    "writelines",
    "print",
    "relative_to",
    "is_relative_to",
    "joinpath",
    "with_name",
    "with_suffix",
    "with_stem",
    "match",
    "fullmatch",
    "search",
    "sub",
    "subn",
    "findall",
    "finditer",
    "add_argument",
    "add_parser",
    "set_defaults",
    "getLogger",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "exception",
    "exists",
    "is_file",
    "is_dir",
    "samefile",
    "stat",
    "lstat",
    "is_symlink",
    "is_absolute",
    "as_posix",
    "parse_args",
    "parse_known_args",
    "print_help",
    "print_usage",
    "most_common",
    "elements",
    "popitem",
    "appendleft",
    "popleft",
    "fromkeys",
    "keys",
    "values",
    "items",
    "copy",
    "update",
    "sort",
    "reverse",
    "clear",
    "remove",
    "group",
    "groups",
    "groupdict",
    "start",
    "end",
    "span",
    "read",
    "readline",
    "readlines",
    "close",
    "flush",
    "seek",
    "tell",
    "fileno",
    "isatty",
    "strftime",
    "isoformat",
    "timestamp",
    "total_seconds",
    "hexdigest",
    "digest",
    "hex",
    "isdigit",
    "isalpha",
    "isalnum",
    "isspace",
    "islower",
    "isupper",
    "isidentifier",
    "isnumeric",
    "isdecimal",
    "istitle",
    "isascii",
    "zfill",
    "center",
    "ljust",
    "rjust",
    "capitalize",
    "swapcase",
    "casefold",
    "expandtabs",
    "translate",
    "weekday",
    "isoweekday",
    "astimezone",
    "utcoffset",
    "tzname",
    "date",
    "time",
    "bit_length",
    "to_bytes",
];

/// The methods of a `pathlib` path that touch nothing: they look at its name
/// or its metadata, list a folder, or make another path. Any other method of
/// a path (`rmtree`, `delete`, `truncate`, `write`) is one the reader has no
/// row for.
const METHODS_OF_PATHS: &[&str] = &[
    "stat",
    "lstat",
    "glob",
    "rglob",
    "iterdir",
    "expanduser",
    "resolve",
    "absolute",
    "exists",
    "is_file",
    "is_dir",
    "is_symlink",
    "is_absolute",
    "is_relative_to",
    "relative_to",
    "samefile",
    "joinpath",
    "with_name",
    "with_suffix",
    "with_stem",
    "as_posix",
    "as_uri",
    "match",
];

/// The builtins that only compute, which a call of a bare name is when the
/// code has not bound the name to something else.
const BUILTINS: &[&str] = &[
    "print",
    "len",
    "range",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "frozenset",
    "sorted",
    "reversed",
    "enumerate",
    "zip",
    "map",
    "filter",
    "sum",
    "min",
    "max",
    "abs",
    "round",
    "any",
    "all",
    "isinstance",
    "issubclass",
    "type",
    "repr",
    "format",
    "hash",
    "id",
    "ord",
    "chr",
    "hex",
    "oct",
    "bin",
    "bytes",
    "bytearray",
    "divmod",
    "pow",
    "dir",
    "iter",
    "next",
    "slice",
    "callable",
    "hasattr",
    "object",
    "super",
    "input",
    "exit",
    "quit",
    "complex",
    "ascii",
    "memoryview",
    "property",
    "staticmethod",
    "classmethod",
    "Exception",
    "BaseException",
    "ValueError",
    "TypeError",
    "KeyError",
    "IndexError",
    "RuntimeError",
    "OSError",
    "IOError",
    "FileNotFoundError",
    "FileExistsError",
    "PermissionError",
    "NotImplementedError",
    "AssertionError",
    "AttributeError",
    "StopIteration",
    "SystemExit",
    "KeyboardInterrupt",
    "ImportError",
    "NameError",
    "ZeroDivisionError",
];

/// Attributes that reach what a name cannot: a namespace as a table, the
/// classes of an object, the globals of a function.
const DUNDERS: [&str; 8] = [
    "__dict__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__code__",
    "__getattribute__",
    "__loader__",
    "__closure__",
];

struct Reader<'s> {
    src: &'s str,
    /// What each name `import` binds stands for: `rm` from `from os import
    /// remove as rm` is `os.remove`.
    aliases: HashMap<String, String>,
    /// The modules `import` and `__import__` bound, by their real names: a
    /// module reaches the modules it imported, so one handed on as a value
    /// can be used under a name the reader does not follow.
    modules: HashSet<String>,
    /// The dotted name of each node, found once: a chain of attributes is
    /// asked for from each node in it, and would be built again each time.
    /// Only filled once the names `import` bound are all known.
    names: HashMap<usize, Option<String>>,
    walking: bool,
    reading: Reading,
    /// How many pieces of literal code (`exec("…")`) this code is inside.
    nesting: usize,
    /// Whether literal code given to `exec` or `eval` in this code, or in
    /// code inside it, binds or uses a name the reader follows.
    shared: bool,
    /// The strings each name is set to in the code, as the reader knows
    /// them.
    constants: Constants,
    /// Whether a name is put back as its constant. Only where a file is
    /// read: a path the reader cannot name is no more than unknown, and a
    /// delete or a write to it is judged as such.
    constants_on: bool,
    /// What the names the code sets to an archive or a config parser stand
    /// for (`TAR`, `ZIP`, `CONFIG`, or more than one): a method call on one
    /// of them reads a file.
    objects: HashMap<String, u8>,
    /// Every name the code binds itself (set, looped over, a parameter, a
    /// function, a class, `as`): a call on one is a method of a value, not a
    /// function of a module.
    bound: HashSet<String>,
    /// The names the code defines as something to call: a function, a class,
    /// or a name set to a `lambda`. Their own calls are read where written.
    callables: HashSet<String>,
    /// The names of the functions the code defines, which a method call on a
    /// value of its own may be (`obj.run()` with a `def run`).
    methods: HashSet<String>,
}

/// `tarfile.open(…)`: `add` reads what it is given.
const TAR: u8 = 1;
/// `zipfile.ZipFile(…)`: `write` reads the file it is given.
const ZIP: u8 = 2;
/// `configparser.ConfigParser()`: `read` reads the files it is given.
const CONFIG: u8 = 4;
/// `pathlib.Path(…)`: its `open` opens the file it names.
const PATH: u8 = 8;

/// What a name stands for in code that has bound nothing: itself, and the
/// `pathlib` classes are `pathlib`'s.
fn fresh(name: &str) -> String {
    if PATHS.contains(&name) {
        format!("pathlib.{name}")
    } else {
        rebase(name)
    }
}

/// The classes of the language whose members the reader models, which an
/// assignment to a member of (`str.join = f`) changes for every value.
const BUILTIN_CLASSES: [&str; 20] = [
    "str",
    "bytes",
    "bytearray",
    "int",
    "float",
    "bool",
    "complex",
    "list",
    "tuple",
    "dict",
    "set",
    "frozenset",
    "object",
    "type",
    "range",
    "property",
    "super",
    "memoryview",
    "slice",
    "enumerate",
];

/// The modules that stand for others without having been imported by name:
/// `os.path` imports `os`.
const HOLDERS: [&str; 4] = ["os.path", "posixpath", "ntpath", "genericpath"];

/// The arguments of a call.
struct Args<'t> {
    positional: Vec<Node<'t>>,
    keywords: Vec<(String, Node<'t>)>,
    /// Whether `*args` or `**kwargs` may stand for any argument.
    splat: bool,
    /// How many positional arguments come before the first `*args` or
    /// `**kwargs`: a path joined from them is only known up to there.
    splat_at: Option<usize>,
    /// Whether a `dir_fd`, `src_dir_fd` or `dst_dir_fd` makes a relative path
    /// count from a directory only known when it runs.
    dir_fd: bool,
}

impl<'t> Args<'t> {
    fn read(call: Node<'t>, src: &str) -> Self {
        let mut args = Self {
            positional: Vec::new(),
            keywords: Vec::new(),
            splat: false,
            splat_at: None,
            dir_fd: false,
        };
        let Some(list) = call.child_by_field_name("arguments") else {
            return args;
        };
        if list.kind() != "argument_list" {
            args.positional.push(list);
            return args;
        }
        let mut cursor = list.walk();
        for child in list.named_children(&mut cursor) {
            match child.kind() {
                "keyword_argument" => {
                    if let (Some(name), Some(value)) = (
                        child.child_by_field_name("name"),
                        child.child_by_field_name("value"),
                    ) {
                        let name = unit::text(&name, src).to_string();
                        args.dir_fd |=
                            matches!(name.as_str(), "dir_fd" | "src_dir_fd" | "dst_dir_fd");
                        args.keywords.push((name, value));
                    }
                }
                "list_splat" | "dictionary_splat" => {
                    args.splat = true;
                    args.splat_at.get_or_insert(args.positional.len());
                }
                "comment" => {}
                _ => args.positional.push(child),
            }
        }
        args
    }

    /// The argument at position `at` or named `name`.
    fn get(&self, at: usize, names: &[&str]) -> Option<Node<'t>> {
        self.positional.get(at).copied().or_else(|| {
            self.keywords
                .iter()
                .find(|(name, _)| names.contains(&name.as_str()))
                .map(|(_, value)| *value)
        })
    }
}

impl<'s> Reader<'s> {
    fn new(
        src: &'s str,
        aliases: HashMap<String, String>,
        modules: HashSet<String>,
        nesting: usize,
    ) -> Self {
        Self {
            src,
            aliases,
            modules,
            names: HashMap::new(),
            walking: false,
            reading: Reading::default(),
            nesting,
            shared: false,
            constants: Constants::default(),
            constants_on: false,
            objects: HashMap::new(),
            bound: HashSet::new(),
            callables: HashSet::new(),
            methods: HashSet::new(),
        }
    }

    /// Note each string a name is set to anywhere in the code, for the reads
    /// of files ([`Self::read_target`]): by an assignment, or by a loop over
    /// strings written out, or a folder it is somewhere under (`for p in
    /// Path(d).glob('*')`). Every string is noted, up to a number of bytes in
    /// all and a length for each ([`Constants`]): a name set to more, or to
    /// a string built from one of those, is dropped, and a read of it is
    /// code the reader does not follow. A name grown in place (`k += …`) is
    /// dropped too. Whatever else the name is set to adds none. The names
    /// the code sets to an archive or a config parser are noted here as well.
    fn collect_constants(&mut self, root: Node<'_>) {
        // Every way a name is bound other than the ones read below as a
        // string it is set to: those names are not worked out whole.
        let mut all = Vec::new();
        let mut loose = Vec::new();
        if self.bindings(root, false, &mut all, &mut loose) {
            self.constants.everything();
        }
        self.bound.extend(all);
        for name in loose {
            self.constants.mark(&name);
        }
        let mut found = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "assignment"
            | "named_expression"
            | "for_statement"
            | "for_in_clause"
            | "augmented_assignment"
            | "as_pattern" => {
                found.push(node);
            }
            _ => {}
        });
        // A name found to be unresolved after a value was worked out from it
        // makes that value stale: the strings are noted again, with it
        // unresolved. Each round marks one more name, so they settle; if they
        // do not within a few, every name is unresolved.
        let mut round = 0;
        loop {
            if round == MAX_ROUNDS {
                self.constants.everything();
            }
            self.constants.start_round();
            self.note_round(&found);
            if !self.constants.stale() || round == MAX_ROUNDS {
                break;
            }
            round += 1;
        }
    }

    /// One round of noting the strings the names are set to ([`Self::collect_constants`]).
    fn note_round(&mut self, found: &[Node<'_>]) {
        self.constants_on = true;
        for &node in found {
            if node.kind() == "as_pattern" {
                // `with tarfile.open(…) as t`.
                let alias = node
                    .child_by_field_name("alias")
                    .and_then(|alias| alias.named_child(0));
                if let (Some(value), Some(alias)) = (node.named_child(0), alias) {
                    self.note_object(value, alias);
                }
                continue;
            }
            let looped = matches!(node.kind(), "for_statement" | "for_in_clause");
            let (name, value) = match node.kind() {
                "named_expression" => (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ),
                _ => (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ),
            };
            let (Some(name), Some(mut value)) = (name, value) else {
                continue;
            };
            if name.kind() != "identifier" {
                continue;
            }
            let target = name;
            let name = self.text(name);
            if node.kind() == "augmented_assignment" {
                // `k += '/id_rsa'`: a string the reader does not work out.
                self.constants.mark(name);
                self.constants.drop_name(name);
                continue;
            }
            // `a = b = 'x'` sets `a` to the string too.
            while value.kind() == "assignment" {
                let Some(next) = value.child_by_field_name("right") else {
                    break;
                };
                value = next;
            }
            if !looped {
                self.note_object(value, target);
            }
            self.constants.lost = false;
            let mut values = Vec::new();
            let mut folder = None;
            // Whether every value the name is set to is a string the reader
            // gives whole (or a folder it stands for a path below).
            let mut whole = true;
            if !looped {
                for parts in self.all_parts(&[value]) {
                    whole &= parts.whole;
                    values.extend(parts.value());
                }
            } else if matches!(value.kind(), "list" | "tuple" | "set") {
                // `for f in ['a', 'b']`: each in turn.
                let mut cursor = value.walk();
                let items: Vec<Node<'_>> = value.named_children(&mut cursor).collect();
                for item in items {
                    if item.kind() == "comment" {
                        continue;
                    }
                    for parts in self.all_parts(&[item]) {
                        whole &= parts.whole;
                        values.extend(parts.value());
                    }
                }
            } else {
                self.constants.begin();
                folder = self.listed_under(value, 0);
                // A folder that is one of several is not one.
                self.constants.lost |= self.constants.pending();
                self.constants.begin();
                whole = folder.is_some();
            }
            if std::mem::take(&mut self.constants.lost) {
                self.constants.mark(name);
                self.constants.drop_name(name);
                continue;
            }
            if !whole {
                self.constants.mark(name);
            }
            for value in values {
                self.constants.note(name, value);
            }
            if let Some(folder) = folder {
                self.constants.note_folder(name, folder);
            }
        }
        self.constants_on = false;
    }

    /// The names a binding pattern sets: `x`, `x, y`, `(x, y)`, `[x, *y]`,
    /// `**kw`, an `as` target. What is assigned to an attribute or an item
    /// binds no name.
    fn pattern_names(&self, node: Node<'_>, out: &mut Vec<String>) {
        match node.kind() {
            "identifier" => out.push(self.text(node).to_string()),
            "typed_parameter" => {
                if let Some(first) = node.named_child(0) {
                    self.pattern_names(first, out);
                }
            }
            "default_parameter" | "typed_default_parameter" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.pattern_names(name, out);
                }
            }
            "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "list_splat_pattern"
            | "dictionary_splat_pattern"
            | "parenthesized_expression"
            | "as_pattern_target"
            | "tuple"
            | "list"
            | "expression_list"
            | "parameters"
            | "delete_statement"
            | "lambda_parameters" => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    self.pattern_names(child, out);
                }
            }
            _ => {}
        }
    }

    /// Every name `root` binds, and, of those, the ones that are not set to
    /// a string the reader can work out whole (`loose`): an unpacking, an
    /// `as`, a parameter, a `def`, a `class`, a `del`, a `case` pattern, and
    /// everything the literal code that `exec` and `eval` run binds, at any
    /// depth, since it runs in this code's names. A name set by plain
    /// assignment, a walrus, a `for` or an augmented assignment is left to
    /// [`Self::note_round`], which reads what it is set to. `nested` is set
    /// for code inside `exec`: there every name is loose. Whether the code
    /// nests too deeply to list them.
    fn bindings(
        &mut self,
        root: Node<'_>,
        nested: bool,
        all: &mut Vec<String>,
        loose: &mut Vec<String>,
    ) -> bool {
        let mut found = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "assignment"
            | "named_expression"
            | "for_statement"
            | "for_in_clause"
            | "augmented_assignment"
            | "as_pattern"
            | "parameters"
            | "lambda_parameters"
            | "function_definition"
            | "class_definition"
            | "delete_statement"
            | "case_pattern"
            | "call"
            | "exec_statement" => {
                found.push(node);
            }
            _ => {}
        });
        let mut deep = false;
        for node in found {
            let mut names = Vec::new();
            // Whether the names are read by `note_round` when they are one
            // identifier.
            let mut read = false;
            match node.kind() {
                "assignment" => {
                    // `x: int` binds nothing.
                    if node.child_by_field_name("right").is_none() {
                        continue;
                    }
                    if let Some(left) = node.child_by_field_name("left") {
                        self.pattern_names(left, &mut names);
                        read = left.kind() == "identifier";
                    }
                    if node
                        .child_by_field_name("right")
                        .is_some_and(|right| right.kind() == "lambda")
                    {
                        self.callables.extend(names.iter().cloned());
                    }
                }
                "named_expression" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        self.pattern_names(name, &mut names);
                        read = true;
                    }
                }
                "for_statement" | "for_in_clause" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        self.pattern_names(left, &mut names);
                        read = left.kind() == "identifier";
                    }
                }
                "augmented_assignment" => {
                    if let Some(left) = node.child_by_field_name("left") {
                        self.pattern_names(left, &mut names);
                        read = true;
                    }
                }
                "as_pattern" => {
                    if let Some(alias) = node.child_by_field_name("alias") {
                        self.pattern_names(alias, &mut names);
                    }
                }
                "parameters" | "lambda_parameters" | "delete_statement" => {
                    self.pattern_names(node, &mut names);
                }
                "function_definition" | "class_definition" => {
                    if let Some(name) = node.child_by_field_name("name") {
                        self.pattern_names(name, &mut names);
                        self.callables.extend(names.iter().cloned());
                        if node.kind() == "function_definition" {
                            self.methods.extend(names.iter().cloned());
                        }
                    }
                }
                "case_pattern" => {
                    // A capture pattern, and a name of a class in one.
                    unit::for_each_node(node, |inner| {
                        if inner.kind() == "identifier" {
                            names.push(self.text(inner).to_string());
                        }
                    });
                }
                "call" | "exec_statement" => {
                    deep |= self.nested_bindings(node, all, loose);
                    continue;
                }
                _ => {}
            }
            all.extend(names.iter().cloned());
            if nested || !read {
                loose.extend(names);
            }
        }
        deep
    }

    /// The names bound by literal code that the call (or Python 2's `exec`
    /// statement) `node` runs in this code's names, at any depth. Whether the
    /// nesting is too deep to list them.
    fn nested_bindings(
        &mut self,
        node: Node<'_>,
        all: &mut Vec<String>,
        loose: &mut Vec<String>,
    ) -> bool {
        let mut code = Vec::new();
        if node.kind() == "exec_statement" {
            code.extend(node.child_by_field_name("code"));
        } else {
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            let args = Args::read(node, self.src);
            let name = self.qualified(function, 0);
            match name.as_deref().and_then(kind) {
                Some(Kind::Eval) => code.extend(args.get(0, &["source", "object"])),
                Some(Kind::Code) => {
                    code.extend(args.get(0, &["stmt", "statement", "command", "expression"]));
                    code.extend(args.get(1, &["setup"]));
                }
                _ => return false,
            }
        }
        let mut deep = false;
        for piece in code {
            if !matches!(piece.kind(), "string" | "concatenated_string") {
                continue;
            }
            let Some(text) = self.value(piece, 0) else {
                continue;
            };
            if self.nesting + 1 >= unit::MAX_DEPTH {
                deep = true;
                continue;
            }
            let translated = translate_newlines(&text);
            let Some(tree) = parse(&translated) else {
                continue;
            };
            let inner_root = tree.root_node();
            if inner_root.has_error() {
                continue;
            }
            let mut inner = Reader::new(
                &translated,
                self.aliases.clone(),
                self.modules.clone(),
                self.nesting + 1,
            );
            let mut inner_all = Vec::new();
            let mut inner_loose = Vec::new();
            deep |= inner.bindings(inner_root, true, &mut inner_all, &mut inner_loose);
            self.callables.extend(inner.callables);
            self.methods.extend(inner.methods);
            // Every name the nested code binds is one of this code's.
            all.extend(inner_all);
            loose.extend(inner_loose);
        }
        deep
    }

    /// `name = tarfile.open(…)`, `with zipfile.ZipFile(…) as name`: `name`
    /// stands for an archive or a config parser, whose methods read files.
    fn note_object(&mut self, value: Node<'_>, name: Node<'_>) {
        if name.kind() != "identifier" {
            return;
        }
        let mut class = 0;
        if self.path_like(value, 0) {
            class |= PATH;
        }
        if value.kind() == "call" {
            if let Some(function) = value.child_by_field_name("function") {
                class |= self.class_of(function);
            }
        }
        if class != 0 {
            *self.objects.entry(self.text(name).to_string()).or_default() |= class;
        }
    }

    /// Whether `node` is a `pathlib` path: `Path(…)`, `Path.home()`, a name
    /// the code set to one, and what a path's own methods and `/` make of it.
    /// A method such as `open` of any other object is not known to open a
    /// file.
    fn path_like(&mut self, node: Node<'_>, level: usize) -> bool {
        if level > 8 {
            return false;
        }
        match node.kind() {
            "parenthesized_expression" => node
                .named_child(0)
                .is_some_and(|inner| self.path_like(inner, level + 1)),
            "identifier" => self
                .objects
                .get(self.text(node))
                .is_some_and(|classes| classes & PATH != 0),
            "call" => {
                let Some(function) = node.child_by_field_name("function") else {
                    return false;
                };
                if self.class_of(function) & PATH != 0 {
                    return true;
                }
                let method = function
                    .child_by_field_name("attribute")
                    .map(|attribute| self.text(attribute));
                let object = function.child_by_field_name("object");
                match (method, object) {
                    (
                        Some(
                            "joinpath" | "with_name" | "with_suffix" | "with_stem" | "resolve"
                            | "absolute" | "expanduser",
                        ),
                        Some(object),
                    ) => self.path_like(object, level + 1),
                    _ => false,
                }
            }
            "binary_operator" => {
                let slash = node
                    .child_by_field_name("operator")
                    .is_some_and(|operator| self.text(operator) == "/");
                slash
                    && node
                        .child_by_field_name("left")
                        .is_some_and(|left| self.path_like(left, level + 1))
            }
            "attribute" => {
                node.child_by_field_name("attribute")
                    .is_some_and(|attribute| self.text(attribute) == "parent")
                    && node
                        .child_by_field_name("object")
                        .is_some_and(|object| self.path_like(object, level + 1))
            }
            _ => false,
        }
    }

    /// What the call of `function` makes: `TAR`, `ZIP`, `CONFIG`, `PATH`, or
    /// none.
    fn class_of(&mut self, function: Node<'_>) -> u8 {
        match self.qualified(function, 0).as_deref() {
            Some(
                "pathlib.Path"
                | "pathlib.PurePath"
                | "pathlib.PosixPath"
                | "pathlib.PurePosixPath"
                | "pathlib.Path.home"
                | "pathlib.Path.cwd",
            ) => PATH,
            Some("tarfile.open") => TAR,
            Some(name) if name.starts_with("tarfile.TarFile") => TAR,
            Some("zipfile.ZipFile" | "zipfile.PyZipFile") => ZIP,
            Some(
                "configparser.ConfigParser"
                | "configparser.RawConfigParser"
                | "configparser.SafeConfigParser"
                | "ConfigParser.ConfigParser"
                | "ConfigParser.RawConfigParser"
                | "ConfigParser.SafeConfigParser",
            ) => CONFIG,
            _ => 0,
        }
    }

    /// Whether `receiver` is an archive or a config parser of the `class`.
    fn is_object(&mut self, receiver: Node<'_>, class: u8) -> bool {
        match receiver.kind() {
            "identifier" => self
                .objects
                .get(self.text(receiver))
                .is_some_and(|classes| classes & class != 0),
            "call" => receiver
                .child_by_field_name("function")
                .is_some_and(|function| self.class_of(function) & class != 0),
            _ => false,
        }
    }

    /// The folder that what `node` lists is under, when the code gives it:
    /// `Path(d).glob(…)`, `.rglob(…)`, `.iterdir()` and `glob.glob(d + '/*')`
    /// list paths that start with it, so a name a loop sets to each is a path
    /// somewhere below the folder. `sorted(…)`, `list(…)` and the like are
    /// looked through.
    fn listed_under(&mut self, node: Node<'_>, level: usize) -> Option<String> {
        if level > 8 || node.kind() != "call" {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        let args = Args::read(node, self.src);
        let name = self.qualified(function, 0);
        match name.as_deref() {
            Some("sorted" | "list" | "tuple" | "set" | "reversed" | "iter" | "enumerate") => {
                let inner = args.positional.first().copied()?;
                return self.listed_under(inner, level + 1);
            }
            Some("glob.glob" | "glob.iglob") => {
                let pattern = args.get(0, &["pathname"])?;
                let parts = self.parts(pattern, 0);
                let end = parts.text.rfind('/')? + 1;
                return Some(parts.text[..end].to_string());
            }
            _ => {}
        }
        let method = function.child_by_field_name("attribute")?;
        if !matches!(self.text(method), "glob" | "rglob" | "iterdir") {
            return None;
        }
        let receiver = function.child_by_field_name("object")?;
        let parts = self.parts(receiver, 0);
        let end = parts.text.rfind('/').map_or(0, |at| at + 1);
        match parts.whole {
            // The folder itself.
            true if parts.text.ends_with('/') => Some(parts.text),
            true => Some(format!("{}/", parts.text)),
            false if end > 0 => Some(parts.text[..end].to_string()),
            false => None,
        }
    }

    /// The paths the argument at `at` of a call that reads a file may name:
    /// a name the code sets to a string is read as each string it is set
    /// to.
    fn read_target(&mut self, args: &Args<'_>, at: usize, names: &[&str]) -> Vec<Arg> {
        match args.get(at, names) {
            Some(node) if !args.dir_fd => self.read_arg(node),
            _ => self.target(args, at, names).into_iter().collect(),
        }
    }

    /// `node`, the argument or the object a file method is called on, as the
    /// paths to read (see [`Self::read_target`]).
    fn read_arg(&mut self, node: Node<'_>) -> Vec<Arg> {
        self.read_nodes(&[node])
    }

    /// The paths the join of `nodes` (one, or a root and what is under it)
    /// may name, as a read takes them: each string a name is set to; the
    /// start a path is known to have, as the folder it is under, when the
    /// rest is only known when the code runs; and a path the reader does not
    /// follow, besides, when it was worked out from a name it dropped.
    fn read_nodes(&mut self, nodes: &[Node<'_>]) -> Vec<Arg> {
        let Some(first) = nodes.first().copied() else {
            return Vec::new();
        };
        let text = self.text(first);
        if let [node] = nodes {
            if node.kind() == "identifier" {
                match self.constants.paths(text, text) {
                    Expansion::Paths(paths) => return paths,
                    Expansion::Lost => {
                        self.reading.unread(text);
                        return Vec::new();
                    }
                    Expansion::Nothing => {}
                }
            }
        }
        self.constants_on = true;
        self.constants.lost = false;
        let all = self.all_parts(nodes);
        self.constants_on = false;
        let mut args: Vec<Arg> = Vec::new();
        for parts in all {
            let arg = read_path(parts, text);
            if !args.contains(&arg) {
                args.push(arg);
            }
        }
        if !self.constants.spend(args.len()) {
            self.constants.lost = true;
            args.clear();
        }
        if std::mem::take(&mut self.constants.lost) {
            self.reading.unread(text);
        }
        args
    }

    /// The join of `nodes` as far as the code gives it, once for each choice
    /// of one string for each name in it that holds more than one (`for n in
    /// ['a', 'b']`). Where names are put back as their strings.
    fn all_parts(&mut self, nodes: &[Node<'_>]) -> Vec<Parts> {
        self.constants.begin();
        let mut found: Vec<Parts> = Vec::new();
        loop {
            let parts = self.joined(String::new(), nodes, 0);
            let seen = found
                .iter()
                .any(|other| other.text == parts.text && other.whole == parts.whole);
            if !self.constants.pending() && !seen {
                found.push(parts);
            }
            if !self.constants.advance() {
                break;
            }
        }
        self.constants.begin();
        if found.is_empty() {
            found.push(Parts::unknown());
        }
        found
    }

    /// The files a call reads, given as one path or a list of them
    /// (`ConfigParser.read`, `fileinput.input`).
    fn read_files(&mut self, node: Node<'_>) -> Vec<Arg> {
        if !matches!(node.kind(), "list" | "tuple") {
            return self.read_arg(node);
        }
        let mut cursor = node.walk();
        let items: Vec<Node<'_>> = node
            .named_children(&mut cursor)
            .filter(|item| !matches!(item.kind(), "comment" | "list_splat"))
            .collect();
        items
            .into_iter()
            .flat_map(|item| self.read_arg(item))
            .collect()
    }

    /// Read every node under `root`, once the names `import` bound are
    /// known. The walk stops once the code is found to nest too deeply to
    /// read: the line is unreadable whatever else is in it.
    fn walk_all(&mut self, root: Node<'_>) {
        self.collect_constants(root);
        self.walking = true;
        walk(root, |node, field, above| {
            // Python reads a name in its NFKC form (`ｒｅｍｏｖｅ` is `remove`),
            // which the reader does not compute: a name that is not ASCII is
            // a name it does not follow.
            if node.kind() == "identifier" && !self.text(node).is_ascii() {
                self.reading.unread(self.text(node));
            }
            match node.kind() {
                "import_statement" | "import_from_statement" | "assignment" => {
                    self.class_binding(node, above);
                }
                "call" => self.call(node, field, above),
                "attribute" | "identifier" => self.reference(node, field, above),
                "subscript" => self.subscript(node),
                "decorator" => self.decorator(node),
                "exec_statement" => self.exec_statement(node),
                _ => {}
            }
            if matches!(node.kind(), "assignment" | "augmented_assignment") {
                self.sys_path_assignment(node);
            }
            if matches!(
                node.kind(),
                "assignment"
                    | "augmented_assignment"
                    | "for_statement"
                    | "for_in_clause"
                    | "as_pattern"
            ) {
                self.member_assignment(node);
            }
            !self.reading.deep
        });
    }

    fn text(&self, node: Node<'_>) -> &'s str {
        unit::text(&node, self.src)
    }

    /// What a name stands for in this code: what `import` bound it to, or
    /// itself.
    fn resolve(&self, name: &str) -> String {
        self.aliases
            .get(name)
            .map_or_else(|| fresh(name), |value| rebase(value))
    }

    /// Whether literal code that `exec`, `eval` or a profiler runs shares
    /// names with this code, in a way the reader would not see: the code runs
    /// in this code's namespace, so a name it binds is a name here
    /// (`exec("import shutil as j")`, then `j.rmtree(…)`), and a name this
    /// code bound is one there (`import shutil as s`, then `exec("s.rmtree(…)")`
    /// ). The nested code is read apart, from a table of its own. So when it
    /// binds a name to what the reader follows other than the name stands
    /// for here, or uses a name bound here to such a thing, the line is not
    /// read. The same is asked of the code inside the nested code, at any
    /// depth; past the depth that can be read, it is yes.
    fn shares_names(&mut self, text: &str) -> bool {
        if self.nesting >= unit::MAX_DEPTH {
            return true;
        }
        let translated = translate_newlines(text);
        let Some(tree) = parse(&translated) else {
            return false;
        };
        let root = tree.root_node();
        // Code that does not parse raises before it runs a thing.
        if root.has_error() {
            return false;
        }
        let mut inner = Reader::new(
            &translated,
            self.aliases.clone(),
            self.modules.clone(),
            self.nesting + 1,
        );
        inner.collect_imports(root);
        // A name bound again to something else the reader follows is one
        // `bind` has already marked unread in the inner reading.
        let mut shares = inner.reading.deep
            || !inner.reading.acts.is_empty()
            || inner
                .aliases
                .iter()
                .any(|(name, value)| rebase(value) != self.resolve(name) && inner.followed(value));
        walk(root, |node, field, _| {
            if node.kind() == "identifier" && field != Some("attribute") {
                let name = self.text_of(node, &translated);
                if let Some(value) = self.aliases.get(name) {
                    shares |= self.resolve(name) != fresh(name) && self.followed(value);
                }
            }
            !shares
        });
        if !shares {
            inner.walk_all(root);
            shares = inner.shared;
        }
        shares
    }

    /// The text of `node` in `src`, which is not the code this reader holds.
    fn text_of<'a>(&self, node: Node<'_>, src: &'a str) -> &'a str {
        unit::text(&node, src)
    }

    /// Note literal code `exec`, `eval` or a profiler runs, which `call` is
    /// the call of: when it shares names with this code, the line is unread.
    fn literal_code(&mut self, text: String, call: Node<'_>) {
        if self.shares_names(&text) {
            self.shared = true;
            self.reading.unread(self.text(call));
        }
        self.reading.acts.push(Act::Code(Language::Python, text));
    }

    fn collect_imports(&mut self, root: Node<'_>) {
        let mut found = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "import_statement" | "import_from_statement" | "assignment" | "named_expression" => {
                found.push(node);
            }
            _ => {}
        });
        for node in found {
            // `o = os`, `m = __import__('os')`: a name for a module or call;
            // also `(o := os)`.
            if matches!(node.kind(), "assignment" | "named_expression") {
                let (left, right) = if node.kind() == "assignment" {
                    (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    )
                } else {
                    (
                        node.child_by_field_name("name"),
                        node.child_by_field_name("value"),
                    )
                };
                if let (Some(left), Some(right)) = (left, right) {
                    if left.kind() == "identifier" {
                        if let Some(name) = self.qualified(right, 0) {
                            self.bind(self.text(left), name, node);
                        }
                    }
                }
                continue;
            }
            let mut cursor = node.walk();
            if node.kind() == "import_statement" {
                for name in node.children_by_field_name("name", &mut cursor) {
                    if name.kind() == "aliased_import" {
                        if let (Some(real), Some(alias)) = (
                            name.child_by_field_name("name"),
                            name.child_by_field_name("alias"),
                        ) {
                            self.bind(self.text(alias), self.text(real).to_string(), node);
                            self.modules.insert(self.text(real).to_string());
                        }
                    } else {
                        // `import a.b.c` binds `a`.
                        let text = self.text(name);
                        let first = text.split('.').next().unwrap_or(text);
                        self.bind(first, first.to_string(), node);
                        self.modules.insert(first.to_string());
                    }
                }
                continue;
            }
            let Some(module) = node.child_by_field_name("module_name") else {
                continue;
            };
            let module = self.text(module).to_string();
            if node
                .children(&mut cursor)
                .any(|child| child.kind() == "wildcard_import")
            {
                self.star_import(&module);
            }
            let mut cursor = node.walk();
            for name in node.children_by_field_name("name", &mut cursor) {
                let (real, alias) = if name.kind() == "aliased_import" {
                    (
                        name.child_by_field_name("name"),
                        name.child_by_field_name("alias"),
                    )
                } else {
                    (Some(name), Some(name))
                };
                if let (Some(real), Some(alias)) = (real, alias) {
                    self.bind(
                        self.text(alias),
                        format!("{module}.{}", self.text(real)),
                        node,
                    );
                }
            }
        }
    }

    /// Record that `name` stands for `value`. A name is one thing in the
    /// reader's table wherever and however often it is written, so a name
    /// bound again to something else (`import os`, then `if 0: import json as
    /// os`; a binding in a function that is never called) is a name the
    /// reader cannot follow, when either of the two is one it looks for:
    /// the line is unread.
    fn bind(&mut self, name: &str, value: String, at: Node<'_>) {
        if let Some(before) = self.aliases.get(name) {
            if *before != value && (self.followed(before) || self.followed(&value)) {
                self.reading.unread(self.text(at));
            }
        }
        self.aliases.insert(name.to_string(), value);
    }

    /// Whether `name`, a dotted name the reader found, is one it reads calls
    /// by: a call it knows, or a module or one of its members.
    fn followed(&self, name: &str) -> bool {
        let rebased = rebase(name);
        let first = rebased.split('.').next().unwrap_or(&rebased);
        kind(&rebased).is_some()
            || module_named(first).is_some()
            || self.is_module(first)
            || self.is_module(&rebased)
            || HOLDERS.contains(&first)
            || PATHS.contains(&first)
            || rebased.starts_with("pathlib.")
    }

    /// `from os import *` makes every name in `os` a bare one.
    fn star_import(&mut self, module: &str) {
        const MODULES: [&str; 8] = [
            "os",
            "shutil",
            "subprocess",
            "pathlib",
            "io",
            "codecs",
            "pty",
            "fileinput",
        ];
        if !MODULES.contains(&module) {
            return;
        }
        for name in [
            "remove",
            "unlink",
            "rmdir",
            "removedirs",
            "rename",
            "replace",
            "renames",
            "symlink",
            "link",
            "truncate",
            "mkdir",
            "makedirs",
            "mkfifo",
            "chmod",
            "lchmod",
            "chown",
            "lchown",
            "chdir",
            "system",
            "popen",
            "open",
            "rmtree",
            "copy",
            "copy2",
            "copyfile",
            "copytree",
            "move",
            "make_archive",
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "getoutput",
            "getstatusoutput",
            "spawn",
            "execv",
            "execvp",
            "Path",
            "PurePath",
            "copymode",
            "copystat",
            "kill",
            "killpg",
            "input",
            "FileInput",
        ] {
            let qualified = format!("{module}.{name}");
            if kind(&qualified).is_some() || qualified.starts_with("pathlib.") {
                self.aliases.insert(name.to_string(), qualified);
            }
        }
    }

    /// The dotted name `node` stands for, once the names `import` bound are
    /// put back: `shutil.rmtree`, `os.path.join`. `None` for what is not a
    /// name.
    fn qualified(&mut self, node: Node<'_>, level: usize) -> Option<String> {
        if level > MAX_TREE_DEPTH {
            self.reading.deep = true;
            return None;
        }
        if self.walking {
            if let Some(known) = self.names.get(&node.id()) {
                return known.clone();
            }
        }
        let name = self.name(node, level);
        if self.walking && !self.reading.deep {
            self.names.insert(node.id(), name.clone());
        }
        name
    }

    fn name(&mut self, node: Node<'_>, level: usize) -> Option<String> {
        match node.kind() {
            "identifier" => {
                let name = self.text(node);
                Some(rebase(&self.aliases.get(name).cloned().unwrap_or_else(
                    || {
                        if PATHS.contains(&name) {
                            format!("pathlib.{name}")
                        } else {
                            name.to_string()
                        }
                    },
                )))
            }
            "attribute" => {
                let object = node.child_by_field_name("object")?;
                let attribute = node.child_by_field_name("attribute")?;
                let object = self.qualified(object, level + 1)?;
                Some(extend(&object, self.text(attribute)))
            }
            "parenthesized_expression" => {
                let inner = node.named_child(0)?;
                self.qualified(inner, level + 1)
            }
            // `a = b = os`: `a` is `os` too.
            "assignment" => {
                let right = node.child_by_field_name("right")?;
                self.qualified(right, level + 1)
            }
            "call" => self.qualified_call(node, level),
            _ => None,
        }
    }

    /// `__import__('os')` is `os`, `getattr(os, 'remove')` is `os.remove`:
    /// with a literal name they are the name.
    fn qualified_call(&mut self, call: Node<'_>, level: usize) -> Option<String> {
        let function = call.child_by_field_name("function")?;
        let name = self.qualified(function, level + 1)?;
        let args = Args::read(call, self.src);
        match kind(&name)? {
            Kind::Import => {
                let module = args.get(0, &["name"])?;
                let mut module = self.value(module, level + 1)?;
                // `__import__('os.path')` is `os`, the top package, unless a
                // `fromlist` is given and is not empty; `import_module` gives
                // the module it names.
                if !name.ends_with("import_module") && module.contains('.') {
                    if args.splat {
                        return None;
                    }
                    let whole = match args.get(3, &["fromlist"]) {
                        None => false,
                        Some(list) => match list.kind() {
                            "none" => false,
                            "list" | "tuple" => {
                                let mut cursor = list.walk();
                                let items = list
                                    .named_children(&mut cursor)
                                    .filter(|item| item.kind() != "comment")
                                    .count();
                                items > 0
                            }
                            _ => return None,
                        },
                    };
                    if !whole {
                        module.truncate(module.find('.').unwrap_or(module.len()));
                    }
                }
                self.modules.insert(module.clone());
                Some(module)
            }
            Kind::Getattr => {
                let object = args.positional.first().copied()?;
                let attribute = args.get(1, &["name"])?;
                let object = self.qualified(object, level + 1)?;
                Some(rebase(&format!(
                    "{object}.{}",
                    self.value(attribute, level + 1)?
                )))
            }
            _ => None,
        }
    }

    /// The text of a string, a path, or a join of them, when the code gives
    /// it; `None` when it is only known when it runs.
    fn value(&mut self, node: Node<'_>, level: usize) -> Option<String> {
        self.parts(node, level).value()
    }

    /// The text of a string, a path, or a join of them, as far as the code
    /// gives it: all of it, or the start it is known to have (see
    /// [`Parts`]). Where names are put back as their strings, one longer than
    /// [`super::MAX_STRING`] is not known.
    fn parts(&mut self, node: Node<'_>, level: usize) -> Parts {
        let parts = self.parts_of(node, level);
        if self.constants_on && parts.text.len() > super::MAX_STRING {
            self.constants.lost = true;
            return Parts::unknown();
        }
        parts
    }

    fn parts_of(&mut self, node: Node<'_>, level: usize) -> Parts {
        if level > MAX_TREE_DEPTH {
            self.reading.deep = true;
            return Parts::unknown();
        }
        match node.kind() {
            "string" => self.string(node, level),
            "concatenated_string" => {
                let mut cursor = node.walk();
                let items: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                let mut text = String::new();
                for item in items {
                    let part = self.parts(item, level + 1);
                    text.push_str(&part.text);
                    if !part.whole {
                        return Parts::partial(text);
                    }
                }
                Parts::whole(text)
            }
            "parenthesized_expression" => match node.named_child(0) {
                Some(inner) => self.parts(inner, level + 1),
                None => Parts::unknown(),
            },
            "binary_operator" => {
                let (Some(left), Some(right), Some(operator)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                    node.child_by_field_name("operator"),
                ) else {
                    return Parts::unknown();
                };
                let operator = self.text(operator);
                let left = self.parts(left, level + 1);
                if !left.whole {
                    return if matches!(operator, "+" | "/") {
                        left
                    } else {
                        Parts::unknown()
                    };
                }
                let right = self.parts(right, level + 1);
                match operator {
                    "+" => Parts {
                        text: format!("{}{}", left.text, right.text),
                        whole: right.whole,
                    },
                    "/" => Parts {
                        text: join(&left.text, &right.text),
                        whole: right.whole,
                    },
                    // `'/home/me/.ssh/%s' % name`: the text before the first
                    // conversion.
                    "%" => match left.text.find('%') {
                        Some(at) => Parts::partial(left.text[..at].to_string()),
                        None => Parts::unknown(),
                    },
                    _ => Parts::unknown(),
                }
            }
            "call" => self.parts_of_call(node, level),
            "identifier" if self.constants_on => match self.constants.holds(self.text(node)) {
                Holds::One(text) => Parts::whole(text),
                Holds::Below(folder) => Parts::partial(folder),
                Holds::Nothing | Holds::Lost => Parts::unknown(),
            },
            "attribute" => {
                let (Some(object), Some(attribute)) = (
                    node.child_by_field_name("object"),
                    node.child_by_field_name("attribute"),
                ) else {
                    return Parts::unknown();
                };
                if self.text(attribute) == "parent" {
                    match self.value(object, level + 1) {
                        Some(object) => Parts::whole(join(&object, "..")),
                        None => Parts::unknown(),
                    }
                } else {
                    Parts::unknown()
                }
            }
            "subscript" => {
                let (Some(object), Some(index)) = (
                    node.child_by_field_name("value"),
                    node.child_by_field_name("subscript"),
                ) else {
                    return Parts::unknown();
                };
                if self.qualified(object, level + 1).as_deref() == Some("os.environ") {
                    self.value(index, level + 1)
                        .and_then(|name| environment(&name))
                        .map_or_else(Parts::unknown, Parts::whole)
                } else {
                    Parts::unknown()
                }
            }
            _ => Parts::unknown(),
        }
    }

    /// `first`, then each of `nodes`, joined as `os.path.join` does: the
    /// start known when one of them is only known when the code runs.
    fn joined(&mut self, first: String, nodes: &[Node<'_>], level: usize) -> Parts {
        let mut text = first;
        for node in nodes {
            let part = self.parts(*node, level + 1);
            text = join(&text, &part.text);
            if self.constants.over(self.constants_on, &text) {
                return Parts::unknown();
            }
            if !part.whole {
                return Parts::partial(text);
            }
        }
        Parts::whole(text)
    }

    /// `first`, then the positional arguments of a call, joined as
    /// `os.path.join` does. A `*args` or `**kwargs` among them may add any
    /// parts, so the path is known only up to it.
    fn joined_args(&mut self, first: String, args: &Args<'_>, level: usize) -> Parts {
        let known = args.splat_at.unwrap_or(args.positional.len());
        let parts = self.joined(first, args.positional.get(..known).unwrap_or(&[]), level);
        if args.splat_at.is_some() && parts.whole {
            return Parts::partial(join(&parts.text, ""));
        }
        parts
    }

    /// A string literal: escapes read, an f-string's plain `{…}` parts put
    /// in.
    fn string(&mut self, node: Node<'_>, level: usize) -> Parts {
        let mut cursor = node.walk();
        let parts: Vec<Node<'_>> = node.children(&mut cursor).collect();
        let prefix = parts
            .iter()
            .find(|part| part.kind() == "string_start")
            .map(|start| self.text(*start).to_ascii_lowercase())
            .unwrap_or_default();
        let raw = prefix.contains('r');
        let format = prefix.contains('f');
        let mut text = String::new();
        for part in parts {
            match part.kind() {
                "string_content" => {
                    let content = self.text(part);
                    // An escape the reader does not decode makes the string
                    // one only known when it runs, never a guess.
                    let Some(content) = (if raw {
                        Some(content.to_string())
                    } else {
                        unescape(content)
                    }) else {
                        return Parts::partial(text);
                    };
                    text.push_str(&if format {
                        content.replace("{{", "{").replace("}}", "}")
                    } else {
                        content
                    });
                }
                "interpolation" => {
                    let mut inner = part.walk();
                    if part.children(&mut inner).any(|child| {
                        matches!(child.kind(), "type_conversion" | "format_specifier" | "=")
                    }) {
                        return Parts::partial(text);
                    }
                    let Some(expression) = part.child_by_field_name("expression") else {
                        return Parts::partial(text);
                    };
                    let value = self.parts(expression, level + 1);
                    text.push_str(&value.text);
                    if self.constants.over(self.constants_on, &text) {
                        return Parts::unknown();
                    }
                    if !value.whole {
                        return Parts::partial(text);
                    }
                }
                _ => {}
            }
        }
        Parts::whole(text)
    }

    fn parts_of_call(&mut self, call: Node<'_>, level: usize) -> Parts {
        let Some(function) = call.child_by_field_name("function") else {
            return Parts::unknown();
        };
        let args = Args::read(call, self.src);
        let name = self.qualified(function, level + 1);
        let first = |reader: &mut Self| match args.positional.first().copied() {
            Some(node) => reader.parts(node, level + 1),
            None => Parts::unknown(),
        };
        let whole = |text: &str| Parts::whole(text.to_string());
        match name.as_deref() {
            Some(
                "pathlib.Path" | "pathlib.PurePath" | "pathlib.PosixPath" | "pathlib.PurePosixPath",
            ) => {
                let parts = self.joined_args(String::new(), &args, level);
                if parts.whole && parts.text.is_empty() {
                    whole(".")
                } else {
                    parts
                }
            }
            Some("pathlib.Path.home" | "pathlib.PurePath.home") => whole("~"),
            Some("pathlib.Path.cwd" | "os.getcwd" | "os.curdir") => whole("."),
            Some(
                "os.path.expanduser" | "os.path.abspath" | "os.path.normpath" | "os.path.realpath"
                | "os.fspath" | "os.fsdecode" | "str",
            ) => first(self),
            Some("os.path.expandvars") => {
                let Some(text) = first(self).value() else {
                    return Parts::unknown();
                };
                let expanded = if let Some(rest) = text
                    .strip_prefix("$HOME")
                    .or_else(|| text.strip_prefix("${HOME}"))
                {
                    (!rest.contains('$')).then(|| format!("~{rest}"))
                } else {
                    (!text.contains(['$', '%'])).then_some(text)
                };
                expanded.map_or_else(Parts::unknown, Parts::whole)
            }
            Some("os.path.join") => self.joined_args(String::new(), &args, level),
            Some("os.path.dirname") => first(self)
                .value()
                .map_or_else(Parts::unknown, |text| Parts::whole(join(&text, ".."))),
            Some("os.environ.get" | "os.getenv") => first(self)
                .value()
                .and_then(|name| environment(&name))
                .map_or_else(Parts::unknown, Parts::whole),
            Some("tempfile.gettempdir") => whole("/tmp"),
            Some("tempfile.mkdtemp") => whole("/tmp/x"),
            _ => {
                let (Some(attribute), Some(receiver)) = (
                    function.child_by_field_name("attribute"),
                    function.child_by_field_name("object"),
                ) else {
                    return Parts::unknown();
                };
                let literal = matches!(receiver.kind(), "string" | "concatenated_string");
                match self.text(attribute) {
                    "expanduser" | "resolve" | "absolute" => self.parts(receiver, level + 1),
                    "joinpath" => {
                        let start = self.parts(receiver, level + 1);
                        if !start.whole {
                            return start;
                        }
                        self.joined_args(start.text, &args, level)
                    }
                    "with_name" => {
                        let Some(parent) = self.value(receiver, level + 1) else {
                            return Parts::unknown();
                        };
                        let parent = join(&parent, "..");
                        match args.positional.first().copied() {
                            Some(node) => {
                                let name = self.parts(node, level + 1);
                                Parts {
                                    text: join(&parent, &name.text),
                                    whole: name.whole,
                                }
                            }
                            None => Parts::unknown(),
                        }
                    }
                    // `'/home/me/.ssh/{}'.format(name)`: the text before the
                    // first field.
                    "format" if literal => {
                        let template = self.parts(receiver, level + 1);
                        match (template.whole, template.text.find('{')) {
                            (true, Some(at)) => Parts::partial(template.text[..at].to_string()),
                            (true, None) => template,
                            (false, _) => Parts::unknown(),
                        }
                    }
                    // `'/'.join(['/home/me/.ssh', name])`.
                    "join" if literal => {
                        let separator = self.parts(receiver, level + 1);
                        let list = args
                            .positional
                            .first()
                            .copied()
                            .filter(|list| matches!(list.kind(), "list" | "tuple"));
                        let (true, Some(list)) = (separator.whole, list) else {
                            return Parts::unknown();
                        };
                        let mut cursor = list.walk();
                        let items: Vec<Node<'_>> = list
                            .named_children(&mut cursor)
                            .filter(|item| item.kind() != "comment")
                            .collect();
                        let mut text = String::new();
                        for (at, item) in items.into_iter().enumerate() {
                            if at > 0 {
                                text.push_str(&separator.text);
                            }
                            let part = self.parts(item, level + 1);
                            text.push_str(&part.text);
                            if self.constants.over(self.constants_on, &text) {
                                return Parts::unknown();
                            }
                            if !part.whole {
                                return Parts::partial(text);
                            }
                        }
                        Parts::whole(text)
                    }
                    _ => Parts::unknown(),
                }
            }
        }
    }

    /// An argument as the rules take a path: its text, or what it is made of
    /// when only known when it runs.
    fn arg(&mut self, node: Node<'_>) -> Arg {
        let value = self.value(node, 0);
        path(value, self.text(node))
    }

    /// The path argument at `at` or named `names`; unknown when `*args`
    /// may hold it, and `None` when the call has none.
    fn target(&mut self, args: &Args<'_>, at: usize, names: &[&str]) -> Option<Arg> {
        match args.get(at, names) {
            // A path counted from a directory handle is only known when it
            // runs.
            Some(node) if args.dir_fd => Some(Arg::Unknown(super::shorten(self.text(node)))),
            Some(node) => Some(self.arg(node)),
            None if args.splat => Some(Arg::Unknown("*args".to_string())),
            None => None,
        }
    }

    fn act(&mut self, act: Option<Act>) {
        self.reading.acts.extend(act);
    }

    fn call<'t>(&mut self, call: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) {
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let args = Args::read(call, self.src);
        let name = self.qualified(function, 0);
        let kind = name.as_deref().and_then(kind);
        // What starts a program is run from where `cwd` says.
        let before = self.reading.acts.len();
        match kind {
            Some(Kind::Remove) => {
                let target = self.target(&args, 0, &["path"]);
                self.act(target.map(Act::Remove));
            }
            Some(Kind::Copy) => {
                // The source of a copy is read, unless it is a URL.
                if !matches!(
                    name.as_deref(),
                    Some("urllib.request.urlretrieve" | "wget.download")
                ) {
                    // `copytree` reads a folder and all that is in it.
                    let tree = name.as_deref() == Some("shutil.copytree");
                    for source in self.read_target(&args, 0, &["src", "fsrc"]) {
                        self.reading.acts.push(if tree {
                            Act::ReadTree(source)
                        } else {
                            Act::Read(source)
                        });
                    }
                }
                let target = self.target(&args, 1, &["dst", "extract_dir", "filename", "out"]);
                self.act(target.map(Act::Write));
            }
            Some(Kind::Archive) => {
                let target = self.target(&args, 0, &["base_name"]);
                self.act(target.map(Act::Write));
                let nodes: Vec<Node<'t>> = [args.get(2, &["root_dir"]), args.get(3, &["base_dir"])]
                    .into_iter()
                    .flatten()
                    .collect();
                for source in self.read_nodes(&nodes) {
                    self.reading.acts.push(Act::ReadTree(source));
                }
            }
            Some(Kind::ReadFile) => {
                for source in self.read_target(&args, 0, &["filename"]) {
                    self.reading.acts.push(Act::Read(source));
                }
            }
            Some(Kind::NetRc) => {
                // No file is `~/.netrc`.
                let file = args
                    .get(0, &["file"])
                    .filter(|node| self.text(*node) != "None");
                let sources = match file {
                    Some(node) => self.read_arg(node),
                    None if args.splat => Vec::new(),
                    None => vec![Arg::Known("~/.netrc".to_string())],
                };
                for source in sources {
                    self.reading.acts.push(Act::Read(source));
                }
            }
            Some(Kind::Move) => {
                let from = self.target(&args, 0, &["src", "old"]);
                let to = self.target(&args, 1, &["dst", "new"]);
                self.act(from.zip(to).map(|(from, to)| Act::Move { from, to }));
            }
            Some(Kind::Link) => {
                let target = self.target(&args, 0, &["src"]);
                let link = self.target(&args, 1, &["dst"]);
                self.act(
                    target
                        .zip(link)
                        .map(|(target, link)| Act::Link { target, link }),
                );
            }
            Some(Kind::Write) => {
                let target = self.target(&args, 0, &["path", "base_name", "database"]);
                let memory = target.as_ref().and_then(Arg::known) == Some(":memory:");
                self.act(target.filter(|_| !memory).map(Act::Write));
            }
            Some(Kind::Chmod) => {
                let path = self.target(&args, 0, &["path"]);
                let mode = self.mode(&args, 1);
                self.act(path.map(|path| Act::Chmod { path, mode }));
            }
            Some(Kind::CopyMode) => {
                let path = self.target(&args, 1, &["dst"]);
                let mode = Arg::Unknown("the mode of another file".to_string());
                self.act(path.map(|path| Act::Chmod { path, mode }));
            }
            Some(Kind::FileInput) => self.file_input(&args, call),
            Some(Kind::Kill) => match args.get(0, &["pid", "pgid"]) {
                // `*args` may hold the process id, or come before it.
                _ if args.splat => self.reading.unread(self.text(call)),
                Some(node) => {
                    let pid = self.text(node);
                    self.reading.acts.push(super::kill(pid));
                }
                None => {}
            },
            Some(Kind::Chown) => {
                let target = self.target(&args, 0, &["path"]);
                self.act(target.map(Act::Chown));
            }
            Some(Kind::Chdir) => {
                let target = self.target(&args, 0, &["path"]);
                self.act(target.map(Act::Chdir));
            }
            Some(Kind::Fchdir) => {
                self.act(Some(Act::Chdir(Arg::Unknown(super::shorten(
                    self.text(call),
                )))));
            }
            Some(Kind::Code) => {
                let setup = name
                    .as_deref()
                    .is_some_and(|name| name.starts_with("timeit."));
                self.runs_code(&args, call, setup);
            }
            Some(Kind::Open) => {
                // No mode reads; a mode only known when it runs may write.
                let writes_file = match args.get(1, &["mode"]) {
                    Some(node) => self.value(node, 0).is_none_or(|mode| writes(Some(&mode))),
                    None => args.splat,
                };
                if writes_file {
                    let target = self.target(&args, 0, &["file", "filename", "name"]);
                    self.act(target.map(Act::Write));
                } else {
                    for source in self.read_target(&args, 0, &["file", "filename", "name"]) {
                        self.reading.acts.push(Act::Read(source));
                    }
                }
            }
            Some(Kind::OsOpen) => {
                let flags = args.get(1, &["flags"]);
                let reads = flags.is_some_and(|flags| {
                    self.text(flags) == "0"
                        || self.qualified(flags, 0).as_deref() == Some("os.O_RDONLY")
                });
                if reads {
                    for source in self.read_target(&args, 0, &["path"]) {
                        self.reading.acts.push(Act::Read(source));
                    }
                } else {
                    let target = self.target(&args, 0, &["path"]);
                    self.act(target.map(Act::Write));
                }
            }
            Some(Kind::Script) => {
                let command = self.target(&args, 0, &["command", "cmd"]);
                self.act(command.map(Act::Script));
            }
            Some(Kind::Subprocess) => self.subprocess(&args),
            Some(Kind::Exec) => {
                let words: Vec<Arg> = args
                    .positional
                    .clone()
                    .into_iter()
                    .map(|node| self.arg(node))
                    .collect();
                self.act(Some(Act::Program(words)));
            }
            Some(Kind::Unread) => self.reading.unread(self.text(call)),
            Some(Kind::Eval) => {
                // The value of `eval` is a module or an object the reader
                // follows, if the call is not a statement of its own and is
                // not just printed, and comes back under no name.
                if name.as_deref() == Some("eval") && self.value_used(above) {
                    self.reading.unread(self.text(call));
                }
                self.eval(&args, call);
            }
            Some(Kind::Import | Kind::Getattr) => {
                // With a literal name the call is a name (`qualified`); the
                // rest is a lookup the reader cannot follow.
                if self.qualified(call, 0).is_none() {
                    self.reading.unread(self.text(call));
                } else {
                    // A module or call it names, handed on as a value.
                    self.used(call, field, above);
                }
            }
            None => {
                self.method(function, &args);
                // A call the reader does not know is given a path.
                if self.reading.acts.len() == before {
                    self.unmodeled(function, name.as_deref(), &args, call);
                }
            }
        }
        if matches!(kind, Some(Kind::Script | Kind::Subprocess | Kind::Exec)) {
            self.within(&args, before);
        }
    }

    /// A call the reader has no row for (not a delete, a write, a read or a
    /// command it follows): it may read, write or delete a file, or run
    /// anything, so the line is `unknown`, unless the call is one of an
    /// explicit list of calls that touch nothing ([`Self::touches_nothing`]).
    /// When it is given a path, as a string or built from the home directory,
    /// the path is what is judged: `unknown`, or `read_secret` when it is a
    /// key.
    fn unmodeled(
        &mut self,
        function: Node<'_>,
        name: Option<&str>,
        args: &Args<'_>,
        call: Node<'_>,
    ) {
        if self.touches_nothing(function, name, args) {
            return;
        }
        let mut nodes: Vec<Node<'_>> = args.positional.clone();
        nodes.extend(args.keywords.iter().map(|(_, value)| *value));
        let mut given = Vec::new();
        for node in nodes {
            let mut cursor = node.walk();
            match node.kind() {
                "list" | "tuple" => given.extend(node.named_children(&mut cursor)),
                "dictionary" => given.extend(
                    node.named_children(&mut cursor)
                        .filter_map(|pair| pair.child_by_field_name("value")),
                ),
                _ => given.push(node),
            }
        }
        let before = self.reading.acts.len();
        for node in given {
            if let Some(path) = self.value(node, 0).as_deref().and_then(named_path) {
                self.reading.acts.push(Act::Opaque(path));
            }
        }
        if self.reading.acts.len() == before {
            self.reading.unread(self.text(call));
        }
    }

    /// Whether a call the reader has no row for touches nothing: a builtin
    /// that only computes (`print`, `len`), a function or class the code
    /// defines (its own calls are read where they are written), a function of
    /// a module that only looks at names or computes (`os.path`, `json`,
    /// `re`, `math`), or a method of a string, a list, a dictionary, a file
    /// object or a regular expression on a value of the code's own. Anything
    /// else (a function of any other module, a method it has no row for, a
    /// name it does not know, a call of a call) is not.
    fn touches_nothing(&mut self, function: Node<'_>, name: Option<&str>, args: &Args<'_>) -> bool {
        match function.kind() {
            "identifier" => match name {
                Some(name) if name.contains('.') => self.names_only(name, args),
                Some(name) => BUILTINS.contains(&name) || self.callables.contains(name),
                None => false,
            },
            // `getattr(os, 'getcwd')()`: a call that is a name.
            "call" => match name {
                Some(name) => {
                    let root = name.split('.').next().unwrap_or(name);
                    if self.aliases.contains_key(root) || !self.bound.contains(root) {
                        self.names_only(name, args)
                    } else {
                        let method = name.rsplit('.').next().unwrap_or(name);
                        METHODS_OF_TEXT.contains(&method) || self.methods.contains(method)
                    }
                }
                None => false,
            },
            // `(lambda: …)()`: the body is read where it is written.
            "parenthesized_expression" => function
                .named_child(0)
                .is_some_and(|inner| inner.kind() == "lambda"),
            "attribute" => {
                let Some(method) = function.child_by_field_name("attribute") else {
                    return false;
                };
                let method = self.text(method);
                if let Some(name) = name {
                    // A chain of names: of a module, an import or a name
                    // nothing here bound, or of a value of the code's own.
                    let mut root = function;
                    while let Some(object) = root
                        .child_by_field_name("object")
                        .filter(|_| root.kind() == "attribute")
                    {
                        root = object;
                    }
                    let module = root.kind() != "identifier" || {
                        let root = self.text(root);
                        self.aliases.contains_key(root) || !self.bound.contains(root)
                    };
                    if module {
                        return self.names_only(name, args);
                    }
                }
                let Some(receiver) = function.child_by_field_name("object") else {
                    return false;
                };
                if self.path_like(receiver, 0) {
                    return METHODS_OF_PATHS.contains(&method);
                }
                METHODS_OF_TEXT.contains(&method) || self.methods.contains(method)
            }
            _ => false,
        }
    }

    /// Whether the call of the dotted name `name` is one of the functions of
    /// a module that only look at names or compute. A `sys.path` entry is
    /// where an import looks for code, so one outside the workspace is not.
    fn names_only(&mut self, name: &str, args: &Args<'_>) -> bool {
        if matches!(
            name,
            "sys.path.insert" | "sys.path.append" | "sys.path.extend"
        ) {
            return self.path_entries_stay(name, args);
        }
        NAMES_ONLY.iter().any(|start| name.starts_with(start)) || NAMES_ONLY_MORE.contains(&name)
    }

    /// Whether what a call adds to `sys.path` (`insert(0, p)`, `append(p)`,
    /// `extend([p])`) is only workspace folders: a string that is not an
    /// absolute path, `~`, `..` or a `file:` URL. A value only known when it
    /// runs may be any.
    fn path_entries_stay(&mut self, name: &str, args: &Args<'_>) -> bool {
        if args.splat {
            return false;
        }
        let at = usize::from(name.ends_with("insert"));
        let Some(node) = args.get(at, &["path", "object", "iterable"]) else {
            return false;
        };
        self.entries_stay(node, name.ends_with("extend"))
    }

    /// [`Self::path_entries_stay`] for the node that holds the entries: one,
    /// or a list of them.
    fn entries_stay(&mut self, node: Node<'_>, list: bool) -> bool {
        let items: Vec<Node<'_>> = if list {
            if !matches!(node.kind(), "list" | "tuple") {
                return false;
            }
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .filter(|item| item.kind() != "comment")
                .collect()
        } else {
            vec![node]
        };
        items.into_iter().all(|item| {
            self.value(item, 0)
                .is_some_and(|text| super::foreign_module(&text).is_none())
        })
    }

    /// An assignment to `sys.path` (`sys.path = [...]`, `sys.path += [...]`,
    /// `sys.path[:0] = [...]`) that puts a folder outside the workspace where
    /// an import looks, or a value only known when it runs: code the reader
    /// does not follow.
    fn sys_path_assignment(&mut self, node: Node<'_>) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let target = if left.kind() == "subscript" {
            left.child_by_field_name("value")
        } else {
            Some(left)
        };
        let is_path = target.is_some_and(|target| {
            target.kind() == "attribute" && self.qualified(target, 0).as_deref() == Some("sys.path")
        });
        if !is_path {
            return;
        }
        let stays = node
            .child_by_field_name("right")
            .is_some_and(|right| self.entries_stay(right, true));
        if !stays {
            self.reading.unread(self.text(node));
        }
    }

    /// An assignment (also augmented, or the target of a `for`, `with ... as`)
    /// to a member of a module, of a name bound to one, or of a builtin class
    /// (`os.path.join = f`, `Path.__truediv__ = f`, `str.join = f`) changes
    /// what the calls the reader models do: code the reader does not follow.
    fn member_assignment(&mut self, node: Node<'_>) {
        let target = match node.kind() {
            "as_pattern" => node.child_by_field_name("alias"),
            _ => node.child_by_field_name("left"),
        };
        if target.is_some_and(|target| self.assigns_to_global_member(target, 0)) {
            self.reading.unread(self.text(node));
        }
    }

    /// Whether `target`, or a part of it when it unpacks, is a member of a
    /// module or of a builtin class.
    fn assigns_to_global_member(&mut self, target: Node<'_>, level: usize) -> bool {
        if level > MAX_TREE_DEPTH {
            self.reading.deep = true;
            return false;
        }
        match target.kind() {
            "attribute" => target
                .child_by_field_name("object")
                .is_some_and(|object| self.is_global_object(object, level + 1)),
            "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "list_splat_pattern"
            | "parenthesized_expression"
            | "as_pattern_target" => {
                let mut cursor = target.walk();
                let parts: Vec<Node<'_>> = target.named_children(&mut cursor).collect();
                parts
                    .into_iter()
                    .any(|part| self.assigns_to_global_member(part, level + 1))
            }
            _ => false,
        }
    }

    /// Whether `object` is a module, a name bound to one, a class of the
    /// language, or a member of one (`os`, `os.path`, `p` after `p = os.path`,
    /// `Path`, `str`, `sys.modules['os']`, `__import__(name)`).
    fn is_global_object(&mut self, object: Node<'_>, level: usize) -> bool {
        if level > MAX_TREE_DEPTH {
            self.reading.deep = true;
            return false;
        }
        if let Some(name) = self.qualified(object, 0) {
            let root = name.split('.').next().unwrap_or(&name);
            return self.is_module(&name)
                || self.is_module(root)
                || BUILTIN_CLASSES.contains(&root)
                || self.aliases.contains_key(root);
        }
        match object.kind() {
            "subscript" => object
                .child_by_field_name("value")
                .is_some_and(|value| self.is_global_object(value, level + 1)),
            "attribute" | "parenthesized_expression" => {
                let inner = if object.kind() == "attribute" {
                    object.child_by_field_name("object")
                } else {
                    object.named_child(0)
                };
                inner.is_some_and(|inner| self.is_global_object(inner, level + 1))
            }
            // `__import__(name)`, `importlib.import_module(name)`, `getattr`.
            "call" => object
                .child_by_field_name("function")
                .and_then(|function| self.qualified(function, 0))
                .as_deref()
                .and_then(kind)
                .is_some_and(|kind| matches!(kind, Kind::Import | Kind::Getattr)),
            _ => false,
        }
    }

    /// `fileinput.input(files, inplace=True)` and `fileinput.FileInput(…)`:
    /// with `inplace` on (or only known when it runs) each file is rewritten
    /// as `sed -i` does it, so each is a write. Files given as anything but a
    /// string or a list of strings, or not given (they then come from the
    /// arguments of the script), are only known when it runs.
    fn file_input(&mut self, args: &Args<'_>, call: Node<'_>) {
        let inplace = match args.get(1, &["inplace"]) {
            // The default only reads.
            None => args.splat,
            Some(node) => !matches!(self.text(node), "False" | "None" | "0"),
        };
        if !inplace {
            // Each file named is read, as `cat` does; none reads the files
            // the line names in the arguments of the script, which are only
            // known when it runs.
            match args.get(0, &["files"]) {
                Some(files) => {
                    for source in self.read_files(files) {
                        self.reading.acts.push(Act::Read(source));
                    }
                }
                None => self.reading.unread(self.text(call)),
            }
            return;
        }
        let files = args.get(0, &["files"]).filter(|_| !args.splat);
        let Some(files) = files else {
            self.reading.unread(self.text(call));
            return;
        };
        if !matches!(files.kind(), "list" | "tuple") {
            if matches!(files.kind(), "string" | "concatenated_string") {
                let target = self.arg(files);
                self.reading.acts.push(Act::Write(target));
            } else {
                self.reading.unread(self.text(call));
            }
            return;
        }
        let mut cursor = files.walk();
        let elements: Vec<Node<'_>> = files
            .named_children(&mut cursor)
            .filter(|element| element.kind() != "comment")
            .collect();
        if elements.is_empty()
            || elements
                .iter()
                .any(|element| element.kind() == "list_splat")
        {
            self.reading.unread(self.text(call));
            return;
        }
        for element in elements {
            let target = self.arg(element);
            self.reading.acts.push(Act::Write(target));
        }
    }

    /// Run what the call at `before` added from the directory its `cwd` names:
    /// as if the line had gone there first. A directory only known when it
    /// runs cannot be told, so the call is `unknown` besides.
    fn within(&mut self, args: &Args<'_>, before: usize) {
        let Some(node) = args
            .keywords
            .iter()
            .find(|(name, _)| name == "cwd")
            .map(|(_, node)| *node)
        else {
            return;
        };
        if self.text(node) == "None" {
            return;
        }
        let acts = self.reading.acts.split_off(before);
        match self.arg(node) {
            dir @ Arg::Known(_) => self.reading.acts.push(Act::In(dir, acts)),
            other => {
                self.reading.unread(other.text());
                self.reading.acts.extend(acts);
            }
        }
    }

    /// The text of a string literal handed on as code. A bytes literal is
    /// decoded by the coding line it holds (`exec(b"# coding: utf-7…")`), a
    /// text the reader reads as UTF-8: one that names another encoding is
    /// code only known when it runs.
    fn code_literal(&mut self, node: Node<'_>) -> Option<String> {
        let text = self.value(node, 0)?;
        (!(self.is_bytes(node) && declares_other_encoding(&text))).then_some(text)
    }

    /// Whether a string literal, or one of the pieces of a concatenation, is
    /// bytes (`b"…"`, `rb"…"`).
    fn is_bytes(&self, node: Node<'_>) -> bool {
        let mut cursor = node.walk();
        let parts: Vec<Node<'_>> = node.children(&mut cursor).collect();
        match node.kind() {
            "string" => parts.iter().any(|part| {
                part.kind() == "string_start" && self.text(*part).to_ascii_lowercase().contains('b')
            }),
            _ => parts.iter().any(|part| self.is_bytes(*part)),
        }
    }

    /// Whether the value of `eval(…)` is used: it is anything but a
    /// statement of its own or an argument of `print`, which does nothing
    /// with it.
    fn value_used(&mut self, above: &[Ancestor<'_>]) -> bool {
        let mut at = above.len();
        while let Some(parent) = at.checked_sub(1).and_then(|index| above.get(index)) {
            match parent.node.kind() {
                "parenthesized_expression" => at -= 1,
                "expression_statement" => return false,
                "argument_list" => {
                    let printed = at
                        .checked_sub(2)
                        .and_then(|index| above.get(index))
                        .filter(|outer| outer.node.kind() == "call")
                        .and_then(|outer| outer.node.child_by_field_name("function"))
                        .and_then(|function| self.qualified(function, 0))
                        .as_deref()
                        == Some("print");
                    return !printed;
                }
                _ => return true,
            }
        }
        false
    }

    /// `eval("…")` and `exec("…")` run code that is read as Python;
    /// anything else is code only known when it runs.
    fn eval(&mut self, args: &Args<'_>, call: Node<'_>) {
        match args.positional.first().and_then(|node| match node.kind() {
            "string" | "concatenated_string" => self.code_literal(*node),
            _ => None,
        }) {
            Some(text) => self.literal_code(text, call),
            None => self.reading.unread(self.text(call)),
        }
    }

    /// `timeit.timeit(stmt, setup)`, `cProfile.run(statement)`:
    /// the code they run is read as Python when it is a literal, a callable
    /// (`lambda`) is walked where it is written, and anything else (a name, a
    /// computed string, `*args`) is code only known when it runs.
    fn runs_code(&mut self, args: &Args<'_>, call: Node<'_>, setup: bool) {
        const CODE: [&str; 4] = ["stmt", "statement", "command", "expression"];
        let mut pieces = Vec::new();
        pieces.extend(args.get(0, &CODE));
        // `timeit`'s second argument is code too.
        if setup {
            pieces.extend(args.get(1, &["setup"]));
        }
        let mut unread = args.splat;
        for node in pieces {
            match node.kind() {
                "lambda" => {}
                "string" | "concatenated_string" => match self.code_literal(node) {
                    Some(text) => self.literal_code(text, call),
                    None => unread = true,
                },
                _ => unread = true,
            }
        }
        if unread {
            self.reading.unread(self.text(call));
        }
    }

    /// The mode argument of a `chmod`, in octal when the code gives a number.
    fn mode(&mut self, args: &Args<'_>, at: usize) -> Arg {
        match args.get(at, &["mode"]) {
            Some(node) => {
                let text = self.text(node);
                match mode(text) {
                    Some(octal) if node.kind() == "integer" => Arg::Known(octal),
                    _ => Arg::Unknown(super::shorten(text)),
                }
            }
            None => Arg::Unknown("mode".to_string()),
        }
    }

    /// `subprocess.run(["rm", "-rf", "~"])` runs the program; with a shell,
    /// or a string, the command line is read as a script.
    fn subprocess(&mut self, args: &Args<'_>) {
        // `*args` and `**options` may hold the program, `cwd`, `executable`;
        // so may the positional arguments of `Popen` after the first
        // (`bufsize`, `executable`, ...).
        if args.splat || args.positional.len() > 1 {
            self.reading
                .unread("subprocess call with arguments passed on");
            if args.get(0, &["args"]).is_none() {
                return;
            }
        }
        let Some(command) = args.get(0, &["args"]) else {
            return;
        };
        let shell = args
            .keywords
            .iter()
            .find(|(name, _)| name == "shell")
            .map(|(_, value)| *value);
        let shell = shell.is_some_and(|value| !matches!(self.text(value), "False" | "None" | "0"));
        // `executable=` is the program that runs, whatever the first word of
        // the command says (with a shell, the shell is that program).
        let executable = args
            .keywords
            .iter()
            .find(|(name, _)| name == "executable")
            .map(|(_, value)| *value)
            .filter(|value| self.text(*value) != "None");
        if let Some(executable) = executable {
            let program = self.arg(executable);
            if shell || program.known().is_none() {
                self.reading.unread(self.text(executable));
            } else if matches!(command.kind(), "list" | "tuple") {
                let mut cursor = command.walk();
                let elements: Vec<Node<'_>> = command
                    .named_children(&mut cursor)
                    .filter(|element| element.kind() != "comment")
                    .collect();
                if elements
                    .iter()
                    .any(|element| element.kind() == "list_splat")
                {
                    self.reading.unread(self.text(command));
                    return;
                }
                let mut words = vec![program];
                words.extend(elements.into_iter().skip(1).map(|node| self.arg(node)));
                self.reading.acts.push(Act::Program(words));
            } else {
                self.reading.acts.push(Act::Program(vec![program]));
            }
            return;
        }
        if matches!(command.kind(), "list" | "tuple") {
            let mut cursor = command.walk();
            let elements: Vec<Node<'_>> = command
                .named_children(&mut cursor)
                .filter(|element| element.kind() != "comment")
                .collect();
            if elements
                .iter()
                .any(|element| matches!(element.kind(), "list_splat"))
            {
                self.reading.unread(self.text(command));
                return;
            }
            if shell {
                if let Some(first) = elements.first() {
                    let script = self.arg(*first);
                    self.reading.acts.push(Act::Script(script));
                }
            } else {
                let words: Vec<Arg> = elements.into_iter().map(|node| self.arg(node)).collect();
                self.reading.acts.push(Act::Program(words));
            }
        } else {
            let script = self.arg(command);
            self.reading.acts.push(Act::Script(script));
        }
    }

    /// Whether `node` is the name of a module the code imported (`copy`,
    /// `np` for `import numpy as np`): a call on it is a function of the
    /// module, not a method of a path.
    fn names_module(&mut self, node: Node<'_>) -> bool {
        matches!(node.kind(), "identifier" | "attribute")
            && self
                .qualified(node, 0)
                .is_some_and(|name| self.is_module(&name))
    }

    /// A method call on something the reader cannot name: `Path` methods,
    /// and files' and archives' own.
    fn method(&mut self, function: Node<'_>, args: &Args<'_>) {
        if function.kind() != "attribute" {
            return;
        }
        let (Some(receiver), Some(attribute)) = (
            function.child_by_field_name("object"),
            function.child_by_field_name("attribute"),
        ) else {
            return;
        };
        match self.text(attribute) {
            // Loads a module and runs its code, or runs the code of a string
            // handed to a profiler or a debugger.
            "exec_module" | "load_module" | "runctx" | "runeval" | "runcall" => {
                self.reading.unread(self.text(function));
            }
            "unlink" | "rmdir" => {
                let target = self.arg(receiver);
                self.reading.acts.push(Act::Remove(target));
            }
            "write_text" | "write_bytes" | "touch" | "mkdir" => {
                let target = self.arg(receiver);
                self.reading.acts.push(Act::Write(target));
            }
            // `Path.read_text()` and `Path.read_bytes()`.
            "read_text" | "read_bytes" => {
                for source in self.read_arg(receiver) {
                    self.reading.acts.push(Act::Read(source));
                }
            }
            // `Path.rename(target)` and `Path.replace(target=…)`; a string's
            // `replace(old, new)` has two.
            "rename" | "replace"
                if args.positional.len() + args.keywords.len() == 1
                    && args.keywords.iter().all(|(name, _)| name == "target") =>
            {
                let from = self.arg(receiver);
                let to = args.get(0, &["target"]).map(|node| self.arg(node));
                self.act(to.map(|to| Act::Move { from, to }));
            }
            // `Path(…).rename(*args)` may be this, and a string literal's
            // `replace` is not.
            "rename" | "replace"
                if args.splat && !matches!(receiver.kind(), "string" | "concatenated_string") =>
            {
                self.reading.unread(self.text(receiver));
            }
            // Python 3.14's `Path.move(target)` and `Path.move_into(dir)`
            // move as `Path.rename` does, the second into a folder, as `mv`
            // does. A module's own `move` is not a path's.
            "move" | "move_into"
                if args.positional.len() + args.keywords.len() == 1
                    && args
                        .keywords
                        .iter()
                        .all(|(name, _)| name == "target" || name == "target_dir")
                    && !self.names_module(receiver) =>
            {
                let from = self.arg(receiver);
                let to = args
                    .get(0, &["target", "target_dir"])
                    .map(|node| self.arg(node));
                self.act(to.map(|to| Act::Move { from, to }));
            }
            "move" | "move_into"
                if args.splat
                    && !matches!(receiver.kind(), "string" | "concatenated_string")
                    && !self.names_module(receiver) =>
            {
                self.reading.unread(self.text(receiver));
            }
            // `Path.copy(target, …)` and `Path.copy_into(dir, …)` (3.14) write
            // the target, as `shutil.copy` does; the options are keywords.
            // A call with no target (`d.copy()`) and a module's own `copy`
            // (`copy.copy(x)`, `numpy.copy(a)`) are not this.
            "copy" | "copy_into"
                if (!args.positional.is_empty()
                    || args
                        .keywords
                        .iter()
                        .any(|(name, _)| name == "target" || name == "target_dir"))
                    && !matches!(receiver.kind(), "string" | "concatenated_string")
                    && !self.names_module(receiver) =>
            {
                let target = args.get(0, &["target", "target_dir"]);
                let target = target.map(|node| self.arg(node));
                for source in self.read_arg(receiver) {
                    self.reading.acts.push(Act::Read(source));
                }
                self.act(target.map(Act::Write));
            }
            "copy" | "copy_into"
                if args.splat
                    && !matches!(receiver.kind(), "string" | "concatenated_string")
                    && !self.names_module(receiver) =>
            {
                self.reading.unread(self.text(receiver));
            }
            // `Path.open(mode)`, `archive.open(name, mode)`, `shelve.open(file,
            // flag)`. Any object has an `open`, and most take a file name or
            // a URL: a string is a way of opening for writing only when it
            // can be one.
            "open" => {
                let keywords = args
                    .keywords
                    .iter()
                    .filter(|(name, _)| matches!(name.as_str(), "mode" | "flag"))
                    .map(|(_, node)| *node);
                let nodes: Vec<Node<'_>> = args
                    .positional
                    .iter()
                    .take(2)
                    .copied()
                    .chain(keywords)
                    .filter(|node| node.kind() == "string")
                    .collect();
                let mut writes_file = false;
                for node in nodes {
                    writes_file |= self
                        .value(node, 0)
                        .is_some_and(|literal| opens_for_writing(&literal));
                }
                // A `pathlib` path is known to be a file, so its `open` is
                // read as the builtin is: the call reads only when its mode
                // is a string literal that reads (or is left out), and may
                // write when the mode is a value only known when it runs, is
                // spread in, or is not a string.
                if !writes_file && self.path_like(receiver, 0) {
                    let mode = args.get(0, &["mode"]);
                    writes_file = args.splat_at == Some(0)
                        || match mode {
                            Some(node) => {
                                node.kind() != "string"
                                    || self
                                        .value(node, 0)
                                        .is_none_or(|literal| opens_for_writing(&literal))
                            }
                            None => args.splat,
                        };
                }
                if writes_file {
                    let target = self.arg(receiver);
                    self.reading.acts.push(Act::Write(target));
                } else {
                    // A path opened to read; any other object's `open` is
                    // not known to be a file, unless the receiver is a
                    // `pathlib` path whose own value is not known.
                    let path = self.path_like(receiver, 0);
                    for source in self.read_arg(receiver) {
                        if path || source.known().is_some() {
                            self.reading.acts.push(Act::Read(source));
                        }
                    }
                }
            }
            "symlink_to" | "hardlink_to" | "link_to" => {
                let link = self.arg(receiver);
                let target = args.positional.first().map(|node| self.arg(*node));
                self.act(target.map(|target| Act::Link { target, link }));
            }
            "chmod" | "lchmod" if !args.positional.is_empty() => {
                let path = self.arg(receiver);
                let mode = self.mode(args, 0);
                self.reading.acts.push(Act::Chmod { path, mode });
            }
            "extractall" => {
                let target = self.target(args, 0, &["path"]);
                self.act(target.map(Act::Write));
            }
            // `TarFile.add(name)` packs a file, or a folder and all that is
            // in it; `ZipFile.write(filename)` reads the file;
            // `ConfigParser.read(filenames)` reads each. Only a name the code
            // set to such an object: any other object has an `add`, a `write`
            // and a `read`.
            "add" if self.is_object(receiver, TAR) => {
                for source in self.read_target(args, 0, &["name"]) {
                    self.reading.acts.push(Act::ReadTree(source));
                }
            }
            "write" if self.is_object(receiver, ZIP) => {
                for source in self.read_target(args, 0, &["filename"]) {
                    self.reading.acts.push(Act::Read(source));
                }
            }
            "read" if self.is_object(receiver, CONFIG) => {
                if let Some(files) = args.get(0, &["filenames"]) {
                    for source in self.read_files(files) {
                        self.reading.acts.push(Act::Read(source));
                    }
                }
            }
            _ => {}
        }
    }

    /// A name or attribute used without being called: an alias of a call the
    /// reader cannot follow.
    fn reference<'t>(&mut self, node: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) {
        // A name that reaches what the reader cannot follow, called or not.
        if node.kind() == "attribute"
            && node
                .child_by_field_name("attribute")
                .is_some_and(|attribute| DUNDERS.contains(&self.text(attribute)))
        {
            self.reading.unread(self.text(node));
            return;
        }
        self.used(node, field, above);
    }

    /// A name, attribute or call that is a name (`__import__('os')`) in the
    /// place `field` of the last of `above`: unread when it is a call the
    /// reader cannot follow handed on, or a module put where its attributes
    /// are not looked up by name.
    fn used<'t>(&mut self, node: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) {
        let Some(parent) = above.last() else {
            return;
        };
        let is = |name: &str| field == Some(name);
        let skipped = match parent.node.kind() {
            "call" => is("function"),
            "attribute" => is("attribute"),
            "keyword_argument" => is("name"),
            "function_definition" | "class_definition" => is("name"),
            // A name in a parameter list is the parameter's, and what it is
            // given when none is passed (`r=os.remove`) is read.
            "default_parameter" | "typed_default_parameter" => is("name"),
            "dotted_name"
            | "aliased_import"
            | "import_statement"
            | "import_from_statement"
            | "parameters"
            | "lambda_parameters"
            | "typed_parameter"
            | "global_statement"
            | "nonlocal_statement"
            | "relative_import" => true,
            _ => false,
        };
        if skipped {
            return;
        }
        let Some(name) = self.qualified(node, 0) else {
            return;
        };
        let unfollowable = kind(&name).is_some_and(|kind| {
            !matches!(kind, Kind::Import | Kind::Getattr) || node.kind() == "identifier"
        });
        let method = node.kind() == "attribute"
            && node
                .child_by_field_name("attribute")
                .is_some_and(|attribute| {
                    let attribute = self.text(attribute);
                    METHODS.contains(&attribute)
                });
        if unfollowable || method || (self.is_module(&name) && self.escapes(node, field, above)) {
            self.reading.unread(self.text(node));
        }
    }

    /// A decorator that is not a call (`@foo.bar`) calls what it names with
    /// the function it decorates: a call the reader has no row for unless it
    /// touches nothing.
    fn decorator(&mut self, node: Node<'_>) {
        let Some(expression) = node.named_child(0) else {
            return;
        };
        if !matches!(expression.kind(), "identifier" | "attribute") {
            return;
        }
        let name = self.qualified(expression, 0);
        if name.as_deref().and_then(kind).is_some() {
            return;
        }
        let args = Args {
            positional: Vec::new(),
            keywords: Vec::new(),
            splat: false,
            splat_at: None,
            dir_fd: false,
        };
        if !self.touches_nothing(expression, name.as_deref(), &args) {
            self.reading.unread(self.text(node));
        }
    }

    /// A name bound in the body of a class is an attribute of the class
    /// (`class C: o = os`, `C.o.remove(…)`), not a name of its own: an import
    /// there, or an assignment of a module or of a call the reader knows, is
    /// one it does not follow.
    fn class_binding<'t>(&mut self, node: Node<'t>, above: &[Ancestor<'t>]) {
        let in_class = above
            .iter()
            .rev()
            .find(|ancestor| {
                matches!(
                    ancestor.node.kind(),
                    "class_definition" | "function_definition" | "lambda"
                )
            })
            .is_some_and(|ancestor| ancestor.node.kind() == "class_definition");
        if !in_class {
            return;
        }
        let binds = match node.kind() {
            "assignment" => node
                .child_by_field_name("right")
                .and_then(|right| self.qualified(right, 0))
                .is_some_and(|name| kind(&name).is_some() || self.is_module(&name)),
            _ => true,
        };
        if binds {
            self.reading.unread(self.text(node));
        }
    }

    /// Whether `name` is a module, whose attributes reach other modules and
    /// so the calls the reader looks for.
    fn is_module(&self, name: &str) -> bool {
        MODULES.contains(&name) || HOLDERS.contains(&name) || self.modules.contains(name)
    }

    /// Whether a module is put where the reader loses it: anywhere but as the
    /// object of an attribute (`os.remove`), the value of a name it records
    /// (`o = os`, also in a chain), a name being set, or a statement of its
    /// own. Handed to a call, held in a list, a dict or a loop, returned or
    /// given as a default it may come back under a name the reader does not
    /// follow (`f(os)` with `def f(o): o.remove(...)`).
    fn escapes<'t>(&mut self, node: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) -> bool {
        let mut field = field;
        let mut at = above.len();
        while let Some(parent) = at.checked_sub(1).and_then(|index| above.get(index)) {
            let is = |name: &str| field == Some(name);
            match parent.node.kind() {
                "parenthesized_expression" => {
                    field = parent.field;
                    at -= 1;
                }
                "attribute" => return !is("object"),
                "expression_statement" => return false,
                "assignment" => {
                    let named = parent
                        .node
                        .child_by_field_name("left")
                        .is_some_and(|left| left.kind() == "identifier");
                    return !(is("left") || (is("right") && named));
                }
                "argument_list" => {
                    // `getattr(os, 'remove')` with a literal name is followed.
                    let first =
                        parent.node.named_child(0).map(|first| first.id()) == Some(node.id());
                    let call = at.checked_sub(2).and_then(|index| above.get(index));
                    let getattr = call
                        .filter(|call| call.node.kind() == "call")
                        .and_then(|call| call.node.child_by_field_name("function"))
                        .and_then(|function| self.qualified(function, 0))
                        .as_deref()
                        .and_then(kind)
                        == Some(Kind::Getattr);
                    return !(first && getattr);
                }
                _ => return true,
            }
        }
        false
    }

    /// Python 2's `exec "code"`, with or without `in globals`: a literal is
    /// code like `exec("…")`'s, anything else is only known when it runs.
    fn exec_statement(&mut self, node: Node<'_>) {
        let code = node.child_by_field_name("code");
        let text = code
            .filter(|code| code.kind() == "string")
            .and_then(|code| self.value(code, 0));
        match text {
            Some(text) => self.literal_code(text, node),
            None => self.reading.unread(self.text(node)),
        }
    }

    /// `sys.modules['os']` and `os.__dict__['remove']`: a name looked up by
    /// a key the reader cannot follow.
    fn subscript(&mut self, node: Node<'_>) {
        let Some(object) = node.child_by_field_name("value") else {
            return;
        };
        let name = self.qualified(object, 0);
        let lookup = name.as_deref().is_some_and(|name| {
            matches!(name, "sys.modules" | "os.environ.__dict__")
                || name.ends_with(".__dict__")
                || name.ends_with(".__globals__")
                || name == "__builtins__"
        });
        if lookup {
            self.reading.unread(self.text(node));
        }
    }
}

/// Whether `mode` is a mode `open` takes: the letters `r`, `w`, `x`, `a`, `b`,
/// `t`, `+` and `U`, each once, one of `r`, `w`, `x` and `a` (or a `U`
/// alone), and not both `b` and `t`. `Path.open` raises on anything else
/// before it opens a file.
fn is_open_mode(mode: &str) -> bool {
    let letters: Vec<char> = mode.chars().collect();
    let distinct = letters
        .iter()
        .enumerate()
        .all(|(at, letter)| !letters[..at].contains(letter));
    let base = letters
        .iter()
        .filter(|letter| matches!(letter, 'r' | 'w' | 'x' | 'a'))
        .count();
    distinct
        && letters
            .iter()
            .all(|letter| matches!(letter, 'r' | 'w' | 'x' | 'a' | 'b' | 't' | '+' | 'U'))
        && (base == 1 || (base == 0 && letters.contains(&'U')))
        && !(letters.contains(&'b') && letters.contains(&'t'))
}

/// Whether a string handed to a method called `open` opens a file for
/// writing: an `open` mode that writes (`w`, `a`, `x`, `+`), a `tarfile` mode
/// (`w:gz`, `a:`), or a `dbm` flag that makes a database (`c`, `n`).
fn opens_for_writing(literal: &str) -> bool {
    (is_open_mode(literal) && writes(Some(literal)))
        || literal
            .split_once([':', '|'])
            .is_some_and(|(mode, _)| matches!(mode, "w" | "a" | "x"))
        || matches!(literal, "c" | "n")
}

/// A string literal's text with its escapes read, as Python reads a string
/// that is not raw: `\n`, `\x41`, `é`, octal, and a backslash before
/// anything else stays. `None` when an escape is not decoded (`\N{NAME}`, a
/// `\x` or `\u` without its digits, a number that is no character): the
/// string is then only known when it runs.
fn unescape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(next) = chars.next() else {
            out.push('\\');
            break;
        };
        match next {
            '\n' => {}
            '\\' | '\'' | '"' => out.push(next),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '0'..='7' => {
                let mut digits = String::from(next);
                while digits.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                    digits.extend(chars.next());
                }
                out.push(
                    u32::from_str_radix(&digits, 8)
                        .ok()
                        .and_then(char::from_u32)?,
                );
            }
            'x' | 'u' | 'U' => {
                let count = match next {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let digits: String = (0..count)
                    .map_while(|_| chars.next_if(char::is_ascii_hexdigit))
                    .collect();
                out.push(
                    u32::from_str_radix(&digits, 16)
                        .ok()
                        .filter(|_| digits.len() == count)
                        .and_then(char::from_u32)?,
                );
            }
            // `\N{NAME}` is a character the name stands for, which the reader
            // does not look up.
            'N' => return None,
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}
