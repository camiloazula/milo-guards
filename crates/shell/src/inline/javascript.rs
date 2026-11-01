//! Inline JavaScript (Node, Bun, Deno): the calls that delete, write, move
//! and run, with the paths they name, found with tree-sitter-javascript.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::{
    environment, join, mode, named_path, path, read_path, walk, writes, Act, Ancestor, Constants,
    Expansion, Holds, Language, Parts, Reading,
};
use crate::unit::{self, Arg, MAX_TREE_DEPTH};

pub(super) fn read(code: &str) -> Reading {
    let ended = end_hashbang(code);
    let code = ended.as_str();
    let mut reader = Reader::new(code, HashMap::new(), HashSet::new(), 0);
    let Some(tree) = parse(code) else {
        reader.reading.unread(code);
        return reader.reading;
    };
    let root = tree.root_node();
    if root.has_error() {
        reader.reading.unread(code);
    }
    reader.collect_aliases(root);
    reader.walk_all(root);
    reader.reading
}

fn parse(code: &str) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .ok()
        .and_then(|()| parser.parse(code, None))
}

/// `code` with the line a hashbang (`#!…`) starts ended as JavaScript ends
/// it: at any line terminator, which is `\r`, U+2028 and U+2029 as well as
/// `\n`. tree-sitter-javascript ends it at `\n` only, so the code after
/// another terminator would be read as part of the comment, and not read.
fn end_hashbang(code: &str) -> String {
    if code.starts_with("#!") {
        if let Some((at, terminator)) = code
            .char_indices()
            .find(|(_, c)| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
        {
            if terminator != '\n' {
                let mut ended = String::with_capacity(code.len());
                ended.push_str(&code[..at]);
                ended.push('\n');
                ended.push_str(&code[at + terminator.len_utf8()..]);
                return ended;
            }
        }
    }
    code.to_string()
}

/// What a call to a qualified name does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Remove,
    /// The first argument is written, made or truncated.
    Write,
    /// The second argument is written.
    Copy,
    Move,
    Link,
    Chmod,
    Chown,
    Chdir,
    /// `process.kill(pid, signal)` and `Deno.kill(pid, signal)`.
    Kill,
    /// `fs.openSync(path, flags)`.
    Open,
    /// `fs.readFileSync(path, options)`, `fs.createReadStream(path, options)`
    /// and the class `fs.ReadStream` it makes: reads, unless a `flag` opens the file for writing (`w`
    /// truncates it).
    ReadFile,
    /// `Deno.open(path, options)`.
    DenoOpen,
    /// `Bun.write(path, data)`: the path may be `Bun.file(path)`.
    BunWrite,
    /// `Bun.file(path)`: a handle on a file, which `.text()`, `.stream()` and
    /// the rest read, and is a copy's source when handed to `Bun.write`.
    BunFile,
    /// Runs a command line.
    Script,
    /// `spawn(command, args, options)` and its kin.
    Spawn,
    /// `child_process.fork(module, args, options)`: runs node on a module.
    Fork,
    /// `new Deno.Command(command, { args })`.
    DenoCommand,
    /// `Bun.spawn(argv)`, `Deno.run({ cmd })`.
    Argv,
    /// `shell.rm('-rf', path)`: the shell command of the same name.
    Shelljs,
    /// Code or a program the reader cannot follow.
    Unread,
    Eval,
    Require,
}

/// The module `name` names, once Node's spellings are one: `node:fs`,
/// `fs/promises`, and `fs-extra`, which has `fs`'s calls too.
fn module(name: &str) -> String {
    let name = name.strip_prefix("node:").unwrap_or(name);
    match name {
        "fs/promises" => "fs.promises".to_string(),
        "path/posix" => "path".to_string(),
        "bun" => "Bun".to_string(),
        _ => name.to_string(),
    }
}

fn kind(name: &str) -> Option<Kind> {
    if let Some(kind) = whole(name) {
        return Some(kind);
    }
    // `fs`, its `promises` and `fs-extra` share the names of their calls,
    // with and without `Sync`.
    let (extra, call) = match name.strip_prefix("fs-extra.") {
        Some(call) => (true, call),
        None => (false, name.strip_prefix("fs.")?),
    };
    let call = call.strip_prefix("promises.").unwrap_or(call);
    let call = call.strip_suffix("Sync").unwrap_or(call);
    Some(match (extra, call) {
        (true, "remove" | "emptyDir") => Kind::Remove,
        (
            true,
            "outputFile" | "ensureFile" | "ensureDir" | "mkdirs" | "mkdirp" | "outputJson"
            | "writeJson" | "createFile",
        ) => Kind::Write,
        (true, "copy") => Kind::Copy,
        (true, "move") => Kind::Move,
        (_, "rm" | "unlink" | "rmdir") => Kind::Remove,
        (
            _,
            "writeFile" | "appendFile" | "createWriteStream" | "WriteStream" | "truncate" | "mkdir"
            | "mkdtemp",
        ) => Kind::Write,
        (_, "copyFile" | "cp") => Kind::Copy,
        (_, "rename") => Kind::Move,
        (_, "symlink" | "link") => Kind::Link,
        (_, "chmod" | "lchmod") => Kind::Chmod,
        (_, "chown" | "lchown") => Kind::Chown,
        (_, "open") => Kind::Open,
        (_, "readFile" | "createReadStream" | "ReadStream") => Kind::ReadFile,
        (true, "readJson" | "readJSON") => Kind::ReadFile,
        _ => return None,
    })
}

/// The calls known by their whole name.
fn whole(name: &str) -> Option<Kind> {
    Some(match name {
        "rimraf" | "rimraf.sync" | "rimraf.rimraf" | "rimraf.rimrafSync" | "Deno.remove"
        | "Deno.removeSync" => Kind::Remove,
        "Deno.writeTextFile"
        | "Deno.writeTextFileSync"
        | "Deno.writeFile"
        | "Deno.writeFileSync"
        | "Deno.truncate"
        | "Deno.truncateSync"
        | "Deno.mkdir"
        | "Deno.mkdirSync"
        | "Deno.create"
        | "Deno.createSync" => Kind::Write,
        "Deno.copyFile" | "Deno.copyFileSync" => Kind::Copy,
        "Deno.rename" | "Deno.renameSync" => Kind::Move,
        "Deno.symlink" | "Deno.symlinkSync" | "Deno.link" | "Deno.linkSync" => Kind::Link,
        "Deno.chmod" | "Deno.chmodSync" => Kind::Chmod,
        "Deno.chown" | "Deno.chownSync" => Kind::Chown,
        "Deno.chdir" | "process.chdir" => Kind::Chdir,
        "process.kill" | "Deno.kill" => Kind::Kill,
        "Deno.open" | "Deno.openSync" => Kind::DenoOpen,
        "Deno.readTextFile" | "Deno.readTextFileSync" | "Deno.readFile" | "Deno.readFileSync" => {
            Kind::ReadFile
        }
        "Deno.run" | "Bun.spawn" | "Bun.spawnSync" => Kind::Argv,
        "Deno.Command" => Kind::DenoCommand,
        "Bun.write" => Kind::BunWrite,
        "Bun.file" => Kind::BunFile,
        "Bun.$"
        | "zx.$"
        | "child_process.exec"
        | "child_process.execSync"
        | "shelljs.exec"
        | "execa.execaCommand"
        | "execa.execaCommandSync"
        // The older names of the two, and `$` (also `$.sync`, its alias
        // `$.s`, and as a tagged template, which is a call with the template
        // as its argument).
        | "execa.command"
        | "execa.commandSync"
        | "execa.$"
        | "execa.$.sync"
        | "execa.$.s" => Kind::Script,
        "child_process.spawn"
        | "child_process.spawnSync"
        | "child_process.execFile"
        | "child_process.execFileSync"
        | "cross-spawn"
        | "cross-spawn.default"
        | "cross-spawn.spawn"
        | "cross-spawn.sync"
        | "execa"
        | "execa.execa"
        | "execa.execaSync"
        | "execa.sync" => Kind::Spawn,
        "child_process.fork" => Kind::Fork,
        "shelljs.rm" | "shelljs.mv" | "shelljs.cp" | "shelljs.ln" | "shelljs.chmod"
        | "shelljs.mkdir" | "shelljs.touch" => Kind::Shelljs,
        "eval" => Kind::Eval,
        "Function"
        | "vm.runInThisContext"
        | "vm.runInNewContext"
        | "vm.runInContext"
        | "vm.Script"
        | "vm.compileFunction"
        | "process.binding"
        | "process.dlopen"
        | "process.mainModule"
        | "process.execve"
        | "Bun.$.cwd"
        | "zx.$.cwd"
        | "zx.cd"
        | "require.main"
        | "worker_threads.Worker"
        // Read code from the input (`repl`), or run what a string or a worker
        // is told to (`inspector`, `cluster`).
        | "repl.start"
        | "repl.REPLServer"
        | "inspector.Session"
        | "inspector.promises.Session"
        | "inspector/promises.Session"
        | "cluster.fork"
        | "cluster.setupPrimary"
        | "cluster.setupMaster"
        | "cluster.settings"
        | "Deno.dlopen"
        | "Deno.core" => Kind::Unread,
        // The system's store of secrets, which is no file the reader names.
        name if name.starts_with("keytar.") => Kind::Unread,
        "require" | "process.getBuiltinModule" | "import.meta.require" => Kind::Require,
        // The members of `child_process` the reader does not read start a
        // program or a process (`ChildProcess`, `_forkChild`).
        name if name.starts_with("child_process.") => Kind::Unread,
        // So are the members of `module` that load or run code (`_compile`,
        // `register`, `runMain`, `_load`, `require`, `createRequire`): only
        // its plain data is not.
        name if name.strip_prefix("module.").is_some_and(|member| {
            let member = member.split('.').next().unwrap_or_default();
            !MODULE_DATA.contains(&member)
        }) =>
        {
            Kind::Unread
        }
        _ => return None,
    })
}

/// The members of `module` that are plain data.
const MODULE_DATA: [&str; 6] = ["exports", "paths", "filename", "id", "children", "loaded"];

/// The objects a computed name looked up on cannot be followed.
const ROOTS: [&str; 11] = [
    "module",
    "fs",
    "fs.promises",
    "child_process",
    "process",
    "Deno",
    "Bun",
    "globalThis",
    "global",
    "vm",
    "os",
];

/// What `globalThis`, `global` and `window` are named, once the reader
/// has put them back: a member of it is the name alone (`globalThis.require`
/// is `require`).
const GLOBAL: &str = "globalThis";

/// `this`, which is the global object in `node -e` and is taken for it
/// where a member of it is named; it is not one of [`ROOTS`], so a `this[key]`
/// of a class is not a lookup the reader cannot follow.
const THIS: &str = "this";

/// What a name stands for in code that has bound nothing: itself, and the
/// global object under its other names.
fn fresh(name: &str) -> String {
    if matches!(name, "global" | "window") {
        GLOBAL.to_string()
    } else {
        name.to_string()
    }
}

/// The names the global object holds itself under.
const GLOBALS: [&str; 3] = ["globalThis", "global", "window"];

/// `object.property` as a name: a member of the global object is the name
/// alone (and the global object's own names are the global object again,
/// `global.global.require`), and a `default` is the object it is the default
/// of: the default export of a module is the module (`import * as ns from
/// 'fs'; ns.default.rmSync`).
fn member(object: &str, property: &str) -> String {
    if object == GLOBAL || object == THIS {
        if GLOBALS.contains(&property) {
            return GLOBAL.to_string();
        }
        return property.to_string();
    }
    if property == "default" {
        return object.to_string();
    }
    format!("{object}.{property}")
}

/// The methods only the file system, `child_process` and their kin have: a
/// call to one that the reader could not tell is such a call is a delete, a
/// write or a command it cannot follow.
const DISTINCT: [&str; 29] = [
    "rmSync",
    "rmdirSync",
    "unlinkSync",
    "writeFileSync",
    "appendFileSync",
    "truncateSync",
    "mkdirSync",
    "mkdtempSync",
    "copyFileSync",
    "cpSync",
    "renameSync",
    "symlinkSync",
    "linkSync",
    "chmodSync",
    "lchmodSync",
    "chownSync",
    "lchownSync",
    "openSync",
    "createWriteStream",
    "WriteStream",
    "execSync",
    "execFileSync",
    "spawnSync",
    "execaCommandSync",
    "rimrafSync",
    "removeSync",
    "outputFileSync",
    "emptyDirSync",
    "writeJsonSync",
];

/// Whether `property` of `module`, a module that is itself a function that
/// starts a program (`cross-spawn`, `execa`, `$` of execa), is a member the
/// reader reads as the call it is. Any other member of such a function
/// (`call`, `apply`, `bind`, or a name it does not know) hands the program
/// on to a call the reader does not see.
fn readable_member(module: &str, property: &str) -> bool {
    let members: &[&str] = match module {
        "cross-spawn" | "cross-spawn.default" => &["spawn", "sync", "default"],
        "execa" => &[
            "execa",
            "execaSync",
            "execaCommand",
            "execaCommandSync",
            "command",
            "commandSync",
            "sync",
            "$",
            "default",
        ],
        "execa.$" => &["sync", "s"],
        _ => return true,
    };
    members.contains(&property)
}

/// The calls, by the start of their name, that are given a path and only look
/// at its name, give back a string made of it, or look at the metadata of a
/// file or list a folder: they open nothing, so a path handed to one is no
/// reason to doubt the line. A call the reader does not know that is not one
/// of these, and is given a path, may read it, write it or delete it.
const NAMES_ONLY: &[&str] = &[
    "console.",
    "path.",
    "JSON.",
    "Math.",
    "Object.",
    "Array.",
    "String.",
    "Number.",
    "Date.",
    "Promise.",
    "Buffer.",
    "Symbol.",
    "process.stdout.",
    "process.stderr.",
    "process.env",
    "process.cwd",
    "process.emitWarning",
    "os.",
    "util.",
    "assert.",
    "crypto.",
    "querystring.",
    "url.",
    "events.",
    "fs.exists",
    "fs.stat",
    "fs.lstat",
    "fs.access",
    "fs.readdir",
    "fs.readlink",
    "fs.realpath",
    "fs.opendir",
    "fs.promises.stat",
    "fs.promises.lstat",
    "fs.promises.access",
    "fs.promises.readdir",
    "fs.promises.readlink",
    "fs.promises.realpath",
    "fs.promises.opendir",
    "Deno.stat",
    "Deno.lstat",
    "Deno.readDir",
    "Deno.readLink",
    "Deno.realPath",
    "Deno.cwd",
    "Deno.env.",
];

/// The methods of strings, arrays, maps, sets, streams and loggers that are
/// given a path as text or as an argument and open nothing: they cut it,
/// compare it, hold it, or write it as a message.
const METHODS_OF_TEXT: &[&str] = &[
    "startsWith",
    "endsWith",
    "split",
    "slice",
    "substring",
    "substr",
    "replace",
    "replaceAll",
    "concat",
    "join",
    "includes",
    "indexOf",
    "lastIndexOf",
    "match",
    "matchAll",
    "test",
    "push",
    "unshift",
    "get",
    "set",
    "has",
    "add",
    "toString",
    "trim",
    "trimStart",
    "trimEnd",
    "padStart",
    "padEnd",
    "normalize",
    "toLowerCase",
    "toUpperCase",
    "log",
    "error",
    "warn",
    "info",
    "debug",
    "write",
    "end",
    "then",
    "catch",
    "finally",
    "on",
    "once",
    "emit",
    "resolve",
    "reject",
    "localeCompare",
    "charAt",
    "at",
    "includes",
    "forEach",
    "map",
    "filter",
];

/// The properties of an options object whose truth means a file is written.
const WRITE_OPTIONS: [&str; 5] = ["write", "append", "create", "createNew", "truncate"];

/// The argument a `require` call names its module in, when there is one.
struct Source<'t>(Option<Node<'t>>);

/// The argument that names the module when a call to `name` is a `require`
/// (also `process.getBuiltinModule`, Bun's `import.meta.require`, and
/// `require.call(this, 'fs')`, `require.apply(this, ['fs'])`): `None` when it
/// is not one, and a [`Source`] with no node when the module is not an
/// argument the reader can find.
fn require_source<'t>(name: Option<&str>, args: &Args<'t>) -> Option<Source<'t>> {
    let name = name?;
    if kind(name) == Some(Kind::Require) {
        return Some(Source(args.get(0)));
    }
    if let Some(base) = name.strip_suffix(".call") {
        if kind(base) == Some(Kind::Require) {
            return Some(Source(args.get(1)));
        }
    }
    if let Some(base) = name.strip_suffix(".apply") {
        if kind(base) == Some(Kind::Require) {
            return Some(Source(
                args.get(1)
                    .filter(|list| list.kind() == "array")
                    .and_then(|list| list.named_child(0)),
            ));
        }
    }
    None
}

/// Whether the value of an expression is used: it is anything but a
/// statement of its own.
fn value_used(above: &[Ancestor<'_>]) -> bool {
    above
        .iter()
        .rev()
        .find(|parent| parent.node.kind() != "parenthesized_expression")
        .is_some_and(|parent| parent.node.kind() != "expression_statement")
}

struct Reader<'s> {
    src: &'s str,
    /// What each name a `require`, an `import` or a destructuring binds
    /// stands for: `rm` from `const { rm } = require('fs/promises')` is
    /// `fs.promises.rm`.
    aliases: HashMap<String, String>,
    /// The modules `require` and `import` named: an object that holds the
    /// calls the reader looks for, which handed on as a value may come back
    /// under a name it does not follow.
    modules: HashSet<String>,
    /// The dotted name of each node, found once: a chain of members is asked
    /// for from each node in it, and would be built again each time. Only
    /// filled once the names `require` and `import` bound are all known.
    names: HashMap<usize, Option<String>>,
    walking: bool,
    reading: Reading,
    /// How many pieces of literal code (`eval("…")`) this code is inside.
    nesting: usize,
    /// Whether literal code given to `eval` in this code, or in code inside
    /// it, binds or uses a name the reader follows.
    shared: bool,
    /// The strings each name is set to in the code, as the reader knows
    /// them.
    constants: Constants,
    /// Whether a name is put back as its constant. Only where a file is
    /// read: a path the reader cannot name is no more than unknown, and a
    /// delete or a write to it is judged as such.
    constants_on: bool,
}

/// The shells whose `-c` reads a command line: another program named by
/// `shell` is run with `-c LINE` and reads the line its own way.
const SHELLS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "ash"];

/// The arguments of a call.
struct Args<'t> {
    positional: Vec<Node<'t>>,
    /// Whether a spread (`...args`) may stand for any argument.
    splat: bool,
}

impl<'t> Args<'t> {
    fn read(call: Node<'t>) -> Self {
        let mut args = Self {
            positional: Vec::new(),
            splat: false,
        };
        let Some(list) = call.child_by_field_name("arguments") else {
            return args;
        };
        if list.kind() == "template_string" {
            args.positional.push(list);
            return args;
        }
        let mut cursor = list.walk();
        for child in list.named_children(&mut cursor) {
            match child.kind() {
                "spread_element" => args.splat = true,
                "comment" => {}
                _ => args.positional.push(child),
            }
        }
        args
    }

    fn get(&self, at: usize) -> Option<Node<'t>> {
        self.positional.get(at).copied()
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
        }
    }

    /// Note each string a name is set to anywhere in the code, for the reads
    /// of files ([`Self::read_target`]): by an assignment, or by a loop over
    /// strings written out. Every string is noted, up to a number of bytes in
    /// all and a length for each ([`Constants`]): a name set to more, or to a
    /// string built from one of those, is dropped, and a read of it is code
    /// the reader does not follow. A name grown in place (`k += …`) is
    /// dropped too. Whatever else the name is set to adds none.
    fn collect_constants(&mut self, root: Node<'_>) {
        let mut found = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "variable_declarator"
            | "assignment_expression"
            | "augmented_assignment_expression"
            | "for_in_statement" => {
                found.push(node);
            }
            _ => {}
        });
        self.constants_on = true;
        for node in found {
            let looped = node.kind() == "for_in_statement";
            let (name, value) = if node.kind() == "variable_declarator" {
                (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                )
            } else {
                (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                )
            };
            let (Some(name), Some(mut value)) = (name, value) else {
                continue;
            };
            if name.kind() != "identifier" {
                continue;
            }
            let name = self.text(name);
            if node.kind() == "augmented_assignment_expression" {
                // `k += '/id_rsa'`: a string the reader does not work out.
                self.constants.drop_name(name);
                continue;
            }
            // `a = b = 'x'` sets `a` to the string too.
            while value.kind() == "assignment_expression" {
                let Some(next) = value.child_by_field_name("right") else {
                    break;
                };
                value = next;
            }
            self.constants.lost = false;
            let mut values = Vec::new();
            if !looped {
                values.extend(self.all_parts(value).into_iter().filter_map(Parts::value));
            } else if value.kind() == "array" {
                // `for (const f of ['a', 'b'])`: each in turn.
                let mut cursor = value.walk();
                let items: Vec<Node<'_>> = value.named_children(&mut cursor).collect();
                for item in items {
                    values.extend(self.all_parts(item).into_iter().filter_map(Parts::value));
                }
            }
            if std::mem::take(&mut self.constants.lost) {
                self.constants.drop_name(name);
                continue;
            }
            for value in values {
                self.constants.note(name, value);
            }
        }
        self.constants_on = false;
    }

    /// The file the first argument names, written or read.
    fn open_file(&mut self, args: &Args<'_>, writes_file: bool) {
        if writes_file {
            let target = self.target(args, 0);
            self.act(target.map(Act::Write));
        } else {
            for source in self.read_target(args, 0) {
                self.reading.acts.push(Act::Read(source));
            }
        }
    }

    /// The paths the argument at `at` of a call that reads a file may name:
    /// a name the code sets to a string is read as each string it is set
    /// to.
    fn read_target(&mut self, args: &Args<'_>, at: usize) -> Vec<Arg> {
        let Some(node) = args.get(at) else {
            return self.target(args, at).into_iter().collect();
        };
        let text = self.text(node);
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
        // The start a path is known to have is the folder it is under, when
        // the rest is only known when the code runs.
        self.constants_on = true;
        self.constants.lost = false;
        let all = self.all_parts(node);
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

    /// `node` as far as the code gives it, once for each choice of one string
    /// for each name in it that holds more than one (`for (const n of ['a',
    /// 'b'])`). Where names are put back as their strings.
    fn all_parts(&mut self, node: Node<'_>) -> Vec<Parts> {
        self.constants.begin();
        let mut found: Vec<Parts> = Vec::new();
        loop {
            let parts = self.parts(node, 0);
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

    /// Read every node under `root`, once the names `require`, `import` and
    /// destructuring bound are known. The walk stops once the code is found
    /// to nest too deeply to read: the line is unreadable whatever else is
    /// in it.
    fn walk_all(&mut self, root: Node<'_>) {
        self.collect_constants(root);
        self.walking = true;
        walk(root, |node, field, above| {
            // A name written with an escape (`\u0072mSync`) is the name it
            // spells; the reader does not decode it, so it follows none.
            if node.kind().ends_with("identifier") && self.text(node).contains('\\') {
                self.reading.unread(self.text(node));
            }
            match node.kind() {
                "import_statement" | "export_statement" => self.module_source(node),
                "call_expression" | "new_expression" => self.call(node, field, above),
                "member_expression"
                | "identifier"
                | "shorthand_property_identifier"
                | "subscript_expression" => self.reference(node, field, above),
                // `with (require('fs')) rmSync(…)`: every name in the block
                // may be a member of the object.
                "with_statement" => self.reading.unread(self.text(node)),
                _ => {}
            }
            if node.kind() == "subscript_expression" {
                self.subscript(node);
            }
            !self.reading.deep
        });
    }

    fn text(&self, node: Node<'_>) -> &'s str {
        unit::text(&node, self.src)
    }

    /// What a name stands for in this code: what `require`, `import` or a
    /// destructuring bound it to, or itself.
    fn resolve(&self, name: &str) -> String {
        self.aliases
            .get(name)
            .cloned()
            .unwrap_or_else(|| fresh(name))
    }

    /// Whether `name`, a dotted name the reader found, is one it reads calls
    /// by: a call it knows, or a module or an object that holds them.
    fn followed(&self, name: &str) -> bool {
        kind(name).is_some() || self.holds_calls(name)
    }

    /// Whether literal code `eval` runs shares names with this code, in a
    /// way the reader would not see: the code runs in this code's scope, so a
    /// name it binds is a name here (`eval("var m = require('fs')")`, then
    /// `m.rm(…)`), and a name this code bound is one there (`const f =
    /// require('fs')`, then `eval("f.rm(…)")`). The nested code is read
    /// apart, from a table of its own. So when it binds a name to what the
    /// reader follows other than the name stands for here, or uses a name
    /// bound here to such a thing, the line is not read. The same is asked of
    /// the code inside the nested code, at any depth; past the depth that can
    /// be read, it is yes.
    fn shares_names(&mut self, text: &str) -> bool {
        if self.nesting >= unit::MAX_DEPTH {
            return true;
        }
        let ended = end_hashbang(text);
        let Some(tree) = parse(&ended) else {
            return false;
        };
        let root = tree.root_node();
        // Code that does not parse raises before it runs a thing.
        if root.has_error() {
            return false;
        }
        let mut inner = Reader::new(
            &ended,
            self.aliases.clone(),
            self.modules.clone(),
            self.nesting + 1,
        );
        inner.collect_aliases(root);
        let mut shares = inner.reading.deep
            || inner
                .aliases
                .iter()
                .any(|(name, value)| *value != self.resolve(name) && inner.followed(value));
        walk(root, |node, _, _| {
            if matches!(node.kind(), "identifier" | "shorthand_property_identifier") {
                let name = unit::text(&node, &ended);
                if let Some(value) = self.aliases.get(name) {
                    shares |= *value != fresh(name) && self.followed(value);
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

    fn collect_aliases(&mut self, root: Node<'_>) {
        let mut found = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "variable_declarator" | "assignment_expression" | "import_statement" => {
                found.push(node);
            }
            _ => {}
        });
        // A name can be bound from one bound before it (`const p = fs.promises`),
        // in the order the code gives them.
        for node in found {
            match node.kind() {
                "import_statement" => self.import(node),
                "variable_declarator" => {
                    if let (Some(name), Some(value)) = (
                        node.child_by_field_name("name"),
                        node.child_by_field_name("value"),
                    ) {
                        self.bind(name, value);
                    }
                }
                _ => {
                    if let (Some(name), Some(value)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
                        self.bind(name, value);
                    }
                }
            }
        }
    }

    /// `import fs from 'fs'`, `import * as fs from 'fs'`,
    /// `import { rmSync as rm } from 'node:fs'`.
    fn import(&mut self, node: Node<'_>) {
        let Some(source) = node.child_by_field_name("source") else {
            return;
        };
        let Some(source) = self.literal(source) else {
            return;
        };
        let module = module(&source);
        let mut cursor = node.walk();
        let clauses: Vec<Node<'_>> = node.children(&mut cursor).collect();
        for clause in clauses {
            if clause.kind() != "import_clause" {
                continue;
            }
            let mut inner = clause.walk();
            for part in clause.named_children(&mut inner) {
                match part.kind() {
                    "identifier" => {
                        self.aliases
                            .insert(self.text(part).to_string(), module.clone());
                        self.modules.insert(module.clone());
                    }
                    "namespace_import" => {
                        if let Some(name) = part.named_child(0) {
                            self.aliases
                                .insert(self.text(name).to_string(), module.clone());
                            self.modules.insert(module.clone());
                        }
                    }
                    "named_imports" => {
                        let mut names = part.walk();
                        let specifiers: Vec<Node<'_>> = part.named_children(&mut names).collect();
                        for specifier in specifiers {
                            let real = specifier.child_by_field_name("name");
                            let alias = specifier.child_by_field_name("alias").or(real);
                            if let (Some(real), Some(alias)) = (real, alias) {
                                // `{ "rmSync" as r }` names the member the
                                // string spells; one the reader cannot
                                // decode is a member it cannot follow.
                                let Some(property) = self.key_name(real) else {
                                    self.reading.unread(self.text(specifier));
                                    continue;
                                };
                                let member = member(&module, &property);
                                self.aliases.insert(self.text(alias).to_string(), member);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Bind what `name` (an identifier or a destructuring pattern) takes
    /// from `value`.
    fn bind(&mut self, name: Node<'_>, value: Node<'_>) {
        let Some(from) = self.qualified(value, 0) else {
            return;
        };
        self.bind_pattern(name, &from, 0);
    }

    fn bind_pattern(&mut self, name: Node<'_>, from: &str, level: usize) {
        if level > MAX_TREE_DEPTH {
            self.reading.deep = true;
            return;
        }
        match name.kind() {
            "identifier" => {
                self.aliases
                    .insert(self.text(name).to_string(), from.to_string());
            }
            // `{ rmSync: r = null }`: the name takes the member.
            "assignment_pattern" => {
                if let Some(left) = name.child_by_field_name("left") {
                    self.bind_pattern(left, from, level + 1);
                }
            }
            "object_pattern" => {
                let mut cursor = name.walk();
                for part in name.named_children(&mut cursor) {
                    match part.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let property = self.text(part);
                            let member = member(from, property);
                            self.aliases.insert(property.to_string(), member);
                        }
                        // `{ rmSync = null }`: the member, with a default for
                        // when it is not there.
                        "object_assignment_pattern" => {
                            if let Some(left) = part.child_by_field_name("left") {
                                let property = self.text(left);
                                let member = member(from, property);
                                self.aliases.insert(property.to_string(), member);
                            }
                        }
                        "pair_pattern" => {
                            if let (Some(key), Some(value)) = (
                                part.child_by_field_name("key"),
                                part.child_by_field_name("value"),
                            ) {
                                match self.key_name(key) {
                                    Some(property) => {
                                        let inner = member(from, &property);
                                        self.bind_pattern(value, &inner, level + 1);
                                    }
                                    // A key only known when it runs, taken
                                    // from a module, is a member under a
                                    // name the reader cannot follow.
                                    None if self.holds_calls(from) => {
                                        self.reading.unread(self.text(part));
                                    }
                                    None => {}
                                }
                            }
                        }
                        // `{ ...rest }` of a module holds all of its members
                        // under a name that is not theirs.
                        "rest_pattern" if self.is_module(from) => {
                            self.reading.unread(self.text(name));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// The member a key of a destructuring pattern or an import names:
    /// `rmSync`, `"rmSync"`, `["rmSync"]`, ``[`rm${"Sync"}`]``, a number. A
    /// key only known when it runs (`[k]`) or a string whose escapes the
    /// reader does not decode names none.
    fn key_name(&mut self, key: Node<'_>) -> Option<String> {
        match key.kind() {
            "string" | "template_string" => self.literal(key),
            "computed_property_name" => {
                let inner = key.named_child(0)?;
                match inner.kind() {
                    "number" => Some(self.text(inner).to_string()),
                    _ => self.value(inner, 0),
                }
            }
            // A name, a number, or a word that is one only here (`default`).
            _ => Some(self.text(key).to_string()),
        }
    }

    /// Whether `name` is a module, or a member of one that is a namespace of
    /// its own (`fs.promises`): an object a key looked up on is a call the
    /// reader looks for.
    fn holds_calls(&self, name: &str) -> bool {
        self.is_module(name)
            || ROOTS.iter().any(|root| {
                name.strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('.'))
            })
    }

    /// The dotted name `node` stands for, once the names bound by `require`,
    /// `import` and destructuring are put back: `fs.promises.rm`,
    /// `child_process.execSync`. `None` for what is not a name.
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

    /// `import 'data:…'`, `export * from 'data:…'`: the code in a `data:` URL
    /// runs where it is written, and is not read.
    fn module_source(&mut self, node: Node<'_>) {
        let Some(source) = node.child_by_field_name("source") else {
            return;
        };
        if self
            .literal(source)
            .is_none_or(|specifier| super::data_url(&specifier))
        {
            self.reading.unread(self.text(node));
        }
    }

    /// Whether `name` is an object that holds calls the reader looks for.
    fn is_module(&self, name: &str) -> bool {
        ROOTS.contains(&name)
            || matches!(
                name,
                "require" | "process.getBuiltinModule" | "import.meta.require"
            )
            || self.modules.contains(name)
    }

    fn name(&mut self, node: Node<'_>, level: usize) -> Option<String> {
        match node.kind() {
            "identifier" | "shorthand_property_identifier" => {
                let name = self.text(node);
                Some(self.aliases.get(name).cloned().unwrap_or_else(|| {
                    if matches!(name, "global" | "window") {
                        GLOBAL.to_string()
                    } else {
                        name.to_string()
                    }
                }))
            }
            // `this` is the global object in `node -e`.
            "this" => Some(THIS.to_string()),
            // Bun's `import.meta.require`.
            "meta_property" => Some("import.meta".to_string()),
            "member_expression" => {
                let object = node.child_by_field_name("object")?;
                let property = node.child_by_field_name("property")?;
                let property = self.text(property).to_string();
                let object = self.qualified(object, level + 1)?;
                Some(member(&object, &property))
            }
            "subscript_expression" => {
                let object = node.child_by_field_name("object")?;
                let index = node.child_by_field_name("index")?;
                let index = self.literal(index)?;
                let object = self.qualified(object, level + 1)?;
                Some(member(&object, &index))
            }
            "parenthesized_expression" | "await_expression" => {
                let inner = node.named_child(0)?;
                self.qualified(inner, level + 1)
            }
            // `a = b = require('fs')`: `a` is the module too.
            "assignment_expression" => {
                let right = node.child_by_field_name("right")?;
                self.qualified(right, level + 1)
            }
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                let called = self.qualified(function, level + 1);
                // `require.bind(null)` is `require` again.
                if let Some(bound) = called
                    .as_deref()
                    .and_then(|name| name.strip_suffix(".bind"))
                {
                    return (kind(bound) == Some(Kind::Require)).then(|| bound.to_string());
                }
                // `require('fs')`, `require.call(null, 'fs')`, `import('fs')`,
                // `process.getBuiltinModule('fs')` are the module.
                let args = Args::read(node);
                let source = if self.text(function) == "import" {
                    args.get(0)
                } else {
                    require_source(called.as_deref(), &args)?.0
                };
                let source = self.literal(source?)?;
                let module = module(&source);
                self.modules.insert(module.clone());
                Some(module)
            }
            _ => None,
        }
    }

    /// A string literal, or a template without substitutions.
    fn literal(&mut self, node: Node<'_>) -> Option<String> {
        match node.kind() {
            "string" | "template_string" => self.value(node, 0),
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
            "string" => {
                let mut text = String::new();
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
                    match part.kind() {
                        "string_fragment" => text.push_str(self.text(part)),
                        "escape_sequence" => match unescape(self.text(part)) {
                            Some(decoded) => text.push_str(&decoded),
                            None => return Parts::partial(text),
                        },
                        _ => {}
                    }
                }
                Parts::whole(text)
            }
            "template_string" => {
                let mut text = String::new();
                let mut cursor = node.walk();
                let parts: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                for part in parts {
                    match part.kind() {
                        "string_fragment" => text.push_str(self.text(part)),
                        "escape_sequence" => match unescape(self.text(part)) {
                            Some(decoded) => text.push_str(&decoded),
                            None => return Parts::partial(text),
                        },
                        "template_substitution" => {
                            let Some(expression) = part.named_child(0) else {
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
            "parenthesized_expression" | "await_expression" => match node.named_child(0) {
                Some(inner) => self.parts(inner, level + 1),
                None => Parts::unknown(),
            },
            "binary_expression" => {
                let (Some(operator), Some(left), Some(right)) = (
                    node.child_by_field_name("operator"),
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return Parts::unknown();
                };
                if self.text(operator) != "+" {
                    return Parts::unknown();
                }
                let left = self.parts(left, level + 1);
                if !left.whole {
                    return left;
                }
                let right = self.parts(right, level + 1);
                Parts {
                    text: format!("{}{}", left.text, right.text),
                    whole: right.whole,
                }
            }
            "member_expression" | "identifier" | "subscript_expression" => {
                if self.constants_on && node.kind() == "identifier" {
                    match self.constants.holds(self.text(node)) {
                        Holds::One(text) => return Parts::whole(text),
                        Holds::Below(folder) => return Parts::partial(folder),
                        Holds::Lost => return Parts::unknown(),
                        Holds::Nothing => {}
                    }
                }
                let Some(name) = self.qualified(node, level + 1) else {
                    return Parts::unknown();
                };
                name.strip_prefix("process.env.")
                    .or_else(|| name.strip_prefix("Bun.env."))
                    .and_then(environment)
                    .map_or_else(Parts::unknown, Parts::whole)
            }
            "call_expression" => self.parts_of_call(node, level),
            _ => Parts::unknown(),
        }
    }

    /// Each of `nodes` joined to `text` as `path.join` does: the start known
    /// when one of them is only known when the code runs.
    fn joined(&mut self, mut text: String, nodes: &[Node<'_>], level: usize) -> Parts {
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

    fn parts_of_call(&mut self, call: Node<'_>, level: usize) -> Parts {
        let Some(function) = call.child_by_field_name("function") else {
            return Parts::unknown();
        };
        let args = Args::read(call);
        let name = self.qualified(function, level + 1);
        let first = |reader: &mut Self| match args.positional.first().copied() {
            Some(node) => reader.parts(node, level + 1),
            None => Parts::unknown(),
        };
        let whole = |text: &str| Parts::whole(text.to_string());
        match name.as_deref() {
            Some("path.join" | "path.resolve") => {
                let parts = self.joined(String::new(), &args.positional, level);
                if parts.whole && parts.text.is_empty() {
                    whole(".")
                } else {
                    parts
                }
            }
            Some("path.normalize" | "String") => first(self),
            Some("path.dirname") => first(self)
                .value()
                .map_or_else(Parts::unknown, |text| Parts::whole(join(&text, ".."))),
            Some("os.homedir") => whole("~"),
            Some("os.tmpdir") => whole("/tmp"),
            Some("process.cwd" | "Deno.cwd") => whole("."),
            Some("Deno.env.get") => first(self)
                .value()
                .and_then(|name| environment(&name))
                .map_or_else(Parts::unknown, Parts::whole),
            _ => {
                let Some(property) = function.child_by_field_name("property") else {
                    return Parts::unknown();
                };
                let Some(receiver) = function.child_by_field_name("object") else {
                    return Parts::unknown();
                };
                match self.text(property) {
                    "toString" if args.positional.is_empty() => self.parts(receiver, level + 1),
                    // `'/home/me/.ssh/'.concat(name)`.
                    "concat" if matches!(receiver.kind(), "string" | "template_string") => {
                        let mut parts = self.parts(receiver, level + 1);
                        for node in &args.positional {
                            if !parts.whole {
                                break;
                            }
                            let part = self.parts(*node, level + 1);
                            parts = Parts {
                                text: format!("{}{}", parts.text, part.text),
                                whole: part.whole,
                            };
                            if self.constants.over(self.constants_on, &parts.text) {
                                return Parts::unknown();
                            }
                        }
                        parts
                    }
                    // `['/home/me/.ssh', name].join('/')`.
                    "join" if receiver.kind() == "array" => {
                        let separator = match args.positional.first().copied() {
                            Some(node) => self.parts(node, level + 1).value(),
                            None => Some(",".to_string()),
                        };
                        let Some(separator) = separator else {
                            return Parts::unknown();
                        };
                        let mut cursor = receiver.walk();
                        let items: Vec<Node<'_>> = receiver
                            .named_children(&mut cursor)
                            .filter(|item| item.kind() != "comment")
                            .collect();
                        let mut text = String::new();
                        for (at, item) in items.into_iter().enumerate() {
                            if at > 0 {
                                text.push_str(&separator);
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

    /// The path argument at `at`; unknown when a spread may hold it, and
    /// `None` when the call has none.
    fn target(&mut self, args: &Args<'_>, at: usize) -> Option<Arg> {
        match args.get(at) {
            Some(node) => Some(self.arg(node)),
            None if args.splat => Some(Arg::Unknown("...args".to_string())),
            None => None,
        }
    }

    fn act(&mut self, act: Option<Act>) {
        self.reading.acts.extend(act);
    }

    /// The operand of a call to `new Deno.Command(…)`/`Bun.file(…)`: what
    /// `node` is when it is such a call, with its first argument.
    fn constructed<'t>(&mut self, node: Node<'t>, name: &str) -> Option<Args<'t>> {
        let node = if node.kind() == "parenthesized_expression" {
            node.named_child(0)?
        } else {
            node
        };
        let function = match node.kind() {
            "call_expression" => node.child_by_field_name("function")?,
            "new_expression" => node.child_by_field_name("constructor")?,
            _ => return None,
        };
        (self.qualified(function, 0).as_deref() == Some(name)).then(|| Args::read(node))
    }

    fn call<'t>(&mut self, call: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) {
        let function = if call.kind() == "new_expression" {
            call.child_by_field_name("constructor")
        } else {
            call.child_by_field_name("function")
        };
        let Some(function) = function else {
            return;
        };
        // `x.constructor('code')()` builds a function from a string.
        if function.kind() == "member_expression"
            && function
                .child_by_field_name("property")
                .is_some_and(|property| self.text(property) == "constructor")
        {
            self.reading.unread(self.text(call));
        }
        let args = Args::read(call);
        let name = self.qualified(function, 0);
        // The web's `setTimeout('code')` and `setInterval('code')` run a
        // string as code, and Deno follows it (node and bun throw): code the
        // reader would have to take from the string, so a first argument that
        // is, or may be, a string is code it does not read. A function (a
        // name, an arrow, a call) is walked where it is written. Handed on
        // with `.call`, `.apply` or `.bind` the argument is not the first.
        if let Some(name) = name.as_deref() {
            let base = name
                .strip_suffix(".call")
                .or_else(|| name.strip_suffix(".apply"))
                .or_else(|| name.strip_suffix(".bind"));
            let timer = |name: &str| matches!(name, "setTimeout" | "setInterval");
            let first = call.child_by_field_name("arguments").and_then(|list| {
                let mut cursor = list.walk();
                let mut parts = list.named_children(&mut cursor);
                parts.find(|node| node.kind() != "comment")
            });
            let text = first.is_some_and(|node| {
                matches!(
                    node.kind(),
                    "string" | "template_string" | "binary_expression" | "spread_element"
                )
            });
            if base.is_some_and(timer) || (timer(name) && text) {
                self.reading.unread(self.text(call));
            }
        }
        // What starts a program is run from where `cwd` says.
        let before = self.reading.acts.len();
        let mut cwd = None;
        // `require.call(null, 'fs')` and `process.getBuiltinModule('fs')` are
        // calls of `require` too.
        let requires = require_source(name.as_deref(), &args);
        let kind = if requires.is_some() {
            Some(Kind::Require)
        } else {
            name.as_deref().and_then(kind)
        };
        match kind {
            Some(Kind::Remove) => {
                let target = self.target(&args, 0);
                self.act(target.map(Act::Remove));
            }
            Some(Kind::Write) => {
                let target = self.target(&args, 0);
                self.act(target.map(Act::Write));
            }
            Some(Kind::Copy) => {
                // `cp` and `cpSync` copy a folder and all that is in it, and
                // so does `fs-extra`'s `copy`.
                let call = name.as_deref().unwrap_or_default();
                let tree = call.starts_with("fs-extra.copy")
                    || matches!(call.rsplit('.').next(), Some("cp" | "cpSync"));
                for source in self.read_target(&args, 0) {
                    self.reading.acts.push(if tree {
                        Act::ReadTree(source)
                    } else {
                        Act::Read(source)
                    });
                }
                let target = self.target(&args, 1);
                self.act(target.map(Act::Write));
            }
            Some(Kind::Move) => {
                let from = self.target(&args, 0);
                let to = self.target(&args, 1);
                self.act(from.zip(to).map(|(from, to)| Act::Move { from, to }));
            }
            Some(Kind::Link) => {
                let target = self.target(&args, 0);
                let link = self.target(&args, 1);
                self.act(
                    target
                        .zip(link)
                        .map(|(target, link)| Act::Link { target, link }),
                );
            }
            Some(Kind::Chmod) => {
                let path = self.target(&args, 0);
                let mode = args.get(1).map_or_else(
                    || Arg::Unknown("mode".to_string()),
                    |node| match (node.kind(), mode(self.text(node))) {
                        ("number", Some(octal)) => Arg::Known(octal),
                        _ => Arg::Unknown(super::shorten(self.text(node))),
                    },
                );
                self.act(path.map(|path| Act::Chmod { path, mode }));
            }
            Some(Kind::Chown) => {
                let target = self.target(&args, 0);
                self.act(target.map(Act::Chown));
            }
            Some(Kind::Chdir) => {
                let target = self.target(&args, 0);
                self.act(target.map(Act::Chdir));
            }
            Some(Kind::Kill) => match args.get(0) {
                // A spread may hold the process id, or come before it.
                _ if args.splat => self.reading.unread(self.text(call)),
                Some(node) => {
                    let pid = self.text(node);
                    self.reading.acts.push(super::kill(pid));
                }
                None => {}
            },
            Some(Kind::Open) => {
                // No flags reads; flags only known when it runs may write.
                let writes_file = match args.get(1) {
                    Some(node) => self.literal(node).is_none_or(|flags| writes(Some(&flags))),
                    None => args.splat,
                };
                self.open_file(&args, writes_file);
            }
            Some(Kind::ReadFile) => {
                let writes_file = match args.get(1) {
                    Some(node) => self.read_flag_writes(node),
                    None => args.splat,
                };
                self.open_file(&args, writes_file);
            }
            Some(Kind::DenoOpen) => {
                let writes_file = match args.get(1) {
                    Some(node) if node.kind() == "object" => self.options_write(node),
                    Some(_) => true,
                    None => args.splat,
                };
                self.open_file(&args, writes_file);
            }
            Some(Kind::BunWrite) => {
                let target = match args.get(0) {
                    Some(node) => match self.constructed(node, "Bun.file") {
                        Some(inner) => self.target(&inner, 0),
                        None => Some(self.arg(node)),
                    },
                    None => self.target(&args, 0),
                };
                self.act(target.map(Act::Write));
            }
            Some(Kind::BunFile) => {
                for source in self.read_target(&args, 0) {
                    self.reading.acts.push(Act::Read(source));
                }
            }
            Some(Kind::Script) => {
                let command = self.target(&args, 0);
                self.act(command.map(Act::Script));
                cwd = self.cwd(args.get(1));
                self.foreign_shell(args.get(1), call);
                // `` $`…`.cwd(dir) ``
                if cwd.is_none() && matches!(name.as_deref(), Some("Bun.$" | "zx.$")) {
                    cwd = self.chained_cwd(field, above);
                }
            }
            Some(Kind::Spawn) => cwd = self.spawn(&args, call),
            Some(Kind::Fork) => self.fork(&args, call),
            Some(Kind::Shelljs) => {
                let program = name.as_deref().and_then(|name| name.rsplit('.').next());
                let mut words = vec![Arg::Known(program.unwrap_or_default().to_string())];
                for node in &args.positional {
                    if node.kind() == "array" {
                        words.extend(self.words(*node));
                    } else {
                        words.push(self.arg(*node));
                    }
                }
                self.act(Some(Act::Program(words)));
            }
            Some(Kind::DenoCommand) if args.splat => self.reading.unread(self.text(call)),
            Some(Kind::DenoCommand) => {
                let program = args.get(0).map(|node| self.arg(node));
                let options = args.get(1).filter(|node| node.kind() == "object");
                let mut words: Vec<Arg> = program.into_iter().collect();
                if let Some(list) = options.and_then(|options| self.property(options, "args")) {
                    words.extend(self.words(list));
                }
                self.act(Some(Act::Program(words)));
                cwd = self.cwd(args.get(1));
            }
            Some(Kind::Argv) => {
                let first = args.get(0);
                let list = match first {
                    Some(node) if node.kind() == "array" => Some(node),
                    Some(node) if node.kind() == "object" => self.property(node, "cmd"),
                    _ => None,
                };
                // `Bun.spawn(argv, { cwd })` and `Deno.run({ cmd, cwd })`.
                cwd = match first {
                    Some(node) if node.kind() == "object" => self.cwd(Some(node)),
                    _ => self.cwd(args.get(1)),
                };
                match list {
                    Some(list) => {
                        let words = self.words(list);
                        self.act(Some(Act::Program(words)));
                    }
                    None => self.reading.unread(self.text(call)),
                }
            }
            Some(Kind::Unread) => self.reading.unread(self.text(call)),
            Some(Kind::Eval) => {
                // The value of the code is a module or an object the reader
                // follows, if the call is not a statement of its own, and
                // comes back under no name.
                if value_used(above) {
                    self.reading.unread(self.text(call));
                }
                let literal = args
                    .get(0)
                    .filter(|node| node.kind() == "string")
                    .and_then(|node| self.value(node, 0));
                match literal {
                    Some(text) => {
                        if self.shares_names(&text) {
                            self.shared = true;
                            self.reading.unread(self.text(call));
                        }
                        self.reading
                            .acts
                            .push(Act::Code(Language::JavaScript, text));
                    }
                    None => self.reading.unread(self.text(call)),
                }
            }
            Some(Kind::Require) => {
                let source = requires.and_then(|found| found.0).or_else(|| args.get(0));
                if source.is_none_or(|node| self.literal(node).is_none()) {
                    self.reading.unread(self.text(call));
                } else if self.escapes(call, field, above) {
                    // The module, handed on as a value, unless it is called
                    // on the spot and is a function that starts a program:
                    // `require('cross-spawn')('ls')` is read as that call.
                    let called = field == Some("function")
                        && above
                            .last()
                            .is_some_and(|parent| parent.node.kind() == "call_expression")
                        && source
                            .and_then(|node| self.literal(node))
                            .is_some_and(|module| {
                                matches!(module.as_str(), "cross-spawn" | "execa")
                            });
                    if !called {
                        self.reading.unread(self.text(call));
                    }
                } else if let Some(parent) = above
                    .last()
                    .filter(|parent| parent.node.kind() == "member_expression")
                    .filter(|_| field == Some("object"))
                {
                    // `require('cross-spawn').call(null, 'rm')`: a function
                    // that starts a program, and a member of it that is not
                    // a call the reader reads.
                    let loaded = source
                        .and_then(|node| self.literal(node))
                        .map(|loaded| module(&loaded));
                    let property = parent.node.child_by_field_name("property");
                    if let (Some(loaded), Some(property)) = (loaded, property) {
                        if matches!(loaded.as_str(), "cross-spawn" | "execa")
                            && !readable_member(&loaded, self.text(property))
                        {
                            self.reading.unread(self.text(parent.node));
                        }
                    }
                }
            }
            None => {
                self.method(function, name.as_deref(), call);
                // A call the reader does not know is given a path.
                if self.reading.acts.len() == before {
                    self.unmodeled(function, name.as_deref(), &args);
                }
            }
        }
        self.within(cwd, before);
        // `import(x)`: a module loaded where the reader cannot follow it,
        // unless it is awaited, which `qualified` follows.
        if self.text(function) == "import" {
            let awaited = above
                .last()
                .is_some_and(|parent| parent.node.kind() == "await_expression");
            // The code in a `data:` URL runs where it is written.
            let data = args
                .get(0)
                .and_then(|node| self.literal(node))
                .is_some_and(|specifier| super::data_url(&specifier));
            if !awaited || data || self.escapes(call, field, above) {
                self.reading.unread(self.text(call));
            }
        }
    }

    /// Run what the call at `before` added from the directory `cwd` names: as
    /// if the line had gone there first. A directory only known when it runs
    /// cannot be told, so the call is `unknown` besides.
    fn within(&mut self, cwd: Option<Arg>, before: usize) {
        let Some(dir) = cwd else {
            return;
        };
        let acts = self.reading.acts.split_off(before);
        match dir {
            dir @ Arg::Known(_) => self.reading.acts.push(Act::In(dir, acts)),
            other => {
                self.reading.unread(other.text());
                self.reading.acts.extend(acts);
            }
        }
    }

    /// The `cwd` of an options object: `None` when it has none (or is
    /// `null`), a directory only known when it runs when it is not a plain
    /// value, or the options are not an object literal.
    fn cwd(&mut self, options: Option<Node<'_>>) -> Option<Arg> {
        let options = options?;
        match options.kind() {
            "object" => {}
            // A callback, not options.
            "arrow_function" | "function_expression" | "function" => return None,
            _ => return Some(Arg::Unknown(super::shorten(self.text(options)))),
        }
        let unknown = || Some(Arg::Unknown("cwd".to_string()));
        let mut cursor = options.walk();
        let members: Vec<Node<'_>> = options.named_children(&mut cursor).collect();
        let mut found = None;
        for member in members {
            match member.kind() {
                "comment" => {}
                "pair" => {
                    let Some(key) = member.child_by_field_name("key") else {
                        return unknown();
                    };
                    let name = match key.kind() {
                        "property_identifier" => self.text(key).to_string(),
                        "string" => match self.literal(key) {
                            Some(name) => name,
                            None => return unknown(),
                        },
                        _ => return unknown(),
                    };
                    if name == "cwd" {
                        found = match member.child_by_field_name("value") {
                            Some(value) if matches!(self.text(value), "undefined" | "null") => None,
                            Some(value) => Some(self.arg(value)),
                            None => return unknown(),
                        };
                    }
                }
                "shorthand_property_identifier" if self.text(member) != "cwd" => {}
                // `{ cwd }`, a method or accessor named `cwd`, a spread or a
                // computed name.
                "method_definition"
                    if member
                        .child_by_field_name("name")
                        .is_some_and(|name| self.text(name) != "cwd") => {}
                _ => return unknown(),
            }
        }
        found
    }

    /// The directory a call on the result of `` $`…` `` is told to work in
    /// by a `.cwd(dir)` after it, however many other methods come between.
    fn chained_cwd(&mut self, field: Option<&str>, above: &[Ancestor<'_>]) -> Option<Arg> {
        let mut field = field;
        let mut at = above.len();
        let mut found = None;
        while at >= 2 {
            let (member, outer) = (above[at - 1], above[at - 2]);
            if member.node.kind() != "member_expression"
                || field != Some("object")
                || member.field != Some("function")
                || outer.node.kind() != "call_expression"
            {
                break;
            }
            let method = member
                .node
                .child_by_field_name("property")
                .map(|property| self.text(property));
            if method == Some("cwd") {
                let args = Args::read(outer.node);
                found = Some(match args.get(0) {
                    Some(node) => self.arg(node),
                    None => Arg::Unknown("cwd".to_string()),
                });
            }
            field = outer.field;
            at -= 2;
        }
        found
    }

    /// `{ shell: '/usr/bin/python3' }` runs that program with `-c LINE`,
    /// which reads the line its own way: unlike a POSIX shell it is not read.
    fn foreign_shell(&mut self, options: Option<Node<'_>>, call: Node<'_>) {
        let Some(options) = options.filter(|options| options.kind() == "object") else {
            return;
        };
        let Some(shell) = self.property(options, "shell") else {
            return;
        };
        let posix = match shell.kind() {
            "true" | "false" => true,
            "string" | "template_string" => self.literal(shell).is_some_and(|program| {
                program
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| SHELLS.contains(&name))
            }),
            _ => false,
        };
        if !posix {
            self.reading.unread(self.text(call));
        }
    }

    /// Whether a module is put where the reader loses it: anywhere but as the
    /// object of a member (`fs.rmSync`), the value of a name it records
    /// (`const fs = require('fs')`, also in a chain or a destructuring), a
    /// name being set, `typeof`, or a statement of its own. Handed to a call,
    /// held in an array or an object, returned or looped over it may come
    /// back under a name the reader does not follow (`(f =>
    /// f.rmSync(…))(require('fs'))`).
    fn escapes<'t>(&self, node: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) -> bool {
        let mut field = field;
        let mut at = above.len();
        while let Some(parent) = at.checked_sub(1).and_then(|index| above.get(index)) {
            let is = |name: &str| field == Some(name);
            let names = |parent: &Ancestor<'t>, side: &str| {
                parent
                    .node
                    .child_by_field_name(side)
                    .is_some_and(|name| matches!(name.kind(), "identifier" | "object_pattern"))
            };
            match parent.node.kind() {
                "parenthesized_expression" | "await_expression" => {
                    field = parent.field;
                    at -= 1;
                }
                "member_expression" | "subscript_expression" => return !is("object"),
                "expression_statement" => return false,
                "variable_declarator" => return !(is("value") && names(parent, "name")),
                "assignment_expression" => {
                    return !(is("left") || (is("right") && names(parent, "left")));
                }
                "unary_expression" => return !self.text(parent.node).starts_with("typeof"),
                _ => return true,
            }
        }
        let _ = node;
        false
    }

    /// The value of the property `key` of an object literal.
    fn property<'t>(&mut self, object: Node<'t>, key: &str) -> Option<Node<'t>> {
        let mut cursor = object.walk();
        let pairs: Vec<Node<'t>> = object.named_children(&mut cursor).collect();
        pairs.into_iter().find_map(|pair| {
            let name = pair.child_by_field_name("key")?;
            let name = match name.kind() {
                "property_identifier" => self.text(name).to_string(),
                _ => self.literal(name)?,
            };
            (pair.kind() == "pair" && name == key)
                .then(|| pair.child_by_field_name("value"))
                .flatten()
        })
    }

    /// Whether the options of a call that reads a file open it for writing:
    /// a `flag` (`flags` for a stream) that writes, or one only known when it
    /// runs, in an object literal. A string is the encoding and a callback
    /// is not options; any other value, or an object with a spread, a
    /// computed name or a method of that name, may hold a flag.
    fn read_flag_writes(&mut self, options: Node<'_>) -> bool {
        match options.kind() {
            "string" | "template_string" => return self.literal(options).is_none(),
            "arrow_function" | "function_expression" | "function" | "null" | "undefined" => {
                return false
            }
            "object" => {}
            _ => return true,
        }
        let mut cursor = options.walk();
        let members: Vec<Node<'_>> = options.named_children(&mut cursor).collect();
        members.into_iter().any(|member| match member.kind() {
            "comment" => false,
            "pair" => {
                let name = member
                    .child_by_field_name("key")
                    .and_then(|key| match key.kind() {
                        "property_identifier" => Some(self.text(key).to_string()),
                        "string" => self.literal(key),
                        _ => None,
                    });
                match name.as_deref() {
                    Some("flag" | "flags") => member
                        .child_by_field_name("value")
                        .and_then(|value| self.literal(value))
                        .is_none_or(|flags| writes(Some(&flags))),
                    Some(_) => false,
                    None => true,
                }
            }
            "shorthand_property_identifier" => matches!(self.text(member), "flag" | "flags"),
            "method_definition" => member
                .child_by_field_name("name")
                .is_none_or(|name| match name.kind() {
                    "property_identifier" => matches!(self.text(name), "flag" | "flags"),
                    "string" => self
                        .literal(name)
                        .is_none_or(|name| matches!(name.as_str(), "flag" | "flags")),
                    _ => true,
                }),
            _ => true,
        })
    }

    /// Whether the options object of `Deno.open` turns a way of writing on:
    /// a property that is not plainly `false`.
    fn options_write(&mut self, options: Node<'_>) -> bool {
        let mut cursor = options.walk();
        let pairs: Vec<Node<'_>> = options.named_children(&mut cursor).collect();
        pairs.into_iter().any(|pair| match pair.kind() {
            "pair" => {
                let key = pair
                    .child_by_field_name("key")
                    .map(|key| self.text(key).trim_matches(['"', '\'']));
                let on = pair
                    .child_by_field_name("value")
                    .is_some_and(|value| self.text(value) != "false");
                key.is_some_and(|key| WRITE_OPTIONS.contains(&key)) && on
            }
            "shorthand_property_identifier" => WRITE_OPTIONS.contains(&self.text(pair)),
            _ => true,
        })
    }

    /// The words of an array literal, each as an argument.
    fn words(&mut self, list: Node<'_>) -> Vec<Arg> {
        if list.kind() != "array" {
            return vec![Arg::Unknown(super::shorten(self.text(list)))];
        }
        let mut cursor = list.walk();
        let elements: Vec<Node<'_>> = list.named_children(&mut cursor).collect();
        elements
            .into_iter()
            .filter(|element| element.kind() != "comment")
            .map(|element| {
                if element.kind() == "spread_element" {
                    Arg::Unknown(super::shorten(self.text(element)))
                } else {
                    self.arg(element)
                }
            })
            .collect()
    }

    /// `fork('worker.js', ['arg'], { cwd })` runs node on the module, a file
    /// of the workspace's own as `node worker.js` is. Not so when the module
    /// is a word that is only known when it runs or starts with `-` (node
    /// reads it as an option: `fork('-e', ['code'])` runs the code), or when
    /// the options name the program (`execPath`) or the options it is run
    /// with (`execArgv`: `['-e', 'code']`), or are not an object literal that
    /// shows what it holds.
    fn fork(&mut self, args: &Args<'_>, call: Node<'_>) {
        let module = args.get(0).and_then(|node| self.value(node, 0));
        let mut reads = module.is_some_and(|module| !module.starts_with('-')) && !args.splat;
        for node in args.positional.iter().skip(1) {
            match node.kind() {
                "array" => {}
                "object" => reads &= self.fork_options(*node),
                _ => reads = false,
            }
        }
        if !reads {
            self.reading.unread(self.text(call));
        }
    }

    /// Whether the options of a `fork` leave the program and its options as
    /// they are: an object literal with no `execPath` or `execArgv`, and no
    /// member that could be one (a spread, a computed name, a method).
    fn fork_options(&mut self, options: Node<'_>) -> bool {
        let mut cursor = options.walk();
        let members: Vec<Node<'_>> = options.named_children(&mut cursor).collect();
        members.into_iter().all(|member| match member.kind() {
            "comment" => true,
            "pair" => {
                let name = member
                    .child_by_field_name("key")
                    .and_then(|key| match key.kind() {
                        "property_identifier" => Some(self.text(key).to_string()),
                        "string" => self.literal(key),
                        _ => None,
                    });
                name.is_some_and(|name| !matches!(name.as_str(), "execPath" | "execArgv"))
            }
            "shorthand_property_identifier" => {
                !matches!(self.text(member), "execPath" | "execArgv")
            }
            _ => false,
        })
    }

    /// `spawn('rm', ['-rf', '~'])` runs the program; with `{ shell: … }`
    /// the command and its arguments are one command line a shell reads.
    /// Gives the directory its options start it in.
    fn spawn(&mut self, args: &Args<'_>, call: Node<'_>) -> Option<Arg> {
        // A spread may hold the program, its arguments or the options, and
        // may come before any of them: the call is not read.
        if args.splat {
            self.reading.unread(self.text(call));
            return None;
        }
        let command = args.get(0)?;
        let program = self.arg(command);
        let mut words = vec![program];
        let mut options = None;
        // Options that are not an object literal may name any directory.
        let mut loose = false;
        for node in args.positional.iter().skip(1) {
            match node.kind() {
                "object" => options = Some(*node),
                "array" => words.extend(self.words(*node)),
                "arrow_function" | "function_expression" | "function" => {}
                _ => {
                    loose = true;
                    words.extend(self.words(*node));
                }
            }
        }
        self.foreign_shell(options, call);
        let shell = options.is_some_and(|options| self.property(options, "shell").is_some());
        if shell {
            let known = words.iter().all(|word| word.known().is_some());
            let line = words.iter().map(Arg::text).collect::<Vec<_>>().join(" ");
            let script = if known {
                Arg::Known(line)
            } else {
                Arg::Unknown(super::shorten(&line))
            };
            self.reading.acts.push(Act::Script(script));
        } else {
            self.reading.acts.push(Act::Program(words));
        }
        if loose {
            Some(Arg::Unknown("options".to_string()))
        } else {
            self.cwd(options)
        }
    }

    /// A call the reader does not know. A method with a name only the file
    /// system, `child_process` and the like have (`rmSync`, `execSync`), on
    /// an object the reader cannot name, is a delete, a write or a command
    /// it cannot follow: `unknown`. Else a method called on a file made by
    /// `Bun.file(path)`.
    fn method(&mut self, function: Node<'_>, name: Option<&str>, call: Node<'_>) {
        let property = match function.kind() {
            "member_expression" => function
                .child_by_field_name("property")
                .map(|property| self.text(property).to_string()),
            "subscript_expression" => function
                .child_by_field_name("index")
                .and_then(|index| self.literal(index)),
            _ => None,
        };
        // The name an alias stands for counts too (`const r = x.rmSync`).
        let last = name.and_then(|name| name.rsplit('.').next());
        if property
            .as_deref()
            .into_iter()
            .chain(last)
            .any(|name| DISTINCT.contains(&name))
        {
            self.reading.unread(self.text(call));
            return;
        }
        if function.kind() != "member_expression" {
            return;
        }
        let (Some(receiver), Some(property)) = (
            function.child_by_field_name("object"),
            function.child_by_field_name("property"),
        ) else {
            return;
        };
        let method = self.text(property);
        if !matches!(method, "delete" | "unlink" | "write" | "writer") {
            return;
        }
        let Some(file) = self.constructed(receiver, "Bun.file") else {
            return;
        };
        let target = self.target(&file, 0);
        self.act(target.map(|target| {
            if matches!(method, "delete" | "unlink") {
                Act::Remove(target)
            } else {
                Act::Write(target)
            }
        }));
    }

    /// A call the reader does not know (not a delete, a write, a read or a
    /// command it follows) that is given a path, as a string or built from
    /// the home directory: it may read it, write it or delete it, so the
    /// line is `unknown`, unless the path is a key (`read_secret`). A call
    /// that only looks at the name of a path, a method of a string, an array
    /// or a map, and a function the code defines (whose own calls are read
    /// where they are written) are not given a path in this sense.
    fn unmodeled(&mut self, function: Node<'_>, name: Option<&str>, args: &Args<'_>) {
        match function.kind() {
            "identifier" => {
                if !name.is_some_and(|name| name.contains('.') || name == "fetch") {
                    return;
                }
            }
            "member_expression" => {
                let Some(method) = function.child_by_field_name("property") else {
                    return;
                };
                if METHODS_OF_TEXT.contains(&self.text(method)) {
                    return;
                }
            }
            _ => return,
        }
        if name.is_some_and(|name| NAMES_ONLY.iter().any(|start| name.starts_with(start))) {
            return;
        }
        let mut given = Vec::new();
        for node in &args.positional {
            let mut cursor = node.walk();
            match node.kind() {
                "array" => given.extend(node.named_children(&mut cursor)),
                "object" => given.extend(
                    node.named_children(&mut cursor)
                        .filter_map(|pair| pair.child_by_field_name("value")),
                ),
                _ => given.push(*node),
            }
        }
        for node in given {
            if let Some(path) = self.value(node, 0).as_deref().and_then(named_path) {
                self.reading.acts.push(Act::Opaque(path));
            }
        }
    }

    /// A name or property used without being called: an alias of a call the
    /// reader cannot follow, or a module put where it is lost.
    fn reference<'t>(&mut self, node: Node<'t>, field: Option<&str>, above: &[Ancestor<'t>]) {
        let Some(parent) = above.last() else {
            return;
        };
        let is = |name: &str| field == Some(name);
        let skipped = match parent.node.kind() {
            "call_expression" => is("function"),
            "new_expression" => is("constructor"),
            "member_expression" => is("property"),
            "variable_declarator" => is("name"),
            // A name a pattern or a parameter list sets is not a use of it.
            "pair_pattern" | "assignment_pattern" | "catch_clause" => {
                is("value") || is("left") || is("parameter")
            }
            "array_pattern" | "rest_pattern" => true,
            // What an `import` binds.
            "import_clause" | "namespace_import" | "import_specifier" => true,
            "assignment_expression" => is("left") && node.kind() != "member_expression",
            "function_declaration"
            | "function_expression"
            | "class_declaration"
            | "formal_parameters"
            | "pair"
            | "object_pattern"
            | "arrow_function" => {
                is("name") || is("alias") || is("key") || is("left") || is("parameter")
            }
            _ => false,
        };
        if skipped {
            return;
        }
        let Some(name) = self.qualified(node, 0) else {
            return;
        };
        // `$` of execa is called as it is, and `$.sync` is the call the
        // reader looks at: the object it is a member of is not the call.
        // The same for `cross-spawn`, which is itself a call and has `spawn`
        // and `sync` members: `spawn.sync(…)` is read as the call it is. Not
        // so for any other member of a function (`spawn.call(null, 'rm')`,
        // `.apply`, `.bind`): the program it starts is not read.
        if matches!(
            name.as_str(),
            "cross-spawn" | "cross-spawn.default" | "execa.$"
        ) && parent.node.kind() == "member_expression"
            && is("object")
            && parent
                .node
                .child_by_field_name("property")
                .is_some_and(|property| readable_member(&name, self.text(property)))
        {
            return;
        }
        if kind(&name).is_some_and(|kind| kind != Kind::Require)
            || (self.is_module(&name) && self.escapes(node, field, above))
        {
            self.reading.unread(self.text(node));
        }
    }

    /// `fs[name](…)`: a member looked up by a name only known when it runs,
    /// on an object whose members delete, write and run.
    fn subscript(&mut self, node: Node<'_>) {
        let (Some(object), Some(index)) = (
            node.child_by_field_name("object"),
            node.child_by_field_name("index"),
        ) else {
            return;
        };
        if self.literal(index).is_some() {
            return;
        }
        let Some(name) = self.qualified(object, 0) else {
            return;
        };
        if ROOTS.contains(&name.as_str()) {
            self.reading.unread(self.text(node));
        }
    }
}

/// A JavaScript escape sequence's character: `\n`, `\x41`, `é`,
/// `\u{1F600}`, a legacy octal escape (`\57`, `\176`, `\0`: sloppy mode,
/// which `node -e` is, reads them); a backslash before anything else is that
/// character. `None` when it is not decoded (a surrogate, a number that is no
/// character): the string is then only known when it runs.
fn unescape(escape: &str) -> Option<String> {
    let Some(rest) = escape.strip_prefix('\\') else {
        return Some(escape.to_string());
    };
    let mut chars = rest.chars();
    let first = chars.next()?;
    let hex = |digits: &str| {
        u32::from_str_radix(digits, 16)
            .ok()
            .and_then(char::from_u32)
            .map(String::from)
    };
    match first {
        'n' => Some("\n".to_string()),
        't' => Some("\t".to_string()),
        'r' => Some("\r".to_string()),
        'b' => Some("\u{8}".to_string()),
        'f' => Some("\u{c}".to_string()),
        'v' => Some("\u{b}".to_string()),
        // One to three octal digits: up to `\377`, so a third digit that
        // would go past it is the character after the escape (`\400` is `\40`
        // and `0`).
        '0'..='7' => {
            let digits = rest;
            let (octal, after) = match digits.len() {
                3 if first > '3' => digits.split_at(2),
                _ => (digits, ""),
            };
            let value = u32::from_str_radix(octal, 8).ok()?;
            let mut text = char::from_u32(value)?.to_string();
            text.push_str(after);
            Some(text)
        }
        'x' | 'u' => {
            let digits = chars.as_str();
            let digits = digits
                .strip_prefix('{')
                .and_then(|inner| inner.strip_suffix('}'))
                .unwrap_or(digits);
            hex(digits)
        }
        '\n' | '\r' => Some(String::new()),
        other => Some(other.to_string()),
    }
}
