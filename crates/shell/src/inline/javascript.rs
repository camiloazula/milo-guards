//! Inline JavaScript (Node, Bun, Deno): the calls that delete, write, move
//! and run, with the paths they name, found with tree-sitter-javascript.

use std::collections::{HashMap, HashSet};

use tree_sitter::Node;

use super::{environment, join, mode, path, walk, writes, Act, Ancestor, Language, Reading};
use crate::unit::{self, Arg, MAX_TREE_DEPTH};

pub(super) fn read(code: &str) -> Reading {
    let mut parser = tree_sitter::Parser::new();
    let tree = parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .ok()
        .and_then(|()| parser.parse(code, None));
    let mut reader = Reader {
        src: code,
        aliases: HashMap::new(),
        modules: HashSet::new(),
        names: HashMap::new(),
        walking: false,
        reading: Reading::default(),
    };
    let Some(tree) = tree else {
        reader.reading.unread(code);
        return reader.reading;
    };
    let root = tree.root_node();
    if root.has_error() {
        reader.reading.unread(code);
    }
    reader.collect_aliases(root);
    reader.walking = true;
    // The walk stops once the code is found to nest too deeply to read: the
    // line is unreadable whatever else is in it.
    walk(root, |node, field, above| {
        match node.kind() {
            "call_expression" | "new_expression" => reader.call(node, field, above),
            "member_expression"
            | "identifier"
            | "shorthand_property_identifier"
            | "subscript_expression" => reader.reference(node, field, above),
            // `with (require('fs')) rmSync(…)`: every name in the block may be
            // a member of the object.
            "with_statement" => reader.reading.unread(reader.text(node)),
            _ => {}
        }
        if node.kind() == "subscript_expression" {
            reader.subscript(node);
        }
        !reader.reading.deep
    });
    reader.reading
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
    /// `fs.openSync(path, flags)`.
    Open,
    /// `Deno.open(path, options)`.
    DenoOpen,
    /// `Bun.write(path, data)`: the path may be `Bun.file(path)`.
    BunWrite,
    /// Runs a command line.
    Script,
    /// `spawn(command, args, options)` and its kin.
    Spawn,
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
            "writeFile" | "appendFile" | "createWriteStream" | "truncate" | "mkdir" | "mkdtemp",
        ) => Kind::Write,
        (_, "copyFile" | "cp") => Kind::Copy,
        (_, "rename") => Kind::Move,
        (_, "symlink" | "link") => Kind::Link,
        (_, "chmod" | "lchmod") => Kind::Chmod,
        (_, "chown" | "lchown") => Kind::Chown,
        (_, "open") => Kind::Open,
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
        "Deno.open" | "Deno.openSync" => Kind::DenoOpen,
        "Deno.run" | "Bun.spawn" | "Bun.spawnSync" => Kind::Argv,
        "Deno.Command" => Kind::DenoCommand,
        "Bun.write" => Kind::BunWrite,
        "Bun.$"
        | "zx.$"
        | "child_process.exec"
        | "child_process.execSync"
        | "shelljs.exec"
        | "execa.execaCommand"
        | "execa.execaCommandSync" => Kind::Script,
        "child_process.spawn"
        | "child_process.spawnSync"
        | "child_process.execFile"
        | "child_process.execFileSync"
        | "execa"
        | "execa.execa"
        | "execa.execaSync"
        | "execa.sync" => Kind::Spawn,
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
        | "module.require"
        | "module._load"
        | "module.prototype.require"
        | "Bun.$.cwd"
        | "zx.$.cwd"
        | "zx.cd"
        | "module.constructor"
        | "module.createRequire"
        | "require.main"
        | "worker_threads.Worker"
        | "Deno.dlopen"
        | "Deno.core" => Kind::Unread,
        "require" | "process.getBuiltinModule" | "import.meta.require" => Kind::Require,
        _ => return None,
    })
}

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
const DISTINCT: [&str; 28] = [
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
    fn text(&self, node: Node<'_>) -> &'s str {
        unit::text(&node, self.src)
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
                        for specifier in part.named_children(&mut names) {
                            let real = specifier.child_by_field_name("name");
                            let alias = specifier.child_by_field_name("alias").or(real);
                            if let (Some(real), Some(alias)) = (real, alias) {
                                let member = member(&module, self.text(real));
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
                                let inner = member(from, self.text(key));
                                self.bind_pattern(value, &inner, level + 1);
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
        if level > MAX_TREE_DEPTH {
            self.reading.deep = true;
            return None;
        }
        match node.kind() {
            "string" => {
                let mut text = String::new();
                let mut cursor = node.walk();
                for part in node.named_children(&mut cursor) {
                    match part.kind() {
                        "string_fragment" => text.push_str(self.text(part)),
                        "escape_sequence" => text.push_str(&unescape(self.text(part))?),
                        _ => {}
                    }
                }
                Some(text)
            }
            "template_string" => {
                let mut text = String::new();
                let mut cursor = node.walk();
                let parts: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                for part in parts {
                    match part.kind() {
                        "string_fragment" => text.push_str(self.text(part)),
                        "escape_sequence" => text.push_str(&unescape(self.text(part))?),
                        "template_substitution" => {
                            let expression = part.named_child(0)?;
                            text.push_str(&self.value(expression, level + 1)?);
                        }
                        _ => {}
                    }
                }
                Some(text)
            }
            "parenthesized_expression" | "await_expression" => {
                let inner = node.named_child(0)?;
                self.value(inner, level + 1)
            }
            "binary_expression" => {
                let operator = node.child_by_field_name("operator")?;
                if self.text(operator) != "+" {
                    return None;
                }
                let left = self.value(node.child_by_field_name("left")?, level + 1)?;
                let right = self.value(node.child_by_field_name("right")?, level + 1)?;
                Some(format!("{left}{right}"))
            }
            "member_expression" | "identifier" | "subscript_expression" => {
                let name = self.qualified(node, level + 1)?;
                let variable = name
                    .strip_prefix("process.env.")
                    .or_else(|| name.strip_prefix("Bun.env."))?;
                environment(variable)
            }
            "call_expression" => self.value_of_call(node, level),
            _ => None,
        }
    }

    fn value_of_call(&mut self, call: Node<'_>, level: usize) -> Option<String> {
        let function = call.child_by_field_name("function")?;
        let args = Args::read(call);
        let name = self.qualified(function, level + 1);
        let texts = |reader: &mut Self| -> Option<Vec<String>> {
            args.positional
                .iter()
                .map(|node| reader.value(*node, level + 1))
                .collect()
        };
        match name.as_deref() {
            Some("path.join" | "path.resolve") => {
                let mut text = String::new();
                for part in texts(self)? {
                    text = join(&text, &part);
                }
                Some(if text.is_empty() {
                    ".".to_string()
                } else {
                    text
                })
            }
            Some("path.normalize" | "String") => texts(self)?.into_iter().next(),
            Some("path.dirname") => Some(join(&texts(self)?.into_iter().next()?, "..")),
            Some("os.homedir") => Some("~".to_string()),
            Some("os.tmpdir") => Some("/tmp".to_string()),
            Some("process.cwd" | "Deno.cwd") => Some(".".to_string()),
            Some("Deno.env.get") => environment(&texts(self)?.into_iter().next()?),
            _ => {
                let property = function.child_by_field_name("property")?;
                if self.text(property) == "toString" && args.positional.is_empty() {
                    let receiver = function.child_by_field_name("object")?;
                    self.value(receiver, level + 1)
                } else {
                    None
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
            Some(Kind::Open) => {
                // No flags reads; flags only known when it runs may write.
                let writes_file = match args.get(1) {
                    Some(node) => self.literal(node).is_none_or(|flags| writes(Some(&flags))),
                    None => args.splat,
                };
                if writes_file {
                    let target = self.target(&args, 0);
                    self.act(target.map(Act::Write));
                }
            }
            Some(Kind::DenoOpen) => {
                let writes_file = match args.get(1) {
                    Some(node) if node.kind() == "object" => self.options_write(node),
                    Some(_) => true,
                    None => args.splat,
                };
                if writes_file {
                    let target = self.target(&args, 0);
                    self.act(target.map(Act::Write));
                }
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
            Some(Kind::Eval) => match args.get(0).filter(|node| node.kind() == "string") {
                Some(node) => {
                    if let Some(text) = self.value(node, 0) {
                        self.reading
                            .acts
                            .push(Act::Code(Language::JavaScript, text));
                    }
                }
                None => self.reading.unread(self.text(call)),
            },
            Some(Kind::Require) => {
                let source = requires.and_then(|found| found.0).or_else(|| args.get(0));
                if source.is_none_or(|node| self.literal(node).is_none()) {
                    self.reading.unread(self.text(call));
                } else if self.escapes(call, field, above) {
                    // The module, handed on as a value.
                    self.reading.unread(self.text(call));
                }
            }
            None => self.method(function, name.as_deref(), call),
        }
        self.within(cwd, before);
        // `import(x)`: a module loaded where the reader cannot follow it,
        // unless it is awaited, which `qualified` follows.
        if self.text(function) == "import" {
            let awaited = above
                .last()
                .is_some_and(|parent| parent.node.kind() == "await_expression");
            if !awaited || self.escapes(call, field, above) {
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

    /// `spawn('rm', ['-rf', '~'])` runs the program; with `{ shell: … }`
    /// the command and its arguments are one command line a shell reads.
    /// Gives the directory its options start it in.
    fn spawn(&mut self, args: &Args<'_>, call: Node<'_>) -> Option<Arg> {
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
