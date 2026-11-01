//! Inline JavaScript (Node, Bun, Deno): the calls that delete, write, move
//! and run, with the paths they name, found with tree-sitter-javascript.

use std::collections::HashMap;

use tree_sitter::Node;

use super::{environment, join, mode, path, writes, Act, Language, Reading};
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
    unit::for_each_node(root, |node| match node.kind() {
        "call_expression" | "new_expression" => reader.call(node),
        "member_expression" | "identifier" => reader.reference(node),
        "subscript_expression" => reader.subscript(node),
        _ => {}
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
        | "module.constructor"
        | "module.createRequire"
        | "require.main"
        | "worker_threads.Worker"
        | "Deno.dlopen"
        | "Deno.core" => Kind::Unread,
        "require" => Kind::Require,
        _ => return None,
    })
}

/// The objects a computed name looked up on cannot be followed.
const ROOTS: [&str; 10] = [
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

/// The properties of an options object whose truth means a file is written.
const WRITE_OPTIONS: [&str; 5] = ["write", "append", "create", "createNew", "truncate"];

struct Reader<'s> {
    src: &'s str,
    /// What each name a `require`, an `import` or a destructuring binds
    /// stands for: `rm` from `const { rm } = require('fs/promises')` is
    /// `fs.promises.rm`.
    aliases: HashMap<String, String>,
    reading: Reading,
}

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
                    }
                    "namespace_import" => {
                        if let Some(name) = part.named_child(0) {
                            self.aliases
                                .insert(self.text(name).to_string(), module.clone());
                        }
                    }
                    "named_imports" => {
                        let mut names = part.walk();
                        for specifier in part.named_children(&mut names) {
                            let real = specifier.child_by_field_name("name");
                            let alias = specifier.child_by_field_name("alias").or(real);
                            if let (Some(real), Some(alias)) = (real, alias) {
                                self.aliases.insert(
                                    self.text(alias).to_string(),
                                    format!("{module}.{}", self.text(real)),
                                );
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
            "object_pattern" => {
                let mut cursor = name.walk();
                for part in name.named_children(&mut cursor) {
                    match part.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let property = self.text(part);
                            self.aliases
                                .insert(property.to_string(), format!("{from}.{property}"));
                        }
                        "pair_pattern" => {
                            if let (Some(key), Some(value)) = (
                                part.child_by_field_name("key"),
                                part.child_by_field_name("value"),
                            ) {
                                let inner = format!("{from}.{}", self.text(key));
                                self.bind_pattern(value, &inner, level + 1);
                            }
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
        match node.kind() {
            "identifier" => {
                let name = self.text(node);
                Some(
                    self.aliases
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| name.to_string()),
                )
            }
            "member_expression" => {
                let object = node.child_by_field_name("object")?;
                let property = node.child_by_field_name("property")?;
                let property = self.text(property);
                if matches!(self.text(object), "globalThis" | "global" | "window") {
                    return Some(property.to_string());
                }
                let object = self.qualified(object, level + 1)?;
                Some(format!("{object}.{property}"))
            }
            "subscript_expression" => {
                let object = node.child_by_field_name("object")?;
                let index = node.child_by_field_name("index")?;
                let index = self.literal(index)?;
                let object = self.qualified(object, level + 1)?;
                Some(format!("{object}.{index}"))
            }
            "parenthesized_expression" | "await_expression" => {
                let inner = node.named_child(0)?;
                self.qualified(inner, level + 1)
            }
            "call_expression" => {
                let function = node.child_by_field_name("function")?;
                // `require('fs')` and `import('fs')` are the module.
                let required = self.qualified(function, level + 1).as_deref() == Some("require");
                if required || self.text(function) == "import" {
                    let args = Args::read(node);
                    let source = self.literal(args.get(0)?)?;
                    return Some(module(&source));
                }
                None
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
                        "escape_sequence" => text.push_str(&unescape(self.text(part))),
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
                        "escape_sequence" => text.push_str(&unescape(self.text(part))),
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

    fn call(&mut self, call: Node<'_>) {
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
        match name.as_deref().and_then(kind) {
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
            }
            Some(Kind::Spawn) => self.spawn(&args),
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
            }
            Some(Kind::Argv) => {
                let first = args.get(0);
                let list = match first {
                    Some(node) if node.kind() == "array" => Some(node),
                    Some(node) if node.kind() == "object" => self.property(node, "cmd"),
                    _ => None,
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
                if args.get(0).is_none_or(|node| self.literal(node).is_none()) {
                    self.reading.unread(self.text(call));
                }
            }
            None => self.method(function),
        }
        // `import(x)`: a module loaded where the reader cannot follow it,
        // unless it is awaited, which `qualified` follows.
        if self.text(function) == "import" {
            let awaited = call
                .parent()
                .is_some_and(|parent| parent.kind() == "await_expression");
            if !awaited {
                self.reading.unread(self.text(call));
            }
        }
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
    fn spawn(&mut self, args: &Args<'_>) {
        let Some(command) = args.get(0) else {
            return;
        };
        let program = self.arg(command);
        let mut words = vec![program];
        let mut options = None;
        for node in args.positional.iter().skip(1) {
            match node.kind() {
                "object" => options = Some(*node),
                _ => words.extend(self.words(*node)),
            }
        }
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
    }

    /// A method called on a file made by `Bun.file(path)`.
    fn method(&mut self, function: Node<'_>) {
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
        if !matches!(method, "delete" | "write" | "writer") {
            return;
        }
        let Some(file) = self.constructed(receiver, "Bun.file") else {
            return;
        };
        let target = self.target(&file, 0);
        self.act(target.map(|target| {
            if method == "delete" {
                Act::Remove(target)
            } else {
                Act::Write(target)
            }
        }));
    }

    /// A name or property used without being called: an alias of a call the
    /// reader cannot follow.
    fn reference(&mut self, node: Node<'_>) {
        let Some(parent) = node.parent() else {
            return;
        };
        let field = |name: &str| {
            parent
                .child_by_field_name(name)
                .is_some_and(|child| child.id() == node.id())
        };
        let skipped = match parent.kind() {
            "call_expression" => field("function"),
            "new_expression" => field("constructor"),
            "member_expression" => field("property"),
            "variable_declarator" => field("name"),
            "function_declaration"
            | "function_expression"
            | "class_declaration"
            | "formal_parameters"
            | "import_specifier"
            | "import_clause"
            | "namespace_import"
            | "pair"
            | "pair_pattern"
            | "object_pattern"
            | "arrow_function"
            | "assignment_expression" => {
                field("name")
                    || field("alias")
                    || field("key")
                    || field("left")
                    || field("parameter")
            }
            _ => false,
        };
        if skipped {
            return;
        }
        let Some(name) = self.qualified(node, 0) else {
            return;
        };
        if kind(&name).is_some_and(|kind| kind != Kind::Require) {
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
/// `\u{1F600}`; a backslash before anything else is that character.
fn unescape(escape: &str) -> String {
    let Some(rest) = escape.strip_prefix('\\') else {
        return escape.to_string();
    };
    let mut chars = rest.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let hex = |digits: &str| {
        u32::from_str_radix(digits, 16)
            .ok()
            .and_then(char::from_u32)
            .map_or_else(|| escape.to_string(), String::from)
    };
    match first {
        'n' => "\n".to_string(),
        't' => "\t".to_string(),
        'r' => "\r".to_string(),
        'b' => "\u{8}".to_string(),
        'f' => "\u{c}".to_string(),
        'v' => "\u{b}".to_string(),
        '0' if chars.as_str().is_empty() => "\0".to_string(),
        'x' | 'u' => {
            let digits = chars.as_str();
            let digits = digits
                .strip_prefix('{')
                .and_then(|inner| inner.strip_suffix('}'))
                .unwrap_or(digits);
            hex(digits)
        }
        '\n' | '\r' => String::new(),
        other => other.to_string(),
    }
}
