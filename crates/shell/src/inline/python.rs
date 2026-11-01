//! Inline Python: the calls that delete, write, move and run, with the
//! paths they name, found with tree-sitter-python.

use std::collections::HashMap;

use tree_sitter::Node;

use super::{environment, join, mode, path, writes, Act, Language, Reading};
use crate::unit::{self, Arg, MAX_TREE_DEPTH};

pub(super) fn read(code: &str) -> Reading {
    let mut parser = tree_sitter::Parser::new();
    let tree = parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
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
    reader.collect_imports(root);
    unit::for_each_node(root, |node| match node.kind() {
        "call" => reader.call(node),
        "attribute" | "identifier" => reader.reference(node),
        "subscript" => reader.subscript(node),
        _ => {}
    });
    reader.reading
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
    Chown,
    Chdir,
    /// `open(path, mode)` and the calls that open a file the same way.
    Open,
    /// `os.open(path, flags)`.
    OsOpen,
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
    /// `__import__` and `importlib.import_module`.
    Import,
    Getattr,
}

/// The modules whose names a dotted name can be started again from: a
/// module that imported another holds it as an attribute (`shutil.os`),
/// `posix` and `nt` are what `os` is, and `builtins` holds the builtins.
const MODULES: [&str; 20] = [
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

/// `name` with the module that really holds the call first: `shutil.os.remove`
/// is `os.remove`, `posix.remove` is `os.remove`, `builtins.exec` is `exec`.
fn rebase(name: &str) -> String {
    let parts: Vec<&str> = name.split('.').collect();
    let start = parts
        .iter()
        .rposition(|part| MODULES.contains(part))
        .unwrap_or(0);
    let rest = parts[start..].join(".");
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
        | "shutil.make_archive"
        | "sqlite3.connect" => Kind::Write,
        "os.chmod" | "os.lchmod" => Kind::Chmod,
        "os.chown" | "os.lchown" | "shutil.chown" => Kind::Chown,
        "os.chdir" => Kind::Chdir,
        "open" | "builtins.open" | "io.open" | "codecs.open" | "gzip.open" | "bz2.open"
        | "lzma.open" | "tarfile.open" | "zipfile.ZipFile" => Kind::Open,
        "os.open" => Kind::OsOpen,
        "os.system"
        | "os.popen"
        | "subprocess.getoutput"
        | "subprocess.getstatusoutput"
        | "asyncio.create_subprocess_shell"
        | "commands.getoutput"
        | "commands.getstatusoutput"
        | "pexpect.run"
        | "pexpect.spawn" => Kind::Script,
        "subprocess.run"
        | "subprocess.call"
        | "subprocess.check_call"
        | "subprocess.check_output"
        | "subprocess.Popen" => Kind::Subprocess,
        "asyncio.create_subprocess_exec" => Kind::Exec,
        "pty.spawn"
        | "compile"
        | "globals"
        | "locals"
        | "vars"
        | "importlib.reload"
        | "__builtins__"
        | "code.interact"
        | "code.InteractiveInterpreter"
        | "code.InteractiveConsole" => Kind::Unread,
        "eval" | "exec" => Kind::Eval,
        "__import__" | "importlib.import_module" | "importlib.__import__" => Kind::Import,
        "getattr" => Kind::Getattr,
        name if name.starts_with("os.exec")
            || name.starts_with("os.spawn")
            || name.starts_with("os.posix_spawn")
            || name.starts_with("runpy.")
            || name.starts_with("ctypes.") =>
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
const METHODS: [&str; 7] = [
    "unlink",
    "rmdir",
    "write_text",
    "write_bytes",
    "symlink_to",
    "hardlink_to",
    "extractall",
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
    reading: Reading,
}

/// The arguments of a call.
struct Args<'t> {
    positional: Vec<Node<'t>>,
    keywords: Vec<(String, Node<'t>)>,
    /// Whether `*args` or `**kwargs` may stand for any argument.
    splat: bool,
}

impl<'t> Args<'t> {
    fn read(call: Node<'t>, src: &str) -> Self {
        let mut args = Self {
            positional: Vec::new(),
            keywords: Vec::new(),
            splat: false,
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
                        args.keywords
                            .push((unit::text(&name, src).to_string(), value));
                    }
                }
                "list_splat" | "dictionary_splat" => args.splat = true,
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
    fn text(&self, node: Node<'_>) -> &'s str {
        unit::text(&node, self.src)
    }

    fn collect_imports(&mut self, root: Node<'_>) {
        let mut found = Vec::new();
        unit::for_each_node(root, |node| match node.kind() {
            "import_statement" | "import_from_statement" | "assignment" => found.push(node),
            _ => {}
        });
        for node in found {
            // `o = os`, `m = __import__('os')`: a name for a module or call.
            if node.kind() == "assignment" {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    if left.kind() == "identifier" {
                        if let Some(name) = self.qualified(right, 0) {
                            self.aliases.insert(self.text(left).to_string(), name);
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
                            self.aliases
                                .insert(self.text(alias).to_string(), self.text(real).to_string());
                        }
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
                    self.aliases.insert(
                        self.text(alias).to_string(),
                        format!("{module}.{}", self.text(real)),
                    );
                }
            }
        }
    }

    /// `from os import *` makes every name in `os` a bare one.
    fn star_import(&mut self, module: &str) {
        const MODULES: [&str; 7] = [
            "os",
            "shutil",
            "subprocess",
            "pathlib",
            "io",
            "codecs",
            "pty",
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
                Some(rebase(&format!("{object}.{}", self.text(attribute))))
            }
            "parenthesized_expression" => {
                let inner = node.named_child(0)?;
                self.qualified(inner, level + 1)
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
                self.value(module, level + 1)
            }
            Kind::Getattr => {
                let object = args.positional.first().copied()?;
                let attribute = args.get(1, &["name"])?;
                let object = self.qualified(object, level + 1)?;
                Some(format!("{object}.{}", self.value(attribute, level + 1)?))
            }
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
            "string" => self.string(node, level),
            "concatenated_string" => {
                let mut cursor = node.walk();
                let parts: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
                let mut text = String::new();
                for part in parts {
                    text.push_str(&self.value(part, level + 1)?);
                }
                Some(text)
            }
            "parenthesized_expression" => {
                let inner = node.named_child(0)?;
                self.value(inner, level + 1)
            }
            "binary_operator" => {
                let left = node.child_by_field_name("left")?;
                let right = node.child_by_field_name("right")?;
                let operator = self.text(node.child_by_field_name("operator")?);
                let left = self.value(left, level + 1)?;
                let right = self.value(right, level + 1)?;
                match operator {
                    "+" => Some(format!("{left}{right}")),
                    "/" => Some(join(&left, &right)),
                    _ => None,
                }
            }
            "call" => self.value_of_call(node, level),
            "attribute" => {
                let object = node.child_by_field_name("object")?;
                let attribute = node.child_by_field_name("attribute")?;
                if self.text(attribute) == "parent" {
                    let object = self.value(object, level + 1)?;
                    Some(join(&object, ".."))
                } else {
                    None
                }
            }
            "subscript" => {
                let object = node.child_by_field_name("value")?;
                let index = node.child_by_field_name("subscript")?;
                if self.qualified(object, level + 1).as_deref() == Some("os.environ") {
                    environment(&self.value(index, level + 1)?)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// A string literal: escapes read, an f-string's plain `{…}` parts put
    /// in.
    fn string(&mut self, node: Node<'_>, level: usize) -> Option<String> {
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
                    let content = if raw {
                        content.to_string()
                    } else {
                        unescape(content)
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
                        return None;
                    }
                    let expression = part.child_by_field_name("expression")?;
                    text.push_str(&self.value(expression, level + 1)?);
                }
                _ => {}
            }
        }
        Some(text)
    }

    fn value_of_call(&mut self, call: Node<'_>, level: usize) -> Option<String> {
        let function = call.child_by_field_name("function")?;
        let args = Args::read(call, self.src);
        let name = self.qualified(function, level + 1);
        let first = |reader: &mut Self| {
            let node = args.positional.first().copied()?;
            reader.value(node, level + 1)
        };
        match name.as_deref() {
            Some(
                "pathlib.Path" | "pathlib.PurePath" | "pathlib.PosixPath" | "pathlib.PurePosixPath",
            ) => {
                let mut text = String::new();
                for node in args.positional.clone() {
                    text = join(&text, &self.value(node, level + 1)?);
                }
                Some(if text.is_empty() {
                    ".".to_string()
                } else {
                    text
                })
            }
            Some("pathlib.Path.home" | "pathlib.PurePath.home") => Some("~".to_string()),
            Some("pathlib.Path.cwd" | "os.getcwd" | "os.curdir") => Some(".".to_string()),
            Some(
                "os.path.expanduser" | "os.path.abspath" | "os.path.normpath" | "os.path.realpath"
                | "os.fspath" | "os.fsdecode" | "str",
            ) => first(self),
            Some("os.path.expandvars") => {
                let text = first(self)?;
                if let Some(rest) = text
                    .strip_prefix("$HOME")
                    .or_else(|| text.strip_prefix("${HOME}"))
                {
                    (!rest.contains('$')).then(|| format!("~{rest}"))
                } else {
                    (!text.contains(['$', '%'])).then_some(text)
                }
            }
            Some("os.path.join") => {
                let mut text = String::new();
                for node in args.positional.clone() {
                    text = join(&text, &self.value(node, level + 1)?);
                }
                Some(text)
            }
            Some("os.path.dirname") => Some(join(&first(self)?, "..")),
            Some("os.environ.get" | "os.getenv") => environment(&first(self)?),
            Some("tempfile.gettempdir") => Some("/tmp".to_string()),
            Some("tempfile.mkdtemp") => Some("/tmp/x".to_string()),
            _ => {
                let attribute = function.child_by_field_name("attribute")?;
                let receiver = function.child_by_field_name("object")?;
                match self.text(attribute) {
                    "expanduser" | "resolve" | "absolute" => self.value(receiver, level + 1),
                    "joinpath" => {
                        let mut text = self.value(receiver, level + 1)?;
                        for node in args.positional.clone() {
                            text = join(&text, &self.value(node, level + 1)?);
                        }
                        Some(text)
                    }
                    "with_name" => {
                        let parent = join(&self.value(receiver, level + 1)?, "..");
                        let node = args.positional.first().copied()?;
                        Some(join(&parent, &self.value(node, level + 1)?))
                    }
                    _ => None,
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
            Some(node) => Some(self.arg(node)),
            None if args.splat => Some(Arg::Unknown("*args".to_string())),
            None => None,
        }
    }

    fn act(&mut self, act: Option<Act>) {
        self.reading.acts.extend(act);
    }

    fn call(&mut self, call: Node<'_>) {
        let Some(function) = call.child_by_field_name("function") else {
            return;
        };
        let args = Args::read(call, self.src);
        let name = self.qualified(function, 0);
        match name.as_deref().and_then(kind) {
            Some(Kind::Remove) => {
                let target = self.target(&args, 0, &["path"]);
                self.act(target.map(Act::Remove));
            }
            Some(Kind::Copy) => {
                let target = self.target(&args, 1, &["dst", "extract_dir", "filename", "out"]);
                self.act(target.map(Act::Write));
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
            Some(Kind::Chown) => {
                let target = self.target(&args, 0, &["path"]);
                self.act(target.map(Act::Chown));
            }
            Some(Kind::Chdir) => {
                let target = self.target(&args, 0, &["path"]);
                self.act(target.map(Act::Chdir));
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
                }
            }
            Some(Kind::OsOpen) => {
                let flags = args.get(1, &["flags"]);
                let reads = flags.is_some_and(|flags| {
                    self.text(flags) == "0"
                        || self.qualified(flags, 0).as_deref() == Some("os.O_RDONLY")
                });
                if !reads {
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
            Some(Kind::Eval) => self.eval(&args, call),
            Some(Kind::Import | Kind::Getattr) => {
                // With a literal name the call is a name (`qualified`); the
                // rest is a lookup the reader cannot follow.
                if self.qualified(call, 0).is_none() {
                    self.reading.unread(self.text(call));
                }
            }
            None => self.method(function, &args),
        }
    }

    /// `eval("…")` and `exec("…")` run code that is read as Python;
    /// anything else is code only known when it runs.
    fn eval(&mut self, args: &Args<'_>, call: Node<'_>) {
        match args.positional.first().and_then(|node| match node.kind() {
            "string" | "concatenated_string" => self.value(*node, 0),
            _ => None,
        }) {
            Some(text) => self.reading.acts.push(Act::Code(Language::Python, text)),
            None => self.reading.unread(self.text(call)),
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
        let Some(command) = args.get(0, &["args"]) else {
            if args.splat {
                self.reading.unread("subprocess call with *args");
            }
            return;
        };
        let shell = args
            .keywords
            .iter()
            .find(|(name, _)| name == "shell")
            .map(|(_, value)| *value);
        let shell = shell.is_some_and(|value| !matches!(self.text(value), "False" | "None" | "0"));
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
            "unlink" | "rmdir" => {
                let target = self.arg(receiver);
                self.reading.acts.push(Act::Remove(target));
            }
            "write_text" | "write_bytes" | "touch" | "mkdir" => {
                let target = self.arg(receiver);
                self.reading.acts.push(Act::Write(target));
            }
            "rename" | "replace" if args.positional.len() == 1 && args.keywords.is_empty() => {
                let from = self.arg(receiver);
                let to = args.positional.first().map(|node| self.arg(*node));
                self.act(to.map(|to| Act::Move { from, to }));
            }
            "open" => {
                let mode = args
                    .get(0, &["mode"])
                    .filter(|node| node.kind() == "string")
                    .and_then(|node| self.value(node, 0));
                if writes(mode.as_deref()) {
                    let target = self.arg(receiver);
                    self.reading.acts.push(Act::Write(target));
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
            _ => {}
        }
    }

    /// A name or attribute used without being called: an alias of a call the
    /// reader cannot follow.
    fn reference(&mut self, node: Node<'_>) {
        // A name that reaches what the reader cannot follow, called or not.
        if node.kind() == "attribute"
            && node
                .child_by_field_name("attribute")
                .is_some_and(|attribute| DUNDERS.contains(&self.text(attribute)))
        {
            self.reading.unread(self.text(node));
            return;
        }
        let Some(parent) = node.parent() else {
            return;
        };
        let field = |name: &str| {
            parent
                .child_by_field_name(name)
                .is_some_and(|child| child.id() == node.id())
        };
        let skipped = match parent.kind() {
            "call" => field("function"),
            "attribute" => field("attribute"),
            "keyword_argument" => field("name"),
            "function_definition" | "class_definition" => field("name"),
            "dotted_name"
            | "aliased_import"
            | "import_statement"
            | "import_from_statement"
            | "parameters"
            | "lambda_parameters"
            | "default_parameter"
            | "typed_parameter"
            | "typed_default_parameter"
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
        if unfollowable || method {
            self.reading.unread(self.text(node));
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

/// A string literal's text with its escapes read, as Python reads a string
/// that is not raw: `\n`, `\x41`, `é`, octal, and a backslash before
/// anything else stays.
fn unescape(text: &str) -> String {
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
                        .and_then(char::from_u32)
                        .unwrap_or('?'),
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
                let read = u32::from_str_radix(&digits, 16)
                    .ok()
                    .filter(|_| digits.len() == count)
                    .and_then(char::from_u32);
                if let Some(c) = read {
                    out.push(c);
                } else {
                    out.push('\\');
                    out.push(next);
                    out.push_str(&digits);
                }
            }
            'N' => {
                // `\N{NAME}`: a character the name stands for, which no path
                // here depends on.
                if chars.peek() == Some(&'{') {
                    for c in chars.by_ref() {
                        if c == '}' {
                            break;
                        }
                    }
                }
                out.push('?');
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}
