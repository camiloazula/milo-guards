//! What the readers are built from besides the grammars: the argument of a
//! call as the code gives it, the limits, and two helpers that walk a tree.

/// One value the code hands to a call, as far as the reader knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// Its value is in the text: `'target'`, `'~/x'`.
    Known(String),
    /// Only known when the code runs (a name nothing sets, a call's result):
    /// its source text.
    Unknown(String),
    /// A path that starts as the code says and ends in something only known
    /// when it runs: somewhere in a folder (`'/home/me/.ssh/id_' + name` is a
    /// file in `/home/me/.ssh/`). Not a value, but the folder is known, and a
    /// caller judges a read of the path by it.
    Below {
        /// The folder, as the code spells it, with its closing `/`.
        folder: String,
        /// The value as written.
        source: String,
    },
}

impl Arg {
    /// The value, when the code gives it whole.
    pub fn known(&self) -> Option<&str> {
        match self {
            Self::Known(text) => Some(text),
            Self::Unknown(_) | Self::Below { .. } => None,
        }
    }

    /// The value, or the source text of what is only known when the code runs.
    pub fn text(&self) -> &str {
        match self {
            Self::Known(text) | Self::Unknown(text) | Self::Below { source: text, .. } => text,
        }
    }
}

/// How deep code may run code (`exec("…")` inside `exec("…")`) before the
/// reader stops following it.
pub const MAX_DEPTH: usize = 8;

/// How deep a parse tree is walked before the code is too nested to read:
/// walking deeper would risk overflowing the stack.
pub const MAX_TREE_DEPTH: usize = 400;

/// The longest code a caller should hand the reader: it reads in time that
/// grows with the code, and the strings it works out from names are held to a
/// few times this. A caller refuses longer code before it reads (the shell
/// guard's limit on a line is the same number).
pub const MAX_LEN: usize = 64 * 1024;

/// Visit every node under `root`, without recursion, so a deep tree cannot
/// overflow the stack.
pub(crate) fn for_each_node<'tree>(
    root: tree_sitter::Node<'tree>,
    mut visit: impl FnMut(tree_sitter::Node<'tree>),
) {
    let mut cursor = root.walk();
    loop {
        visit(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// The source text of `node`.
pub(crate) fn text<'s>(node: &tree_sitter::Node<'_>, source: &'s str) -> &'s str {
    source.get(node.byte_range()).unwrap_or_default()
}
