//! What the crate says of a module specifier and of a coding declaration
//! outside the code it reads, and the shape of an argument.

use milo_guards_code::{
    declares_other_encoding, is_data_url, is_foreign_module, Arg, MAX_DEPTH, MAX_LEN,
    MAX_TREE_DEPTH,
};

#[test]
fn a_data_url_is_found_as_the_url_parser_reads_it() {
    for specifier in [
        "data:text/javascript,console.log(1)",
        "DATA:text/javascript,x",
        "Data:x",
        // Leading control characters and spaces, tabs and newlines inside.
        " data:x",
        "\u{1}\ndata:x",
        "da\tta:x",
        "d\na\rt\ta:x",
    ] {
        assert!(is_data_url(specifier), "{specifier:?}");
    }
    for specifier in [
        "",
        "dat",
        "data",
        "./data:x",
        "database:x",
        "https://example.com/data:x",
        "lodash",
        "./x.js",
    ] {
        assert!(!is_data_url(specifier), "{specifier:?}");
    }
}

#[test]
fn a_module_is_foreign_when_it_is_not_the_workspaces_own() {
    for specifier in [
        // The network, and a registry that downloads.
        "http://example.com/a.js",
        "https://example.com/a.js",
        "HTTPS://example.com/a.js",
        "jsr:@std/path",
        "npm:left-pad",
        // A file outside the workspace.
        "/tmp/x.js",
        "~/x.js",
        "\\\\server\\share\\x.js",
        "..",
        "../x.js",
        "..\\x.js",
        "file:///tmp/x.js",
        "FILE:x.js",
        "C:\\x.js",
        "c:/x.js",
        // As the URL parser reads it.
        " https://example.com/a.js",
        "ht\ntps://example.com/a.js",
    ] {
        assert!(is_foreign_module(specifier), "{specifier:?}");
    }
    for specifier in [
        // The workspace's own, and an installed package.
        "./x.js",
        "x.js",
        "src/x.js",
        "fs",
        "node:fs",
        "lodash",
        "@scope/pkg",
        "json",
        "",
        // A data URL is its own question.
        "data:text/javascript,x",
    ] {
        assert!(!is_foreign_module(specifier), "{specifier:?}");
    }
}

#[test]
fn another_coding_declaration_than_utf_8_is_found_in_code_read_as_bytes() {
    for code in [
        "# coding: utf-7\nprint(1)",
        "# -*- coding: latin-1 -*-\nprint('é')",
        "#!/usr/bin/python\n# vim: set fileencoding=utf-16 :\nprint(1)",
        "# coding=cp037\nprint(1)",
        // ASCII-compatible, but the text is not all ASCII.
        "# coding: latin-1\nprint('é')",
    ] {
        assert!(declares_other_encoding(code), "{code:?}");
    }
    for code in [
        "print(1)",
        "# coding: utf-8\nprint('é')",
        "# -*- coding: UTF8 -*-\nprint(1)",
        "# coding: utf-8-sig\nprint(1)",
        // ASCII-compatible, and the text is all ASCII: read the same.
        "# coding: latin-1\nprint(1)",
        "# coding: ascii\nprint(1)",
        // Not in the first two lines, or not a declaration.
        "print(1)\nprint(2)\n# coding: utf-7\n",
        "x = 'coding: utf-7'",
    ] {
        assert!(!declares_other_encoding(code), "{code:?}");
    }
}

#[test]
fn an_argument_is_its_value_or_the_source_of_what_is_not_known() {
    let known = Arg::Known("/home/me".to_string());
    assert_eq!(known.known(), Some("/home/me"));
    assert_eq!(known.text(), "/home/me");

    let unknown = Arg::Unknown("input()".to_string());
    assert_eq!(unknown.known(), None);
    assert_eq!(unknown.text(), "input()");

    // A path somewhere in a folder is not a value, but it has a source.
    let below = Arg::Below {
        folder: "/home/me/.ssh/".to_string(),
        source: "'/home/me/.ssh/id_' + n".to_string(),
    };
    assert_eq!(below.known(), None);
    assert_eq!(below.text(), "'/home/me/.ssh/id_' + n");
}

#[test]
fn the_limits_are_the_ones_a_caller_holds_code_to() {
    assert_eq!(MAX_DEPTH, 8);
    assert_eq!(MAX_TREE_DEPTH, 400);
    assert_eq!(MAX_LEN, 64 * 1024);
}
