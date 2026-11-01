//! Archiving that deletes what it archives (issue 34): `tar --remove-files`,
//! `zip -m` and `7z a -sdel` delete their members, judged as `rm` judges its
//! operands.

mod common;

use common::{check, macos, posix, windows};
use milo_guards_shell::{classify, Paths, Rule, Shell};

/// The reason of the first finding of rule `rule` for `line`.
fn reason(line: &str, shell: Shell, paths: &Paths, rule: Rule) -> Option<String> {
    classify(line, shell, paths)
        .findings()
        .iter()
        .find(|finding| finding.rule == rule)
        .map(|finding| finding.reason.clone())
}

#[test]
fn packing_without_removing_stays_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar -cf x.tar src",
            "tar -cf x.tar *",
            "tar -czf out.tgz -C ~ notes",
            "tar czf out.tgz -C ~/work/repo/src .",
            "tar -xf x.tar",
            "tar -tf x.tar",
            "zip x.zip src",
            "zip -r x.zip *",
            "zip x.zip /etc/hosts",
            "7z a x.7z src",
            "7z a x.7z ~",
            "7z a x.7z *",
        ],
        &[],
    );
}

#[test]
fn removing_what_is_inside_the_workspace_is_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar -cf x.tar src --remove-files",
            "tar -czf x.tgz src docs --remove-files",
            "tar --remove-files -cf x.tar src/a.txt",
            "tar -cf x.tar -C src . --remove-files",
            "tar -cf x.tar -C ~/work/repo/build out --remove-files",
            "tar -cf x.tar -C /tmp/scratch . --remove-files",
            "tar -cf x.tar /tmp/scratch/a --remove-files",
            "tar -cf x.tar *.log --remove-files",
            "tar -cf x.tar *git --remove-files",
            "tar -cf x.tar --exclude=keep.txt src --remove-files",
            "tar -cf x.tar --exclude ~ src --remove-files",
            "tar -cf x.tar --exclude-from ~/skip.txt src --remove-files",
            "tar -cf x.tar --transform 's,^,pre/,' src --remove-files",
            "tar -cf x.tar --sparse src --remove-files",
            "tar -cf x.tar --checkpoint src --remove-files",
            "tar -cf x.tar --remove-files --file-not-an-option src",
            "tar -xf x.tar --remove-files",
            "tar -xf x.tar notes --remove-files",
            "zip -m x.zip src/a.txt",
            "zip -mr x.zip src",
            "zip -r -m x.zip src docs",
            "zip -m x.zip build/out.o -x ~",
            "zip -mr x.zip src -x '*.o'",
            "zip -mr x.zip src --exclude '*.o'",
            "zip -m x.zip",
            "zip -mr x.zip *.log",
            "zip -mr -P ~ x.zip src",
            "zip -mr -b ~ x.zip src",
            "zip -mr -t 20200101 x.zip src",
            "zip -mr -tt 20200101 x.zip src",
            "zip -mr -n .zip x.zip src",
            "zip -mr -sf x.zip src",
            "7z a x.7z src -sdel",
            "7z a -sdel x.7z src",
            "7z u x.7z src/a.txt -sdel",
            "7z a x.7z *.log -sdel",
            "7z a x.7z src -sdel -x!~",
            "7z l x.7z ~ -sdel",
            "7z x a.7z -sdel",
            "7z d x.7z ~ -sdel",
            "7z a x.7z src -tzip -mx9",
        ],
        &[],
    );
}

#[test]
fn tar_remove_files_deletes_its_members() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("tar -cf x.tar ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar ~/ --remove-files", Rule::Delete),
            ("tar -cf x.tar $HOME --remove-files", Rule::Delete),
            ("tar cf x.tar ~ --remove-files", Rule::Delete),
            ("tar --remove-files -cf x.tar ~", Rule::Delete),
            ("tar -czf x.tgz ~ --remove-files", Rule::Delete),
            ("tar -rf x.tar ~ --remove-files", Rule::Delete),
            ("tar -uf x.tar ~ --remove-files", Rule::Delete),
            ("tar --create --file=x.tar ~ --remove-files", Rule::Delete),
            ("tar --create --file x.tar ~ --remove-files", Rule::Delete),
            ("tar --append -f x.tar ~ --remove-files", Rule::Delete),
            ("tar --update -f x.tar ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar ~ --remove", Rule::Delete),
            ("tar -cf x.tar ~ --rem", Rule::Delete),
            ("tar -cf x.tar ~ --remove-files=ignored", Rule::Delete),
            ("tar -cf x.tar * --remove-files", Rule::Delete),
            ("tar -cf x.tar . --remove-files", Rule::Delete),
            ("tar -cf x.tar .. --remove-files", Rule::Delete),
            (
                "tar -cf x.tar ../other-project --remove-files",
                Rule::Delete,
            ),
            ("tar -cf x.tar .git --remove-files", Rule::Delete),
            ("tar -cf x.tar ~/.ssh --remove-files", Rule::Delete),
            ("tar -cf x.tar /etc --remove-files", Rule::Delete),
            ("tar -cf x.tar / --remove-files", Rule::Delete),
            ("tar -cf x.tar src ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar ~ src --remove-files", Rule::Delete),
            ("tar -cf x.tar --exclude=a ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --exclude a ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --exclude ~ ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --sparse ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --checkpoint ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar -z ~ --remove-files", Rule::Delete),
            ("tar -cvf x.tar ~ --remove-files", Rule::Delete),
            ("gtar -cf x.tar ~ --remove-files", Rule::Delete),
            ("bsdtar -cf x.tar ~ --remove-files", Rule::Delete),
            ("sudo tar -cf x.tar /etc --remove-files", Rule::Delete),
            ("cd ~ && tar -cf x.tar * --remove-files", Rule::Delete),
            ("cd ~ && tar -cf x.tar . --remove-files", Rule::Delete),
            (
                "cd /etc && tar -cf x.tar passwd --remove-files",
                Rule::Delete,
            ),
            ("tar -cf x.tar --remove-files -- ~", Rule::Delete),
            ("echo ok; tar -cf x.tar ~ --remove-files", Rule::Delete),
        ],
    );
}

#[test]
fn tar_members_are_read_from_where_dash_c_moves() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar -cf x.tar -C src a --remove-files",
            "tar -cf x.tar -C build -C out . --remove-files",
            "tar -cf x.tar a -C ~ --remove-files",
        ],
        &[
            ("tar -cf x.tar -C ~ . --remove-files", Rule::Delete),
            ("tar -cf x.tar -C ~ notes --remove-files", Rule::Delete),
            ("tar -cf x.tar -C ~/.ssh . --remove-files", Rule::Delete),
            ("tar -cf x.tar -C /etc passwd --remove-files", Rule::Delete),
            ("tar -cf x.tar -C/etc passwd --remove-files", Rule::Delete),
            (
                "tar -cf x.tar --directory /etc passwd --remove-files",
                Rule::Delete,
            ),
            (
                "tar -cf x.tar --directory=/etc passwd --remove-files",
                Rule::Delete,
            ),
            ("tar -C /etc -cf x.tar passwd --remove-files", Rule::Delete),
            ("tar cCf /etc x.tar passwd --remove-files", Rule::Delete),
            ("tar -cf x.tar -C .. repo --remove-files", Rule::Delete),
            ("tar -cf x.tar -C src -C .. . --remove-files", Rule::Delete),
            ("tar -cf x.tar -C build -C ~ . --remove-files", Rule::Delete),
            ("tar -cf x.tar -C src a -C ~ b --remove-files", Rule::Delete),
            ("tar -cf x.tar -C \"$DIR\" a --remove-files", Rule::Delete),
            (
                "tar -cf x.tar -C ~ --add-file a --remove-files",
                Rule::Delete,
            ),
            (
                "cd ~ && tar -cf x.tar -C src a --remove-files",
                Rule::Delete,
            ),
        ],
    );
}

#[test]
fn tar_members_only_known_when_it_runs_are_risky() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("tar -cf x.tar \"$DIR\" --remove-files", Rule::Delete),
            ("tar -cf x.tar $FILES --remove-files", Rule::Delete),
            ("tar -cf x.tar $(ls) --remove-files", Rule::Delete),
            ("tar -cf x.tar -T list.txt --remove-files", Rule::Delete),
            ("tar -cf x.tar -Tlist.txt --remove-files", Rule::Delete),
            (
                "tar -cf x.tar --files-from list.txt --remove-files",
                Rule::Delete,
            ),
            (
                "tar -cf x.tar --files-from=list.txt --remove-files",
                Rule::Delete,
            ),
            ("tar -cf x.tar --add-file ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --add-file=~ --remove-files", Rule::Delete),
            ("tar \"$mode\" -f x.tar ~ --remove-files", Rule::Delete),
            ("tar $mode -f x.tar src --remove-files", Rule::Delete),
            ("ls | xargs tar -rf x.tar --remove-files", Rule::Delete),
            ("ls ~ | xargs tar -rf x.tar --remove-files", Rule::Delete),
        ],
    );
}

#[test]
fn tar_delete_reasons_are_those_of_rm() {
    for (line, rm) in [
        ("tar -cf x.tar ~ --remove-files", "rm -rf ~"),
        ("tar -cf x.tar * --remove-files", "rm -rf *"),
        ("tar -cf x.tar . --remove-files", "rm -rf ."),
        ("tar -cf x.tar .git --remove-files", "rm -rf .git"),
        ("tar -cf x.tar -C ~ notes --remove-files", "rm -rf ~/notes"),
        (
            "tar -cf x.tar -C /etc passwd --remove-files",
            "rm -rf /etc/passwd",
        ),
        ("tar -cf x.tar \"$DIR\" --remove-files", "rm -rf \"$DIR\""),
        ("cd ~ && tar -cf x.tar * --remove-files", "cd ~ && rm -rf *"),
    ] {
        let expected = reason(rm, Shell::Posix, &posix(), Rule::Delete);
        assert!(expected.is_some(), "{rm} is not a delete");
        assert_eq!(
            reason(line, Shell::Posix, &posix(), Rule::Delete),
            expected,
            "{line}"
        );
    }
    assert_eq!(
        reason(
            "tar -cf x.tar ~ --remove-files",
            Shell::Posix,
            &posix(),
            Rule::Delete
        )
        .as_deref(),
        Some("deletes your home directory")
    );
    assert_eq!(
        reason(
            "tar -cf x.tar * --remove-files",
            Shell::Posix,
            &posix(),
            Rule::Delete
        )
        .as_deref(),
        reason("rm -rf *", Shell::Posix, &posix(), Rule::Delete).as_deref()
    );
}

#[test]
fn zip_move_deletes_its_members() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("zip -mr x.zip ~", Rule::Delete),
            ("zip -rm x.zip ~", Rule::Delete),
            ("zip -r -m x.zip ~", Rule::Delete),
            ("zip -r x.zip ~ -m", Rule::Delete),
            ("zip -m x.zip ~", Rule::Delete),
            ("zip --move -r x.zip ~", Rule::Delete),
            ("zip --mov -r x.zip ~", Rule::Delete),
            ("zip -mr x.zip *", Rule::Delete),
            ("zip -mr x.zip '*'", Rule::Delete),
            ("zip -mr x.zip .", Rule::Delete),
            ("zip -mr x.zip ..", Rule::Delete),
            ("zip -mr x.zip /etc", Rule::Delete),
            ("zip -mr x.zip ../other-project", Rule::Delete),
            ("zip -mr x.zip .git", Rule::Delete),
            ("zip -mr x.zip '*git'", Rule::Delete),
            ("zip -mr x.zip src ~", Rule::Delete),
            ("zip -mr x.zip ~ -x '*.o'", Rule::Delete),
            ("zip -mr x.zip ~ -x ~/keep", Rule::Delete),
            ("zip -mr x.zip ~ --exclude '*.o'", Rule::Delete),
            ("zip -mr x.zip -i ~", Rule::Delete),
            ("zip -mr x.zip ~ -i '*.c'", Rule::Delete),
            ("zip -mr -b /tmp x.zip ~", Rule::Delete),
            ("zip -mr -t 20200101 x.zip ~", Rule::Delete),
            ("zip -mr -tt 20200101 x.zip ~", Rule::Delete),
            ("zip -mr -P secret x.zip ~", Rule::Delete),
            ("zip -mr -O out.zip x.zip ~", Rule::Delete),
            ("zip -mr -s 100m x.zip ~", Rule::Delete),
            ("zip -mr -s100m x.zip ~", Rule::Delete),
            ("zip -mr -ds 10m x.zip ~", Rule::Delete),
            ("zip -mr --password secret x.zip ~", Rule::Delete),
            ("zip -mr --password=secret x.zip ~", Rule::Delete),
            ("zip -mr -- x.zip ~", Rule::Delete),
            ("zip -mr x.zip \"$DIR\"", Rule::Delete),
            ("zip -mr x.zip $FILES", Rule::Delete),
            ("zip -mr $ARGS", Rule::Delete),
            ("zip -mr -@ x.zip", Rule::Delete),
            ("zip -mr x.zip --names-stdin", Rule::Delete),
            ("ls ~ | zip -m x.zip -@", Rule::Delete),
            ("ls | xargs zip -m x.zip", Rule::Delete),
            ("ls ~ | xargs zip -m x.zip", Rule::Delete),
            ("sudo zip -mr x.zip /etc", Rule::Delete),
            ("cd ~ && zip -mr x.zip *", Rule::Delete),
            ("cd ~ && zip -mr x.zip .", Rule::Delete),
        ],
    );
}

#[test]
fn zip_delete_reasons_are_those_of_rm() {
    for (line, rm) in [
        ("zip -mr x.zip ~", "rm -rf ~"),
        ("zip -mr x.zip *", "rm -rf *"),
        ("zip -mr x.zip .", "rm -rf ."),
        ("zip -mr x.zip /etc", "rm -rf /etc"),
        ("zip -mr x.zip \"$DIR\"", "rm -rf \"$DIR\""),
    ] {
        let expected = reason(rm, Shell::Posix, &posix(), Rule::Delete);
        assert!(expected.is_some(), "{rm} is not a delete");
        assert_eq!(
            reason(line, Shell::Posix, &posix(), Rule::Delete),
            expected,
            "{line}"
        );
    }
}

#[test]
fn seven_zip_sdel_deletes_its_members() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("7z a x.7z ~ -sdel", Rule::Delete),
            ("7z a -sdel x.7z ~", Rule::Delete),
            ("7z a x.7z -sdel ~", Rule::Delete),
            ("7z u x.7z ~ -sdel", Rule::Delete),
            ("7z a x.7z ~ -SDEL", Rule::Delete),
            ("7z A x.7z ~ -sdel", Rule::Delete),
            ("7z a x.7z * -sdel", Rule::Delete),
            ("7z a x.7z '*' -sdel", Rule::Delete),
            ("7z a x.7z . -sdel", Rule::Delete),
            ("7z a x.7z .git -sdel", Rule::Delete),
            ("7z a x.7z '*git' -sdel", Rule::Delete),
            ("7z a x.7z /etc -sdel -r", Rule::Delete),
            ("7z a x.7z ../other-project -sdel", Rule::Delete),
            ("7z a x.7z src ~ -sdel", Rule::Delete),
            ("7z a -tzip -mx9 x.zip ~ -sdel", Rule::Delete),
            ("7z a x.7z ~ -x!'*.o' -sdel", Rule::Delete),
            ("7z a x.7z @list.txt -sdel", Rule::Delete),
            ("7z a x.7z -i!~ -sdel", Rule::Delete),
            ("7z a x.7z -ir!/etc/* -sdel", Rule::Delete),
            ("7z a x.7z -ir0!/etc/* -sdel", Rule::Delete),
            ("7z a x.7z -i@list.txt -sdel", Rule::Delete),
            ("7z a x.7z \"$DIR\" -sdel", Rule::Delete),
            ("7z $CMD x.7z ~ -sdel", Rule::Delete),
            ("7za a x.7z ~ -sdel", Rule::Delete),
            ("7zr a x.7z ~ -sdel", Rule::Delete),
            ("7zz a x.7z ~ -sdel", Rule::Delete),
            ("ls | xargs 7z a x.7z -sdel", Rule::Delete),
            ("sudo 7z a x.7z /etc -sdel", Rule::Delete),
            ("cd ~ && 7z a x.7z * -sdel", Rule::Delete),
        ],
    );
}

#[test]
fn seven_zip_delete_reasons_are_those_of_rm() {
    for (line, rm) in [
        ("7z a x.7z ~ -sdel", "rm -rf ~"),
        ("7z a x.7z * -sdel", "rm -rf *"),
        ("7z a x.7z . -sdel", "rm -rf ."),
        ("7z a x.7z /etc -sdel", "rm -rf /etc"),
    ] {
        let expected = reason(rm, Shell::Posix, &posix(), Rule::Delete);
        assert!(expected.is_some(), "{rm} is not a delete");
        assert_eq!(
            reason(line, Shell::Posix, &posix(), Rule::Delete),
            expected,
            "{line}"
        );
    }
}

#[test]
fn archiving_and_removing_is_judged_from_the_machines_home() {
    check(
        Shell::Posix,
        &macos(),
        &["tar -cf x.tar src --remove-files", "zip -mr x.zip src"],
        &[
            ("tar -cf x.tar ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar /Users/me --remove-files", Rule::Delete),
            ("zip -mr x.zip /Users/me", Rule::Delete),
            ("7z a x.7z /Applications -sdel", Rule::Delete),
        ],
    );
}

#[test]
fn seven_zip_sdel_on_windows() {
    check(
        Shell::PowerShell,
        &windows(),
        &["7z a x.7z src -sdel", "7z a x.7z ~ ", "7z x a.7z -sdel"],
        &[
            ("7z a x.7z ~ -sdel", Rule::Delete),
            ("7z a x.7z $HOME -sdel", Rule::Delete),
            ("7z a x.7z C:\\Users\\me -sdel", Rule::Delete),
            ("7z a x.7z C:\\Windows -sdel", Rule::Delete),
            ("7z a x.7z * -sdel", Rule::Delete),
            ("7z a x.7z $dir -sdel", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["7z a x.7z src -sdel", "7z a x.7z C:\\Windows"],
        &[
            ("7z a x.7z C:\\Windows -sdel", Rule::Delete),
            ("7z a x.7z %USERPROFILE% -sdel", Rule::Delete),
            ("7z a x.7z * -sdel", Rule::Delete),
        ],
    );
}

#[test]
fn zip_exclude_and_include_with_an_attached_value_open_no_list() {
    // `-xpat`, `-x=pat`, `--exclude=pat` and `-ipat` are one value; the
    // archive's name and the members after them stay operands.
    check(
        Shell::Posix,
        &posix(),
        &[
            "zip -m -x'*.o' x.zip src",
            "zip -m -xb x.zip src",
            "zip -m -x=b x.zip src",
            "zip -m --exclude=b x.zip src",
            "zip -m --exc=b x.zip src",
            "zip -mr -x'*.o' x.zip src",
        ],
        &[
            ("zip -m -x'*.o' x.zip ~", Rule::Delete),
            ("zip -mr -x'*.o' x.zip ~", Rule::Delete),
            ("zip -m -xb x.zip ~", Rule::Delete),
            ("zip -m -x=b x.zip ~", Rule::Delete),
            ("zip -m --exclude=b x.zip ~", Rule::Delete),
            ("zip -m --exc=b x.zip ~", Rule::Delete),
            ("zip -m -mx'*.o' x.zip ~", Rule::Delete),
            ("zip -m -i'*.c' x.zip ~", Rule::Delete),
            ("zip -m -i=b x.zip ~", Rule::Delete),
            ("zip -m --include=b x.zip ~", Rule::Delete),
            ("zip -m --include=b x.zip ~ -x b", Rule::Delete),
            ("zip -m -xb x.zip src ~", Rule::Delete),
            ("zip -m -xb -m x.zip ~", Rule::Delete),
            ("zip -m --exclude=b -- x.zip ~", Rule::Delete),
            // A bare one still opens a list that swallows what follows.
            ("zip -m x.zip ~ -x b", Rule::Delete),
            ("zip -m x.zip ~ --exclude b", Rule::Delete),
        ],
    );
    // The bare form keeps the names after it out of the members.
    check(
        Shell::Posix,
        &posix(),
        &["zip -m x.zip src -x ~", "zip -m x.zip src --exclude ~ ~"],
        &[],
    );
}

#[test]
fn zip_at_sign_ends_an_exclude_or_include_list() {
    check(
        Shell::Posix,
        &posix(),
        &["zip -m x.zip src -x ~ @", "zip -m x.zip -x b @ src"],
        &[
            ("zip -m -x b @ x.zip ~", Rule::Delete),
            ("zip -m x.zip -x b @ ~", Rule::Delete),
            ("zip -m x.zip src -x b @ ~", Rule::Delete),
            ("zip -m x.zip -x b c @ ~", Rule::Delete),
            ("zip -m x.zip --exclude b @ ~", Rule::Delete),
            ("zip -m x.zip -i b @ ~", Rule::Delete),
            ("zip -m x.zip -i b @ ~ -x c", Rule::Delete),
            ("zip -m -x b @ x.zip src ~", Rule::Delete),
        ],
    );
}

#[test]
fn zip_two_letter_flags_ending_in_b_or_s_take_no_value() {
    check(
        Shell::Posix,
        &posix(),
        &["zip -m -db x.zip src", "zip -dbm x.zip src"],
        &[
            ("zip -m -db x.zip ~", Rule::Delete),
            ("zip -m -sb x.zip ~", Rule::Delete),
            ("zip -m -ws x.zip ~", Rule::Delete),
            ("zip -dbm x.zip ~", Rule::Delete),
            ("zip -sbm x.zip ~", Rule::Delete),
            ("zip -r -dbm x.zip ~", Rule::Delete),
            ("zip -mdb x.zip ~", Rule::Delete),
            ("zip -mwsr x.zip ~", Rule::Delete),
            // The single letters still take their value.
            ("zip -mr -b /tmp x.zip ~", Rule::Delete),
            ("zip -mr -s 100m x.zip ~", Rule::Delete),
        ],
    );
}

#[test]
fn seven_zip_without_names_packs_everything_in_the_folder() {
    let rm = reason("rm -rf *", Shell::Posix, &posix(), Rule::Delete);
    assert!(rm.is_some());
    for line in [
        "7z a -sdel x.7z",
        "7z a x.7z -sdel -x!keep",
        "7za a -sdel x.7z",
        "7z u -sdel x.7z",
        "7z a x.7z -sdel -r",
    ] {
        assert_eq!(
            reason(line, Shell::Posix, &posix(), Rule::Delete),
            rm,
            "{line}"
        );
    }
    check(
        Shell::Posix,
        &posix(),
        // A name or an `-i` switch says what to pack; so do commands that
        // do not add.
        &[
            "7z a -sdel x.7z src",
            "7z a x.7z -sdel -i!src",
            "7z a x.7z -sdel -ir!src",
            "7z a x.7z",
            "7z a x.7z -x!keep",
            "7z a -sdel",
            "7z l x.7z -sdel",
            "7z x x.7z -sdel",
            "7z d x.7z -sdel",
        ],
        &[
            ("cd ~ && 7z a -sdel x.7z", Rule::Delete),
            ("cd ~ && 7z u -sdel x.7z", Rule::Delete),
            ("7z a x.7z -sdel -i!~", Rule::Delete),
            ("7z a x.7z -sdel -i@list.txt", Rule::Delete),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &["7z a -sdel x.7z src"],
        &[
            ("7z a -sdel x.7z", Rule::Delete),
            ("7z u x.7z -sdel", Rule::Delete),
            ("cd ~; 7z a -sdel x.7z", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["7z a -sdel x.7z src"],
        &[
            ("7z a -sdel x.7z", Rule::Delete),
            ("7z u x.7z -sdel -x!keep", Rule::Delete),
            ("cd %USERPROFILE% && 7z a -sdel x.7z", Rule::Delete),
        ],
    );
}

#[test]
fn zip_li_is_a_flag_and_opens_no_include_list() {
    check(
        Shell::Posix,
        &posix(),
        &["zip -mr x.zip src -li", "zip -mr x.zip src -li keep"],
        &[
            ("zip -mr x.zip src -li ~", Rule::Delete),
            ("zip -m x.zip src -rli ~", Rule::Delete),
            ("zip -mr x.zip src -lli ~", Rule::Delete),
        ],
    );
}

#[test]
fn tar_long_option_that_may_be_a_flag_takes_no_value() {
    // `--inc` is `--incremental` in GNU tar, which takes no value, and
    // `--include` in bsdtar, which does; the next argument is a member.
    check(
        Shell::Posix,
        &posix(),
        &["tar -cf x.tar --inc src --remove-files"],
        &[
            ("gtar -cf x.tar --inc ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --incremental ~ --remove-files", Rule::Delete),
            ("tar -xf x.tar --inc -C /etc", Rule::Overwrite),
            ("gtar -xf x.tar --inc -C /etc", Rule::Overwrite),
        ],
    );
}

#[test]
fn zip_long_values_are_the_names_zip_has() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "zip -mr --logfile-path log x.zip src",
            "zip -mr --logfile-path=log x.zip src",
        ],
        &[
            ("zip -mr --unzip-command cmd x.zip ~", Rule::Delete),
            ("zip -mr --logfile-path log x.zip ~", Rule::Delete),
            ("zip -mr --test x.zip ~", Rule::Delete),
        ],
    );
}

#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "the guard keeps no clock; only this test times it, to catch a quadratic read"
)]
fn a_long_chain_of_dash_c_is_read_quickly() {
    // Each `-C` is joined to the one before it; the chain must stay bounded,
    // not be copied onto every later member.
    let mut line = "tar -cf x.tar --remove-files".to_string();
    line.push_str(&" -Ca".repeat(8_000));
    line.push_str(&" *".repeat(3_000));
    assert!(line.len() <= 64 * 1024, "{}", line.len());
    let started = std::time::Instant::now();
    let assessment = classify(&line, Shell::Posix, &posix());
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_millis(200),
        "took {took:?}"
    );
    assert!(!assessment.findings().is_empty());
}

#[test]
fn zip_a_value_attached_to_its_option_ends_the_bundle() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("zip -m -lfout x.zip ~", Rule::Delete),
            ("zip -m -n.dat x.zip ~", Rule::Delete),
            ("zip -m -n.mat x.zip ~", Rule::Delete),
            ("zip -m -s1t x.zip ~", Rule::Delete),
            ("zip -m -s1x x.zip ~ src", Rule::Delete),
        ],
    );
}

#[test]
fn zip_unicode_option_takes_a_value() {
    // `-UN` (`--unicode`) takes `q`, `w`, `i`, `n` or a word; its last
    // letter must not be read as `-n`, which would take the archive's name.
    check(
        Shell::Posix,
        &posix(),
        &[
            "zip -m -UN warn x.zip src",
            "zip -m --unicode warn x.zip src",
        ],
        &[
            ("zip -m -UN=warn x.zip ~", Rule::Delete),
            ("zip -m -UN=n x.zip ~", Rule::Delete),
            ("zip -UNwarn -m x.zip ~", Rule::Delete),
            ("zip -mUNn x.zip ~", Rule::Delete),
            ("zip -m --unicode warn x.zip ~", Rule::Delete),
        ],
    );
}

#[test]
fn seven_zip_switch_with_a_value_only_known_when_it_runs_is_no_operand() {
    // `-p"$PASS"` starts with `-`: a switch, so the archive is still the
    // first name and, with none after it, the default `*` is packed and
    // deleted.
    check(
        Shell::Posix,
        &posix(),
        &["7z a -p\"$PASS\" x.7z src -sdel"],
        &[
            ("7z a -p\"$PASS\" x.7z -sdel", Rule::Delete),
            ("7z a -sdel -p\"$PASS\" x.7z", Rule::Delete),
            ("7z a -x!\"$SKIP\" x.7z -sdel", Rule::Delete),
            ("7z a -sdel -mx=\"$LEVEL\" backup.7z", Rule::Delete),
            ("7z a -t\"$FMT\" -sdel out.7z", Rule::Delete),
            ("7z a -w\"$T\" x.7z -sdel", Rule::Delete),
            ("7z a $OPTS x.7z -sdel", Rule::Delete),
            ("7z a \"$OPTS\" x.7z -sdel", Rule::Delete),
            ("7z a x.7z -i\"$PAT\" -sdel", Rule::Delete),
            ("7z a x.7z -i!\"$PAT\" -sdel", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[],
        &[("7z a -sdel -p%PW% x.7z", Rule::Delete)],
    );
}

#[test]
fn archiving_the_home_without_removing_it_reads_but_does_not_delete() {
    // Packing the home folder reads the keys in it (`read_secret`), but with
    // no option that deletes what it archives it is no `delete`.
    let paths = posix();
    for line in [
        "tar -cf x.tar ~",
        "tar -rf x.tar ~",
        "zip -r x.zip ~",
        "tar -tf x.tar ~ --remove-files",
        "zip -r x.zip ~ --no-dir-entries",
        "zip -r -s100m x.zip ~",
        "zip -r -n.mp3 x.zip ~",
        "zip -r -ds10m x.zip ~",
        "zip -r -lfmain.log x.zip ~",
    ] {
        let found = common::rules(line, Shell::Posix, &paths);
        assert!(
            found.contains(&Rule::ReadSecret),
            "expected ReadSecret: {line}"
        );
        assert!(!found.contains(&Rule::Delete), "unexpected Delete: {line}");
    }
}

#[test]
fn zip_unknown_argument_inside_a_list_ends_it() {
    // A variable can be a switch or `@`, which zip ends the list at, so the
    // names after it are operands again.
    check(
        Shell::Posix,
        &posix(),
        &["zip -m x.zip src -x \"$X\" '*.o'"],
        &[
            ("zip -m x.zip src -x \"$X\" ~", Rule::Delete),
            ("zip -m x.zip src -x $X ~", Rule::Delete),
            ("zip -m x.zip -x \"$X\" ~", Rule::Delete),
            ("zip -mr x.zip src -x \"$X\" /etc", Rule::Delete),
            ("zip -m x.zip src --exclude \"$X\" ~", Rule::Delete),
            ("zip -m x.zip src -i \"$X\" ~", Rule::Delete),
        ],
    );
}
