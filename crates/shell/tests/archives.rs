//! Archives. Unpacking writes into a folder: the one an option names, or
//! the working directory with none, judged like any write, in every shell
//! and by every prefix of tar's long options; a mode only known when it runs
//! may unpack. Archiving that deletes what it archives (`tar --remove-files`,
//! `zip -m`, `7z a -sdel`) deletes its members, judged as `rm` judges its
//! operands and with the reasons of `rm`; without such an option it deletes
//! nothing.

mod common;

use common::{check, macos, posix, reason, rules, took, windows};
use milo_guards_shell::{classify, Paths, Rule, Shell};
use std::time::Duration;

#[test]
fn unpacking_an_archive_is_judged_by_the_folder_it_fills() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar -xf x.tar",
            "tar xf x.tar",
            "tar xzvf x.tgz",
            "tar -xzf x.tgz -C build",
            "tar -xf x.tar -C ./out/deps",
            "tar -xf x.tar -C .",
            "tar -xf x.tar --directory build",
            "tar --extract --file=x.tar --directory=build",
            "tar -xf x.tar -C /tmp/scratch",
            "tar -xf x.tar -C ~/work/repo/vendor",
            "tar -xf x.tar -C /home/me/work/repo",
            "tar -C build -xf x.tar",
            "tar -xOf x.tar notes.txt | head",
            "tar --to-stdout -xf x.tar notes.txt",
            "tar -cf x.tar src",
            "tar czf out.tgz -C ~/work/repo/src .",
            "tar -czf out.tgz -C ~ notes",
            "tar -tf x.tar",
            "tar tvf x.tar",
            "unzip x.zip",
            "unzip -o x.zip",
            "unzip x.zip -d build",
            "unzip -o x.zip -d build/deps",
            "unzip -qod build x.zip",
            "unzip -dbuild x.zip",
            "unzip -l x.zip",
            "unzip -p x.zip notes.txt | head",
            "unzip -c x.zip notes.txt",
            "unzip -t x.zip",
            "unzip -Z x.zip",
            "unzip -P secret x.zip -d build",
            "7z x a.7z",
            "7z x a.7z -obuild",
            "7z x -obuild a.7z",
            "7z e a.7z -o/tmp/scratch",
            "7z l a.7z",
            "7z a out.7z src",
            "7z x a.7z -aoa",
            "cd build && tar -xf ../x.tar",
            // With no folder, into the working directory.
            "cd build && tar -xf x.tar",
            "cd build && unzip x.zip",
        ],
        &[
            ("tar -xf x.tar -C ~", Rule::Overwrite),
            ("tar xf x.tar -C ~", Rule::Overwrite),
            ("tar -xzf x.tgz -C ~", Rule::Overwrite),
            ("tar -xzf x.tgz -C /usr/local", Rule::Overwrite),
            ("tar -xf x.tar -C /", Rule::Overwrite),
            ("tar -xf x.tar -C ..", Rule::Overwrite),
            ("tar -xf x.tar -C ../other", Rule::Overwrite),
            ("tar -xf x.tar -C ~/.ssh", Rule::Overwrite),
            ("tar -xf x.tar -C~", Rule::Overwrite),
            ("tar -xf x.tar -C$HOME", Rule::Overwrite),
            ("tar -xf x.tar -C \"$DEST\"", Rule::Overwrite),
            ("tar -xf x.tar --directory ~", Rule::Overwrite),
            ("tar -xf x.tar --directory=~", Rule::Overwrite),
            ("tar -xf x.tar --dir ~", Rule::Overwrite),
            ("tar --extract -f x.tar -C ~", Rule::Overwrite),
            ("tar --get -f x.tar -C ~", Rule::Overwrite),
            ("tar -C ~ -xf x.tar", Rule::Overwrite),
            ("tar -xf x.tar -C build -C ~", Rule::Overwrite),
            ("tar xCf ~ x.tar", Rule::Overwrite),
            ("tar -xf x.tar --one-top-level=/etc", Rule::Overwrite),
            ("bsdtar -xf x.tar -C ~", Rule::Overwrite),
            ("gtar -xf x.tar -C ~", Rule::Overwrite),
            ("sudo tar -xf x.tar -C /usr/local", Rule::Overwrite),
            ("unzip -o x.zip -d ~", Rule::Overwrite),
            ("unzip x.zip -d ~", Rule::Overwrite),
            ("unzip x.zip -d /etc", Rule::Overwrite),
            ("unzip x.zip -d ..", Rule::Overwrite),
            ("unzip -d ~ x.zip", Rule::Overwrite),
            ("unzip -d~ x.zip", Rule::Overwrite),
            ("unzip -qod ~ x.zip", Rule::Overwrite),
            ("unzip x.zip -x '*.o' -d ~", Rule::Overwrite),
            ("unzip x.zip -d \"$DEST\"", Rule::Overwrite),
            ("7z x a.7z -o~", Rule::Overwrite),
            ("7z x -o/etc a.7z", Rule::Overwrite),
            ("7z e a.7z -o..", Rule::Overwrite),
            ("7z x a.7z -O/etc", Rule::Overwrite),
            ("7za x a.7z -o~", Rule::Overwrite),
            ("7zz x a.7z -o~", Rule::Overwrite),
            ("7z x a.7z -o$DEST", Rule::Overwrite),
            // With no folder, into the working directory.
            ("cd ~ && tar -xf x.tar", Rule::Overwrite),
            ("cd ~ && unzip x.zip", Rule::Overwrite),
            ("cd ~ && 7z x a.7z", Rule::Overwrite),
            ("cd / && tar xf x.tar", Rule::Overwrite),
            ("cd .. && tar xf x.tar", Rule::Overwrite),
            ("cd /etc && unzip x.zip", Rule::Overwrite),
            ("cd ~/.ssh && tar -xf x.tar", Rule::Overwrite),
            ("cd $SOMEWHERE && tar -xf x.tar", Rule::Overwrite),
            ("cd ~ && tar -xf x.tar -C .", Rule::Overwrite),
            ("cd ~ && unzip x.zip -d .", Rule::Overwrite),
        ],
    );
    // The same lines from a home that is the working directory.
    let home = Paths::new("/home/me", "/home/me", ["/home/me/work/repo"]);
    check(
        Shell::Posix,
        &home,
        &[],
        &[
            ("tar -xf x.tar", Rule::Overwrite),
            ("unzip x.zip", Rule::Overwrite),
            ("7z x a.7z", Rule::Overwrite),
        ],
    );
    check(
        Shell::Posix,
        &macos(),
        &["tar -xf x.tar -C build", "unzip x.zip -d /tmp/x"],
        &[
            ("tar -xf x.tar -C ~", Rule::Overwrite),
            ("tar -xf x.tar -C /Users/me", Rule::Overwrite),
            ("unzip x.zip -d /Applications", Rule::Overwrite),
        ],
    );
}

#[test]
fn archives_in_powershell_and_cmd_are_judged_by_their_folder() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "Expand-Archive x.zip -DestinationPath build",
            "Expand-Archive x.zip -DestinationPath build -Force",
            "Expand-Archive -Path x.zip -DestinationPath build",
            "Expand-Archive -LiteralPath x.zip -DestinationPath .",
            "Expand-Archive x.zip build",
            "Expand-Archive -Path x.zip build",
            "Expand-Archive x.zip",
            "Expand-Archive x.zip -DestinationPath \"$env:TEMP\\x\"",
            "Expand-Archive x.zip -DestinationPath C:\\Users\\me\\dev\\repo\\vendor",
            "tar -xf x.tar -C build",
            "tar -xf x.zip",
            "tar -tf x.zip",
            "7z x a.7z -obuild",
        ],
        &[
            ("Expand-Archive x.zip -DestinationPath ~", Rule::Overwrite),
            (
                "Expand-Archive -Path x.zip -DestinationPath C:\\Windows",
                Rule::Overwrite,
            ),
            (
                "Expand-Archive -LiteralPath x.zip -DestinationPath $HOME",
                Rule::Overwrite,
            ),
            ("Expand-Archive x.zip C:\\", Rule::Overwrite),
            ("Expand-Archive -Path x.zip ~", Rule::Overwrite),
            ("Expand-Archive x.zip ~\\Documents", Rule::Overwrite),
            ("Expand-Archive x.zip -Dest ~", Rule::Overwrite),
            (
                "Expand-Archive x.zip -DestinationPath $dest",
                Rule::Overwrite,
            ),
            ("Set-Location ~; Expand-Archive x.zip", Rule::Overwrite),
            ("cd C:\\; Expand-Archive x.zip -Force", Rule::Overwrite),
            ("tar -xf x.tar -C C:\\Windows", Rule::Overwrite),
            ("tar -xf x.zip -C ~", Rule::Overwrite),
            ("7z x a.7z -oC:\\Windows", Rule::Overwrite),
            ("unzip x.zip -d C:\\", Rule::Overwrite),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "tar -xf x.zip -C build",
            "7z x a.7z -obuild",
            "7z.exe x a.7z -obuild",
        ],
        &[
            ("tar -xf x.zip -C C:\\Windows", Rule::Overwrite),
            ("tar.exe -xf x.zip -C C:\\", Rule::Overwrite),
            ("7z x a.7z -oC:\\Windows", Rule::Overwrite),
            ("7z.exe x a.7z -oC:\\", Rule::Overwrite),
            ("cd C:\\ && tar -xf x.zip", Rule::Overwrite),
        ],
    );
}

/// tar takes any unique prefix of a long option. A prefix that is a flag to
/// one tar and an option with a value to another takes no value: `--inc` is
/// `--incremental` in GNU tar and `--include` in bsdtar, and `--mod` is
/// `--mode` in GNU tar and the only prefix of `--modification-time` (`-m`) in
/// bsdtar; the next argument is a member or an option.
#[test]
fn tar_reads_a_long_option_by_any_prefix_that_fits() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar --cre -f x.tar -C ~ .",
            "tar --crea -f x.tar -C ~ .",
            "tar --lis -f x.tar -C ~",
            "tar --upd -f x.tar -C ~ .",
            "tar --app -f x.tar -C ~ .",
            "tar --dif -f x.tar -C ~",
            "tar --com -f x.tar -C ~",
            "tar --ext --to-stdout -f x.tar -C ~",
            "tar --ext --to-s -f x.tar -C ~",
            "tar --extr --to-std -f x.tar -C ~",
            "tar --ex -f x.tar -C ~",
            "tar --one-file-system -f x.tar -C ~",
            "tar --ext -f x.tar -C build",
            "tar --ext --dir build -f x.tar",
            "tar --ext --one-top=build -f x.tar",
            "tar -cf x.tar --inc src --remove-files",
        ],
        &[
            ("tar --ext -f x.tar -C ~", Rule::Overwrite),
            ("tar --extr -f x.tar -C ~", Rule::Overwrite),
            ("tar --extra -f x.tar -C ~", Rule::Overwrite),
            ("tar --extrac -f x.tar -C ~", Rule::Overwrite),
            ("tar --ext -C ~ -f x.tar", Rule::Overwrite),
            ("tar --ext -f x.tar --dir ~", Rule::Overwrite),
            ("tar --ext -f x.tar --one-top=~", Rule::Overwrite),
            ("tar --ext -f x.tar --one-top-level=~", Rule::Overwrite),
            ("bsdtar --ext -f x.tar -C ~", Rule::Overwrite),
            ("gtar --extr -f x.tar -C /etc", Rule::Overwrite),
            ("tar --ext -f x.tar -C \"$d\"", Rule::Overwrite),
            ("gtar -cf x.tar --inc ~ --remove-files", Rule::Delete),
            ("tar -cf x.tar --incremental ~ --remove-files", Rule::Delete),
            ("tar -xf x.tar --inc -C /etc", Rule::Overwrite),
            ("gtar -xf x.tar --inc -C /etc", Rule::Overwrite),
            ("tar -xf x.tar --mod -C /etc", Rule::Overwrite),
            ("bsdtar -xf x.tar --mod -C /etc", Rule::Overwrite),
            ("tar -xpf x.tar --mod -C ~", Rule::Overwrite),
        ],
    );
}

#[test]
fn tar_with_a_mode_only_known_when_it_runs_may_unpack() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar -czf \"$out\" -C ~ .",
            "tar -cf \"$out\" -C ~ \"$file\"",
            "tar -tf \"$a\" -C ~",
            "tar \"$mode\" -f x.tar -C build",
            "tar $mode -f x.tar -C .",
            "tar \"$mode\" -f x.tar -O -C ~",
            "tar --create -f \"$out\" -C ~ .",
            "tar -xf x.tar \"$file\"",
        ],
        &[
            ("tar \"$mode\" -f x.tar -C ~", Rule::Overwrite),
            ("tar $mode -C ~", Rule::Overwrite),
            ("tar -f x.tar $mode -C ~", Rule::Overwrite),
            ("tar -f x.tar -C ~ \"-$mode\"", Rule::Overwrite),
            ("tar \"$mode\" -f x.tar -C /usr/local", Rule::Overwrite),
            ("tar $(echo xf) x.tar -C ~", Rule::Overwrite),
            ("cd ~ && tar $mode x.tar", Rule::Overwrite),
        ],
    );
}

/// `tar --remove-files` deletes the members it archives, read from where
/// each `-C` moves; members only known when it runs, from a list or from a
/// mode only known when it runs may be anything. Members inside the
/// workspace, and packing without the option, stay safe.
#[test]
fn tar_remove_files_deletes_its_members() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "tar -cf x.tar *",
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
            "tar -cf x.tar -C src a --remove-files",
            "tar -cf x.tar -C build -C out . --remove-files",
            "tar -cf x.tar a -C ~ --remove-files",
        ],
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
            // Where `-C` moves.
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
            // Members only known when it runs.
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

/// `zip -m` (`--move`) deletes the members it archives; members inside the
/// workspace, and packing without it, stay safe.
#[test]
fn zip_m_deletes_its_members() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "zip x.zip src",
            "zip -r x.zip *",
            "zip x.zip /etc/hosts",
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
        ],
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

/// The options zip reads to find the archive and its members.
#[test]
fn zip_reads_its_options_to_find_the_members() {
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
            // A bare `-x` keeps the names after it out of the members.
            "zip -m x.zip src -x ~",
            "zip -m x.zip src --exclude ~ ~",
            "zip -m x.zip src -x ~ @",
            "zip -m x.zip -x b @ src",
            "zip -m -db x.zip src",
            "zip -dbm x.zip src",
            "zip -mr x.zip src -li",
            "zip -mr x.zip src -li keep",
            "zip -mr --logfile-path log x.zip src",
            "zip -mr --logfile-path=log x.zip src",
            "zip -m -UN warn x.zip src",
            "zip -m --unicode warn x.zip src",
            "zip -m x.zip src -x \"$X\" '*.o'",
        ],
        &[
            // `-xpat`, `-x=pat`, `--exclude=pat` and `-ipat` are one value;
            // the archive's name and the members after them stay operands.
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
            // `@` ends an exclude or include list.
            ("zip -m -x b @ x.zip ~", Rule::Delete),
            ("zip -m x.zip -x b @ ~", Rule::Delete),
            ("zip -m x.zip src -x b @ ~", Rule::Delete),
            ("zip -m x.zip -x b c @ ~", Rule::Delete),
            ("zip -m x.zip --exclude b @ ~", Rule::Delete),
            ("zip -m x.zip -i b @ ~", Rule::Delete),
            ("zip -m x.zip -i b @ ~ -x c", Rule::Delete),
            ("zip -m -x b @ x.zip src ~", Rule::Delete),
            // Two-letter flags ending in `b` or `s` take no value; the single
            // letters still take theirs.
            ("zip -m -db x.zip ~", Rule::Delete),
            ("zip -m -sb x.zip ~", Rule::Delete),
            ("zip -m -ws x.zip ~", Rule::Delete),
            ("zip -dbm x.zip ~", Rule::Delete),
            ("zip -sbm x.zip ~", Rule::Delete),
            ("zip -r -dbm x.zip ~", Rule::Delete),
            ("zip -mdb x.zip ~", Rule::Delete),
            ("zip -mwsr x.zip ~", Rule::Delete),
            // `-li` is a flag and opens no include list.
            ("zip -mr x.zip src -li ~", Rule::Delete),
            ("zip -m x.zip src -rli ~", Rule::Delete),
            ("zip -mr x.zip src -lli ~", Rule::Delete),
            // A long option takes a value only when zip has it by that name.
            ("zip -mr --unzip-command cmd x.zip ~", Rule::Delete),
            ("zip -mr --logfile-path log x.zip ~", Rule::Delete),
            ("zip -mr --test x.zip ~", Rule::Delete),
            // A value attached to its option ends the bundle.
            ("zip -m -lfout x.zip ~", Rule::Delete),
            ("zip -m -n.dat x.zip ~", Rule::Delete),
            ("zip -m -n.mat x.zip ~", Rule::Delete),
            ("zip -m -s1t x.zip ~", Rule::Delete),
            ("zip -m -s1x x.zip ~ src", Rule::Delete),
            // `-UN` (`--unicode`) takes `q`, `w`, `i`, `n` or a word; its last
            // letter must not be read as `-n`, which would take the archive's
            // name.
            ("zip -m -UN=warn x.zip ~", Rule::Delete),
            ("zip -m -UN=n x.zip ~", Rule::Delete),
            ("zip -UNwarn -m x.zip ~", Rule::Delete),
            ("zip -mUNn x.zip ~", Rule::Delete),
            ("zip -m --unicode warn x.zip ~", Rule::Delete),
            // A variable can be a switch or `@`, which zip ends a list at, so
            // the names after it are operands again.
            ("zip -m x.zip src -x \"$X\" ~", Rule::Delete),
            ("zip -m x.zip src -x $X ~", Rule::Delete),
            ("zip -m x.zip -x \"$X\" ~", Rule::Delete),
            ("zip -mr x.zip src -x \"$X\" /etc", Rule::Delete),
            ("zip -m x.zip src --exclude \"$X\" ~", Rule::Delete),
            ("zip -m x.zip src -i \"$X\" ~", Rule::Delete),
        ],
    );
}

/// `7z a -sdel` (and `u`) deletes the members it archives. With no name
/// after the archive's it packs, and deletes, everything in the folder; a
/// switch with a value only known when it runs starts with `-` and is no
/// operand.
#[test]
fn seven_zip_sdel_deletes_its_members() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "7z a x.7z src",
            "7z a x.7z *",
            "7z a x.7z src -sdel",
            "7z a -sdel x.7z src",
            "7z u x.7z src/a.txt -sdel",
            "7z a x.7z *.log -sdel",
            "7z a x.7z src -sdel -x!~",
            "7z l x.7z ~ -sdel",
            "7z x a.7z -sdel",
            "7z d x.7z ~ -sdel",
            "7z a x.7z src -tzip -mx9",
            // A name or an `-i` switch says what to pack; so do commands that
            // do not add.
            "7z a x.7z -sdel -i!src",
            "7z a x.7z -sdel -ir!src",
            "7z a x.7z",
            "7z a x.7z -x!keep",
            "7z a -sdel",
            "7z l x.7z -sdel",
            "7z x x.7z -sdel",
            "7z d x.7z -sdel",
            "7z a -p\"$PASS\" x.7z src -sdel",
        ],
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
            // No name: everything in the folder.
            ("cd ~ && 7z a -sdel x.7z", Rule::Delete),
            ("cd ~ && 7z u -sdel x.7z", Rule::Delete),
            ("7z a x.7z -sdel -i!~", Rule::Delete),
            ("7z a x.7z -sdel -i@list.txt", Rule::Delete),
            // A switch with a value only known when it runs.
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
}

#[test]
fn seven_zip_sdel_on_windows() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "7z a x.7z src -sdel",
            "7z x a.7z -sdel",
            "7z a -sdel x.7z src",
        ],
        &[
            ("7z a x.7z ~ -sdel", Rule::Delete),
            ("7z a x.7z $HOME -sdel", Rule::Delete),
            ("7z a x.7z C:\\Users\\me -sdel", Rule::Delete),
            ("7z a x.7z C:\\Windows -sdel", Rule::Delete),
            ("7z a x.7z * -sdel", Rule::Delete),
            ("7z a x.7z $dir -sdel", Rule::Delete),
            ("7z a -sdel x.7z", Rule::Delete),
            ("7z u x.7z -sdel", Rule::Delete),
            ("cd ~; 7z a -sdel x.7z", Rule::Delete),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "7z a x.7z src -sdel",
            "7z a x.7z C:\\Windows",
            "7z a -sdel x.7z src",
        ],
        &[
            ("7z a x.7z C:\\Windows -sdel", Rule::Delete),
            ("7z a x.7z %USERPROFILE% -sdel", Rule::Delete),
            ("7z a x.7z * -sdel", Rule::Delete),
            ("7z a -sdel x.7z", Rule::Delete),
            ("7z u x.7z -sdel -x!keep", Rule::Delete),
            ("cd %USERPROFILE% && 7z a -sdel x.7z", Rule::Delete),
            ("7z a -sdel -p%PW% x.7z", Rule::Delete),
        ],
    );
}

#[test]
fn archiving_that_deletes_is_judged_from_the_machines_home() {
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

/// Packing the home folder reads the keys in it (`read_secret`), but with no
/// option that deletes what it archives it is no `delete`. `7z a` adds a
/// named folder with everything under it, so it reads the keys in the home
/// as well; that read is not judged yet (a followup), so its rows are held
/// only to "no `delete`", not to Safe.
#[test]
fn archiving_the_home_without_removing_it_does_not_delete() {
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
        let found = rules(line, Shell::Posix, &paths);
        assert!(
            found.contains(&Rule::ReadSecret),
            "expected ReadSecret: {line}"
        );
        assert!(!found.contains(&Rule::Delete), "unexpected Delete: {line}");
    }
    for (shell, paths, line) in [
        (Shell::Posix, posix(), "7z a x.7z ~"),
        (Shell::PowerShell, windows(), "7z a x.7z ~ "),
    ] {
        let found = rules(line, shell, &paths);
        assert!(!found.contains(&Rule::Delete), "unexpected Delete: {line}");
    }
}

/// The delete of each archiver gives the reason `rm -rf` gives for the same
/// members; with no name, `7z` packs `*`.
#[test]
fn an_archivers_delete_gives_the_reason_of_rm() {
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
        ("zip -mr x.zip ~", "rm -rf ~"),
        ("zip -mr x.zip *", "rm -rf *"),
        ("zip -mr x.zip .", "rm -rf ."),
        ("zip -mr x.zip /etc", "rm -rf /etc"),
        ("zip -mr x.zip \"$DIR\"", "rm -rf \"$DIR\""),
        ("7z a x.7z ~ -sdel", "rm -rf ~"),
        ("7z a x.7z * -sdel", "rm -rf *"),
        ("7z a x.7z . -sdel", "rm -rf ."),
        ("7z a x.7z /etc -sdel", "rm -rf /etc"),
        ("7z a -sdel x.7z", "rm -rf *"),
        ("7z a x.7z -sdel -x!keep", "rm -rf *"),
        ("7za a -sdel x.7z", "rm -rf *"),
        ("7z u -sdel x.7z", "rm -rf *"),
        ("7z a x.7z -sdel -r", "rm -rf *"),
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
fn the_rules_give_a_reason_a_prompt_can_show() {
    for (line, rule, reason_text) in [
        (
            "tar -xf x.tar -C ~",
            Rule::Overwrite,
            "unpacks into your home directory",
        ),
        (
            "unzip x.zip -d /etc",
            Rule::Overwrite,
            "unpacks into a system folder",
        ),
        (
            "tar -xf x.tar -C ../x",
            Rule::Overwrite,
            "unpacks into a folder outside the workspace",
        ),
        (
            "tar -xf x.tar -C \"$D\"",
            Rule::Overwrite,
            "unpacks into a folder only known when it runs",
        ),
        (
            "tar -cf x.tar ~ --remove-files",
            Rule::Delete,
            "deletes your home directory",
        ),
    ] {
        assert_eq!(
            reason(line, Shell::Posix, &posix(), rule).as_deref(),
            Some(reason_text),
            "{line}"
        );
    }
}

#[test]
#[cfg_attr(
    coverage,
    ignore = "timing: `just timing` runs it in an optimized build"
)]
fn a_long_chain_of_dash_c_is_read_quickly() {
    // Each `-C` is joined to the one before it; the chain must stay bounded,
    // not be copied onto every later member.
    let mut line = "tar -cf x.tar --remove-files".to_string();
    line.push_str(&" -Ca".repeat(8_000));
    line.push_str(&" *".repeat(3_000));
    assert!(line.len() <= 64 * 1024, "{}", line.len());
    let took = took(&line, Shell::Posix, &posix());
    assert!(took < Duration::from_millis(200), "took {took:?}");
    assert!(!classify(&line, Shell::Posix, &posix())
        .findings()
        .is_empty());
}
