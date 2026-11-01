//! What a third review of `destroy_resources` found: a loop or pipeline
//! variable that is quoted still names every container the loop reaches, and
//! four cloud tables missed a delete verb their sibling CLIs have.

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

#[test]
fn a_quoted_loop_variable_is_not_one_container() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "docker rm -f \"$id\"",
            "docker rm \"$c\"",
            // A variable no loop or read sets is one value.
            "docker rm -f \"$id\"; for c in a b; do echo \"$c\"; done",
            "id=web; docker rm -f \"$id\"",
        ],
        &[
            (
                "for c in $(docker ps -aq); do docker rm -f \"$c\"; done",
                DESTROY,
            ),
            (
                "docker ps -aq | while read c; do docker rm -f \"$c\"; done",
                DESTROY,
            ),
            (
                "docker ps -aq | while IFS= read -r c; do docker rm -f \"$c\"; done",
                DESTROY,
            ),
            ("for c in web db; do docker rm -f \"$c\"; done", DESTROY),
            ("for c in web db; do docker rm -f \"${c}\"; done", DESTROY),
            ("for c in web db; do docker rm -f $c; done", DESTROY),
            (
                "for c in $(docker ps -aq); do docker container rm -f \"$c\"; done",
                DESTROY,
            ),
            ("docker ps -aq | xargs docker rm -f", DESTROY),
        ],
    );
}

#[test]
fn a_quoted_powershell_loop_variable_is_not_one_container() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "docker rm -f \"$id\"",
            "docker rm -f $env:ID",
            "docker rm -f \"$env:ID\"",
        ],
        &[
            ("docker ps -aq | % { docker rm -f \"$_\" }", DESTROY),
            (
                "docker ps -aq | ForEach-Object { docker rm -f \"$PSItem\" }",
                DESTROY,
            ),
            (
                "foreach ($c in docker ps -aq) { docker rm -f \"$c\" }",
                DESTROY,
            ),
            ("docker ps -aq | % { docker rm -f $_ }", DESTROY),
            (
                "docker ps -aq | ForEach-Object { docker rm -f $PSItem }",
                DESTROY,
            ),
            ("foreach ($c in docker ps -aq) { docker rm -f $c }", DESTROY),
            ("foreach ($c in 'a','b') { docker rm -f \"$c\" }", DESTROY),
        ],
    );
}

#[test]
fn cloud_tables_catch_the_delete_verbs_their_siblings_have() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "gcloud storage rsync -r . gs://b",
            "firebase database:get /",
            "oci os object list --bucket-name b",
            "az storage blob list --account-name a -c c",
        ],
        &[
            ("oci os object bulk-delete --bucket-name b --force", DESTROY),
            (
                "gcloud storage rsync -r . gs://b --delete-unmatched-destination-objects",
                DESTROY,
            ),
            (
                "gcloud storage rsync --delete-unmatched-destination-objects -r . gs://b",
                DESTROY,
            ),
            ("firebase database:remove / --force", DESTROY),
            (
                "az storage remove --account-name a -c c --recursive",
                DESTROY,
            ),
            // The siblings these match stay risky.
            ("aws s3 rm s3://b --recursive", DESTROY),
            ("gsutil rsync -d . gs://b", DESTROY),
            ("aws s3 sync . s3://b --delete", DESTROY),
        ],
    );
}
