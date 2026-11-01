//! What a fifth review of `destroy_resources` found: a replica count kubectl
//! reads in more bases than ten, a loop's variable that is not the loop's own
//! (and no word of cmd's `for` at all), value options the tables did not
//! list, and everyday cloud lines read as unknown because a verb was missing.

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

fn rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

#[test]
fn a_replica_count_is_read_as_go_reads_an_integer() {
    rows(
        &[
            "kubectl scale deploy web --replicas=3",
            "kubectl scale deploy web --replicas 3",
            "kubectl scale deploy web --replicas=010",
            "kubectl scale deploy web --replicas=-1",
            "kubectl scale deploy web --cache-dir --replicas=0 --replicas=3",
            "kubectl scale deploy web --replicas=3 -- --replicas=0",
        ],
        &[
            // A prefix or an underscore does not make a count that is not 0.
            ("kubectl scale deploy web --replicas=0x0", DESTROY),
            ("kubectl scale deploy web --replicas=0X0", DESTROY),
            ("kubectl scale deploy web --replicas=0b0", DESTROY),
            ("kubectl scale deploy web --replicas=0o0", DESTROY),
            ("kubectl scale deploy web --replicas=0_0", DESTROY),
            ("kubectl scale deploy web --replicas=0x_0", DESTROY),
            ("kubectl scale deploy web --replicas=00", DESTROY),
            ("kubectl scale deploy web --replicas=-0x0", DESTROY),
            ("kubectl scale deploy web --replicas=+0b0", DESTROY),
            ("kubectl scale deploy web --replicas 0x0", DESTROY),
            ("kubectl scale deploy web --replicas=0", DESTROY),
            // The last one given counts, and a value of another option is
            // not one.
            (
                "kubectl scale deploy web --replicas=3 --replicas=0x0",
                DESTROY,
            ),
            (
                "kubectl scale deploy web --cache-dir --replicas=3 --replicas=0",
                DESTROY,
            ),
            // A count that is not a plain decimal and not a zero is not one
            // the guard reads.
            ("kubectl scale deploy web --replicas=0x5", Rule::Unknown),
            ("kubectl scale deploy web --replicas=0b1", Rule::Unknown),
            ("kubectl scale deploy web --replicas=1_0", Rule::Unknown),
            ("kubectl scale deploy web --replicas=0_", Rule::Unknown),
            ("kubectl scale deploy web --replicas=0x", Rule::Unknown),
            ("kubectl scale deploy web --replicas=abc", Rule::Unknown),
            ("kubectl scale deploy web --replicas=$N", Rule::Unknown),
        ],
    );
}

#[test]
fn a_loop_removes_every_item_whatever_its_variable_is_called() {
    rows(
        &[
            "id=web; docker rm -f \"$id\"",
            "docker rm -f \"$id\"; for c in a b; do echo \"$c\"; done",
            "for c in a b; do docker rm -f web; done",
            "for c in a b; do docker ps -q; done",
        ],
        &[
            (
                "for c in $(docker ps -aq); do id=\"$c\"; docker rm -f \"$id\"; done",
                DESTROY,
            ),
            (
                "docker ps -aq | while read -r line; do id=${line%% *}; docker rm -f \"$id\"; done",
                DESTROY,
            ),
            (
                "for c in $(docker ps -aq); do name=$(docker inspect -f '{{.Name}}' \"$c\"); docker rm -f \"$name\"; done",
                DESTROY,
            ),
            (
                "set -- $(docker ps -aq); while [ $# -gt 0 ]; do docker rm -f \"$1\"; shift; done",
                DESTROY,
            ),
            (
                "f() { docker rm -f \"$1\"; }; for c in $(docker ps -aq); do f \"$c\"; done",
                DESTROY,
            ),
            ("until false; do docker rm -f \"$x\"; done", DESTROY),
            (
                "for ((i=0;i<3;i++)); do docker container rm \"$x\"; done",
                DESTROY,
            ),
            ("while true; do docker pod rm \"$x\"; done", DESTROY),
            // A loop in a script a shell is handed.
            (
                "sh -c 'for c in a b; do docker rm -f \"$x\"; done'",
                DESTROY,
            ),
        ],
    );
}

#[test]
fn a_powershell_loop_removes_every_item_whatever_its_variable_is_called() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "$id = 'web'; docker rm -f \"$id\"",
            "docker rm -f \"$id\"; foreach ($c in 'a','b') { echo \"$c\" }",
            "docker ps -aq | ForEach-Object { docker rm -f web }",
            "foreach ($c in 'a','b') { docker rm -f web }",
        ],
        &[
            (
                "docker ps -aq | ForEach-Object { $c = $_; docker rm -f \"$c\" }",
                DESTROY,
            ),
            (
                "docker ps -aq | % { $c = $_; docker rm -f \"$c\" }",
                DESTROY,
            ),
            (
                "foreach ($c in docker ps -aq) { $id = $c; docker rm -f \"$id\" }",
                DESTROY,
            ),
            (
                "for ($i = 0; $i -lt 3; $i++) { docker rm -f \"$x\" }",
                DESTROY,
            ),
            ("while ($true) { docker container rm \"$x\" }", DESTROY),
            ("do { docker pod rm \"$x\" } while ($true)", DESTROY),
            ("function f { docker rm -f \"$args\" }", DESTROY),
        ],
    );
}

#[test]
fn a_cmd_for_removes_every_item() {
    check(
        Shell::Cmd,
        &windows(),
        &[
            "for %%c in (web db) do docker rm -f web",
            "for %%c in (web db) do echo %%c",
            "docker rm -f web",
        ],
        &[
            (
                "for /f \"delims=\" %%i in ('docker ps -aq') do docker rm -f \"%%i\"",
                DESTROY,
            ),
            (
                "for /f \"delims=\" %%i in ('docker ps -aq') do @docker rm -f \"%%i\"",
                DESTROY,
            ),
            ("for %%c in (web db) do docker rm -f \"%%c\"", DESTROY),
            (
                "for /f \"delims=\" %%i in ('docker ps -aq') do (set id=%%i& docker rm -f \"!id!\")",
                DESTROY,
            ),
            (
                "for /f \"delims=\" %%i in ('docker ps -aq') do docker container rm \"%%~i\"",
                DESTROY,
            ),
        ],
    );
}

#[test]
fn the_value_options_the_tables_missed_are_skipped_to_find_the_command() {
    rows(
        &[
            "cdktf --log-level debug synth",
            "minikube --user me status",
            "pulumi --tracing-header x preview",
            "podman-compose --podman-run-args x up",
        ],
        &[
            ("cdktf --log-level debug destroy", DESTROY),
            ("cdktf --app \"node x\" destroy", DESTROY),
            ("cdktf -a x destroy", DESTROY),
            ("cdktf -o out destroy", DESTROY),
            ("cdktf --output out destroy", DESTROY),
            ("minikube --user me delete", DESTROY),
            ("minikube -b kubeadm delete", DESTROY),
            ("minikube --bootstrapper kubeadm delete", DESTROY),
            ("minikube --log_backtrace_at f.go:1 delete", DESTROY),
            ("pulumi --tracing-header x destroy -y", DESTROY),
            ("podman-compose --podman-pull-args x down -v", DESTROY),
            ("podman-compose --podman-push-args x down -v", DESTROY),
            ("podman-compose --podman-build-args x down -v", DESTROY),
            ("podman-compose --podman-inspect-args x down -v", DESTROY),
            ("podman-compose --podman-run-args x down -v", DESTROY),
            ("podman-compose --podman-start-args x down -v", DESTROY),
            ("podman-compose --podman-stop-args x down -v", DESTROY),
            ("podman-compose --podman-rm-args x down -v", DESTROY),
            ("podman-compose --podman-volume-args x down -v", DESTROY),
        ],
    );
}

#[test]
fn everyday_cloud_lines_with_a_variable_after_a_copying_or_running_verb_are_safe() {
    rows(
        &[
            "gcloud storage cp $F gs://b/",
            "gcloud storage cp \"$F\" gs://b/",
            "gcloud storage rsync $SRC gs://b",
            "gcloud storage mv $A gs://b/",
            "gcloud pubsub topics publish $T --message x",
            "gcloud container images list-tags $IMG",
            "gcloud sql connect $DB --user root",
            "gcloud config configurations activate $C",
            "az storage blob upload -f $F -c c -n x",
            "az storage blob upload-batch -d c -s $DIR",
            "az storage blob download -c c -n x -f $F",
            "az storage blob download-batch -d $DIR -s c",
            "az acr build -r $R -t img .",
            "vercel pull --environment $E",
            "vercel promote $URL",
            "vercel redeploy $URL",
            "wrangler tail $W",
            "wrangler dev $F",
            "wrangler d1 execute $DB --command \"select 1\"",
            "oci session authenticate --profile-name $P",
            "aws lambda invoke --function-name $F out.json",
        ],
        &[
            // A group's word is still where the verb is.
            ("gcloud projects $verb prod", Rule::Unknown),
            ("gcloud run $verb web", Rule::Unknown),
            // A verb that deletes is read behind a copying one's operand.
            (
                "gcloud storage cp $F gs://b/; gcloud storage rm gs://b/x",
                DESTROY,
            ),
            (
                "gcloud storage rsync $SRC gs://b --delete-unmatched-destination-objects",
                DESTROY,
            ),
            (
                "az storage blob upload -f $F -c c -n x; az group delete -n g -y",
                DESTROY,
            ),
        ],
    );
}
