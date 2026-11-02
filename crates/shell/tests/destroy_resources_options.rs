//! How a line that may destroy resources is read: the options before the
//! command (with a value or without) are skipped to find it, a rehearsal or a
//! help flag makes it safe only where the tool reads it as one, a word only
//! known when it runs is unknown where a verb could be and split where the
//! shell splits it, a loop removes every item it reaches, and kubectl's
//! replica count is read as kubectl reads it.

mod common;

use common::{check, posix, rules, windows};
use milo_guards_shell::{Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

#[test]
fn global_options_are_skipped_to_find_the_command() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "cdk --json synth",
            "minikube --logtostderr status",
            "pulumi --logflow preview",
            "aws --cli-auto-prompt s3 ls",
            "gcloud --log-http storage ls gs://b",
            "pulumi --stack dev preview",
            "kubectl --proxy-url http://p:3128 get pods",
            "podman --ssh native ps",
            "helm --color always list",
            "cdktf --log-level debug synth",
            "minikube --user me status",
            "pulumi --tracing-header x preview",
            "podman-compose --podman-run-args x up",
            "hcloud --config f --context prod server list",
            "hcloud --poll-interval 1s --context prod server describe web",
        ],
        &[
            // A flag without a value does not hide the command.
            ("cdk --json destroy", DESTROY),
            ("cdk -j destroy", DESTROY),
            ("cdk --ignore-errors destroy", DESTROY),
            ("cdk --lookups destroy", DESTROY),
            ("cdk --staging destroy", DESTROY),
            ("cdk --notices destroy", DESTROY),
            ("cdk --version-reporting destroy", DESTROY),
            ("cdk --asset-metadata destroy", DESTROY),
            ("cdk --path-metadata destroy", DESTROY),
            ("cdk --app 'node app.js' destroy", DESTROY),
            ("minikube --logtostderr delete --all", DESTROY),
            ("minikube --skip_log_headers delete", DESTROY),
            ("minikube --rootless delete", DESTROY),
            ("minikube --profile dev delete", DESTROY),
            ("pulumi --logflow destroy --yes", DESTROY),
            ("aws --cli-auto-prompt s3 rb s3://x --force", DESTROY),
            ("gcloud --log-http storage rm -r gs://b", DESTROY),
            ("gcloud --user-output-enabled storage rm -r gs://b", DESTROY),
            // An option that takes a value is skipped with its value, so the
            // value is not read as the command.
            ("kubectl --proxy-url http://p:3128 delete ns prod", DESTROY),
            ("kubectl --kuberc x delete ns prod", DESTROY),
            ("kubectl --as-user-extra a=b delete ns prod", DESTROY),
            ("oc --kuberc x delete project prod", DESTROY),
            ("podman --out /dev/null system reset -f", DESTROY),
            ("podman --ssh native volume rm x", DESTROY),
            ("podman --tls-ca F volume rm x", DESTROY),
            ("podman --tls-cert F volume rm x", DESTROY),
            ("podman --tls-key F volume rm x", DESTROY),
            ("podman --tls-details F volume rm x", DESTROY),
            ("podman --cdi-spec-dir D volume rm x", DESTROY),
            ("podman --network-cmd-path P volume rm x", DESTROY),
            ("podman --volumepath P volume rm x", DESTROY),
            ("podman --db-backend sqlite volume rm x", DESTROY),
            ("nerdctl --host-gateway-ip 1.2.3.4 volume rm x", DESTROY),
            ("helm --color always uninstall api", DESTROY),
            ("helm --colour always uninstall api", DESTROY),
            ("helm --content-cache /tmp/x uninstall api", DESTROY),
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
            (
                "hcloud --config f --context prod server delete web",
                DESTROY,
            ),
            (
                "hcloud --poll-interval 1s --context prod server delete web",
                DESTROY,
            ),
            (
                "hcloud --endpoint http://x --debug-file log --config f server delete web",
                DESTROY,
            ),
            ("hcloud --context prod volume delete data", DESTROY),
        ],
    );
}

#[test]
fn terragrunt_reads_the_command_after_dashes_and_every_option_before() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "terragrunt run --all --queue-include-dir a --queue-exclude-dir b -- plan",
            "terragrunt run --all --parallelism 4 -- apply",
            "terragrunt run --all -- apply -destroy=false",
            "terragrunt run-all --terragrunt-include-dir a --terragrunt-exclude-dir b plan",
            "terragrunt run --all -- terraform plan",
            "terragrunt run --all --source s --iam-assume-role r --log-format json -- plan",
            "terragrunt run --all --queue-include-dir a -- plan",
        ],
        &[
            (
                "terragrunt run --all --queue-include-dir a --queue-include-dir b --queue-exclude-dir c -- destroy",
                DESTROY,
            ),
            (
                "terragrunt run-all --terragrunt-include-dir a --terragrunt-include-dir b --terragrunt-exclude-dir c destroy",
                DESTROY,
            ),
            (
                "terragrunt run --all --parallelism 4 --queue-include-dir a --queue-exclude-dir b -- destroy",
                DESTROY,
            ),
            (
                "terragrunt run --all --terragrunt-parallelism 2 --terragrunt-source s --terragrunt-iam-role r --log-format json -- destroy",
                DESTROY,
            ),
            (
                "terragrunt run --all --source s --iam-assume-role r --queue-include-dir a --queue-exclude-dir b -- destroy",
                DESTROY,
            ),
            ("terragrunt run --all -- apply -destroy", DESTROY),
            ("terragrunt run --all -- apply -auto-approve -destroy", DESTROY),
            ("terragrunt run --all -destroy -- apply", DESTROY),
            ("terragrunt exec -- terraform destroy", DESTROY),
            ("terragrunt exec -- tofu apply -destroy", DESTROY),
            ("terragrunt run --all -- -chdir=x destroy", DESTROY),
            ("terragrunt --queue-include-dir a destroy", DESTROY),
            (
                "terragrunt run --all --queue-include-dir a -- $cmd",
                Rule::Unknown,
            ),
        ],
    );
}

/// A rehearsal (`--dry-run`, `--dryrun`, `--preview-only`) or a help flag
/// makes the line safe only when it is on, read as a flag (not past `--`, not
/// as the value of another option) and the last of its kind; a value only
/// known when it runs, or one that is neither yes nor no, is no rehearsal.
/// For the destroying flag `-destroy` it is the other way round: a value only
/// known when it runs counts as on.
#[test]
fn a_rehearsal_or_help_flag_counts_only_where_the_tool_reads_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "pulumi destroy --preview-only",
            "pulumi destroy --yes --preview-only",
            "pulumi destroy --yes --preview-only=true",
            "pulumi destroy --yes --preview-only=1",
            "helm uninstall api --dry-run",
            "helm uninstall api --dry-run=true",
            "helm uninstall api --dry-run=server",
            "helm uninstall api --dry-run=client",
            "helm uninstall api --dry-run=\"true\"",
            "kubectl delete ns prod --dry-run=server",
            // A later known value is read again.
            "helm uninstall api --dry-run=$D --dry-run",
            "terraform apply -destroy=false",
            "terraform plan -destroy=$D",
            // The value of another option is no flag; a flag after one is.
            "kubectl delete ns prod --help",
            "kubectl delete ns prod -n x --dry-run=server",
            "kubectl delete ns prod --cache-dir d --dry-run=server",
            "kubectl delete ns prod --cache-dir d --help",
            "kubectl delete ns prod --dry-run=server --cache-dir d",
            "minikube kubectl -- delete ns prod --help",
            "minikube kubectl -- delete ns prod --dry-run=client",
            "helm uninstall api --description x --dry-run",
            "helm uninstall api --timeout 5s --dry-run",
            "helm uninstall api --cascade foreground --dry-run",
            "pulumi destroy --yes -m x --preview-only",
            "pulumi destroy --yes --stack dev --preview-only",
            "terraform apply -destroy=false -auto-approve",
            "terraform apply -- -destroy",
            // aws reads the last of `--dry-run` and `--no-dry-run`.
            "aws ec2 terminate-instances --instance-ids i-1 --dry-run",
            "aws ec2 terminate-instances --instance-ids i-1 --no-dry-run --dry-run",
            "aws ec2 terminate-instances --no-dry-run --instance-ids i-1 --dry-run",
            "aws s3 rm s3://b --recursive --dryrun",
            // After `--` it is no flag, so the rehearsal stands.
            "aws ec2 terminate-instances --instance-ids i-1 --dry-run -- --no-dry-run",
        ],
        &[
            // A rehearsal turned off is not one.
            ("pulumi destroy --yes --preview-only=false", DESTROY),
            ("pulumi destroy --preview-only=false", DESTROY),
            (
                "pulumi destroy --preview-only --preview-only=false",
                DESTROY,
            ),
            ("helm uninstall api --dry-run=false", DESTROY),
            ("helm uninstall api --dry-run --dry-run=false", DESTROY),
            ("kubectl delete pod web --dry-run=none", DESTROY),
            (
                "kubectl delete pod web --dry-run=client --dry-run=none",
                DESTROY,
            ),
            // A rehearsal whose value is only known when it runs.
            ("helm uninstall api --dry-run=$DRY", DESTROY),
            ("helm uninstall api --dry-run=\"$DRY\"", DESTROY),
            ("helm uninstall api --dry-run=$(cat flag)", DESTROY),
            ("helm uninstall api --dry-run --dry-run=$DRY", DESTROY),
            ("pulumi destroy --yes --preview-only=$P", DESTROY),
            ("pulumi destroy --yes --preview-only=\"$P\"", DESTROY),
            ("pulumi destroy --preview-only --preview-only=$P", DESTROY),
            // A value that is neither yes nor no is no rehearsal either.
            ("helm uninstall api --dry-run=maybe", DESTROY),
            // The destroying flag with a value only known when it runs.
            ("terraform apply -destroy=$D", DESTROY),
            ("terraform apply -destroy=\"$D\" -auto-approve", DESTROY),
            ("terraform apply -destroy=false -destroy=$D", DESTROY),
            ("terragrunt run-all apply -destroy=$D", DESTROY),
            // Past `--`, or as the value of another option, it is no flag.
            ("helm uninstall api -- --dry-run", DESTROY),
            ("pulumi destroy --yes -- --preview-only", DESTROY),
            ("kubectl delete ns prod -- --help", DESTROY),
            ("kubectl delete ns prod -- --dry-run=server", DESTROY),
            ("helm uninstall api --description --dry-run", DESTROY),
            ("helm uninstall api --timeout --dry-run", DESTROY),
            ("helm uninstall api --cascade --dry-run", DESTROY),
            ("pulumi destroy --yes -m --preview-only", DESTROY),
            ("pulumi destroy --yes --stack --preview-only", DESTROY),
            (
                "kubectl delete ns prod --cache-dir --dry-run=server",
                DESTROY,
            ),
            ("kubectl delete ns prod --cache-dir --help", DESTROY),
            ("kubectl delete ns prod -n --help", DESTROY),
            (
                "microk8s kubectl delete ns prod --cache-dir --help",
                DESTROY,
            ),
            (
                "minikube kubectl -- delete ns prod --cache-dir --help",
                DESTROY,
            ),
            ("minikube kubectl -- delete ns prod -- --help", DESTROY),
            (
                "terraform apply -destroy -backup -destroy=false -auto-approve",
                DESTROY,
            ),
            (
                "terraform apply -auto-approve -destroy -- -destroy=false",
                DESTROY,
            ),
            ("terraform apply -destroy -destroy=false", DESTROY),
            (
                "aws ec2 terminate-instances --instance-ids i-1 --dry-run --no-dry-run",
                DESTROY,
            ),
            (
                "aws ec2 terminate-instances --instance-ids i-1 --no-dry-run",
                DESTROY,
            ),
            (
                "aws ec2 terminate-instances --dry-run --instance-ids i-1 --no-dry-run",
                DESTROY,
            ),
        ],
    );
    // PowerShell passes `--dry-run=False` for `$false`.
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "helm uninstall api --dry-run",
            "helm uninstall api --dry-run=true",
        ],
        &[
            ("helm uninstall api --dry-run=$false", DESTROY),
            ("helm uninstall api --dry-run=false", DESTROY),
            ("pulumi destroy --yes --preview-only=$p", DESTROY),
        ],
    );
}

#[test]
fn a_word_only_known_when_it_runs_is_unknown_past_the_first() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "gcloud compute instances describe $VM",
            "gcloud compute instances list --filter=$F",
            "az vm show -g rg -n $VM",
            "az vm show --ids $ID",
            "doctl compute droplet get $ID",
            "kind create cluster --name $N",
            "kind load docker-image $IMG",
            "k3d cluster create $name",
            "pulumi stack select $S",
            "terragrunt plan $dir",
            "terragrunt run-all plan $dir",
        ],
        &[
            ("gcloud projects $verb prod", Rule::Unknown),
            ("gcloud compute instances \"$action\" vm", Rule::Unknown),
            ("az group $verb -n rg", Rule::Unknown),
            ("doctl compute droplet $verb web", Rule::Unknown),
            ("fly apps $verb app", Rule::Unknown),
            ("kind delete $what", Rule::Unknown),
            ("k3d cluster $verb dev", Rule::Unknown),
            ("pulumi stack $verb dev", Rule::Unknown),
            ("terragrunt run-all $cmd", Rule::Unknown),
            ("terragrunt run --all -- $cmd", Rule::Unknown),
            ("gcloud $group delete prod", DESTROY),
            ("gcloud projects delete $id", DESTROY),
        ],
    );
}

/// A container named by a word the shell splits into several (an unquoted
/// variable, `"$@"`, an array, a word after a quoted head, a brace list) is
/// a container chosen when it runs; a quoted word is one container. Neither
/// PowerShell nor cmd expands braces.
#[test]
fn a_computed_container_is_judged_like_the_shell_reads_it() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "docker rm -f \"$name\"",
            "docker rm -f \"$*\"",
            "docker rm -f \"$a\"",
            "docker rm -f \"a$b\"",
            "docker rm -f \"$a\"\"$b\"",
            "docker rm -f \"$a\"x",
            "docker rm -f 'web$b'",
            "docker rm -f web\\$b",
            "docker rm -f \"${a:-x,y}\"",
            "docker rm -f \"$a\"'{1,2}'",
            "docker rm -f web{1}",
            "docker rm -f 'web{1,2'",
        ],
        &[
            ("docker rm -f \"$@\"", DESTROY),
            ("docker rm -f \"${@}\"", DESTROY),
            ("docker rm -f \"${ids[@]}\"", DESTROY),
            ("docker rm \"$@\"", DESTROY),
            ("docker rm -f ${ids[@]}", DESTROY),
            ("docker rm -f \"$a\"$b", DESTROY),
            ("docker rm -f \"$a\"${b}", DESTROY),
            ("docker rm -f \"$a\"$b\"c\"", DESTROY),
            ("docker rm -f \"$a\"-$b", DESTROY),
            ("docker rm \"$a\"$b", DESTROY),
            ("docker rm -f $a", DESTROY),
            ("docker rm -f web{1,2,3}", DESTROY),
            ("docker rm -f {web,db}", DESTROY),
            ("docker rm -f web{1..3}", DESTROY),
            ("docker rm web{1,2}", DESTROY),
            ("docker rm -f \"$a\"{1,2}", DESTROY),
            ("docker rm -f web{1,2}$x", DESTROY),
            ("docker container rm -f {web,db}", DESTROY),
            ("docker rm -f \"web\"{1,2}", DESTROY),
            // A brace list whose commas hold a variable or quote.
            ("docker rm -f {\"$a\",db}", DESTROY),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "docker rm -f \"$name\"",
            "docker rm -f \"$ids\"",
            "docker rm -f $env:NAME",
            "docker rm -f \"$a\"",
        ],
        &[
            ("docker rm -f $ids", DESTROY),
            ("docker rm $ids", DESTROY),
            ("docker rm -f @ids", DESTROY),
            ("docker rm -f $containers.Id", DESTROY),
            ("$ids = docker ps -aq; docker rm -f $ids", DESTROY),
            ("docker rm -f $a", DESTROY),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["docker rm -f \"%IDS%\""],
        &[
            ("docker rm -f %IDS%", DESTROY),
            ("docker rm %IDS%", DESTROY),
            ("docker rm -f !IDS!", DESTROY),
        ],
    );
    // These break this rule and no other.
    assert_eq!(
        rules("docker rm -f $names", Shell::Posix, &posix()),
        vec![DESTROY]
    );
    assert_eq!(
        rules("docker rm -f \"$(docker ps -aq)\"", Shell::Posix, &posix()),
        vec![DESTROY]
    );
    assert_eq!(
        rules("docker rm -f $name", Shell::PowerShell, &windows()),
        vec![DESTROY]
    );
}

/// A loop removes every item it reaches, whatever its variable is called and
/// even when the variable is quoted: the loop's own, one set from it, a
/// function's argument, or one no loop sets at all. A variable no loop or
/// read sets, outside a loop, is one value.
#[test]
fn a_loop_removes_every_item_whatever_its_variable_is_called() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "docker rm -f \"$id\"",
            "docker rm \"$c\"",
            "docker rm -f \"$id\"; for c in a b; do echo \"$c\"; done",
            "id=web; docker rm -f \"$id\"",
            "for c in a b; do docker rm -f web; done",
            "for c in a b; do docker ps -q; done",
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
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "docker rm -f \"$id\"",
            "docker rm -f $env:ID",
            "docker rm -f \"$env:ID\"",
            "$id = 'web'; docker rm -f \"$id\"",
            "docker rm -f \"$id\"; foreach ($c in 'a','b') { echo \"$c\" }",
            "docker ps -aq | ForEach-Object { docker rm -f web }",
            "foreach ($c in 'a','b') { docker rm -f web }",
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
    // No word of cmd's `for` is one container.
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

/// `kubectl scale` to zero replicas stops everything; the count is read as
/// Go reads an integer, so a prefix or an underscore does not make a count
/// that is not 0, and the last count given counts.
#[test]
fn a_replica_count_is_read_as_go_reads_an_integer() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "kubectl scale deploy web --replicas=3",
            "kubectl scale --replicas 2 deploy/web",
            "kubectl scale deploy web --replicas=0 --dry-run=client",
            "kubectl scale deploy web --replicas 3",
            "kubectl scale deploy web --replicas=010",
            "kubectl scale deploy web --replicas=-1",
            "kubectl scale deploy web --cache-dir --replicas=0 --replicas=3",
            "kubectl scale deploy web --replicas=3 -- --replicas=0",
        ],
        &[
            ("kubectl scale deploy web --replicas=0", DESTROY),
            ("kubectl scale --replicas=0 deploy/web", DESTROY),
            ("kubectl scale deploy web --replicas 0", DESTROY),
            ("kubectl -n prod scale deploy web --replicas=0", DESTROY),
            ("kubectl scale deploy web --replicas=00", DESTROY),
            ("kubectl scale deploy web --replicas=0x0", DESTROY),
            ("kubectl scale deploy web --replicas=0X0", DESTROY),
            ("kubectl scale deploy web --replicas=0b0", DESTROY),
            ("kubectl scale deploy web --replicas=0o0", DESTROY),
            ("kubectl scale deploy web --replicas=0_0", DESTROY),
            ("kubectl scale deploy web --replicas=0x_0", DESTROY),
            ("kubectl scale deploy web --replicas=-0x0", DESTROY),
            ("kubectl scale deploy web --replicas=+0b0", DESTROY),
            ("kubectl scale deploy web --replicas 0x0", DESTROY),
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
