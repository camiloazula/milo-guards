//! What a review of `destroy_resources` found: a rehearsal flag with a value
//! only known when it runs, rehearsal and help flags read past `--` and as
//! the value of another option, aws's `--no-dry-run`, hcloud and terragrunt
//! options that take a value, and a word that splits after a quoted head or
//! as a brace list. Each table holds the lines of one finding, safe and
//! risky.

mod common;

use common::{check, posix, windows};
use milo_guards_shell::{Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

fn posix_rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

#[test]
fn a_rehearsal_whose_value_is_only_known_when_it_runs_is_not_one() {
    posix_rows(
        &[
            "helm uninstall api --dry-run",
            "helm uninstall api --dry-run=server",
            "helm uninstall api --dry-run=client",
            "helm uninstall api --dry-run=true",
            "helm uninstall api --dry-run=\"true\"",
            "pulumi destroy --yes --preview-only",
            "pulumi destroy --yes --preview-only=true",
            "pulumi destroy --yes --preview-only=1",
            "kubectl delete ns prod --dry-run=server",
            // A later known value is read again.
            "helm uninstall api --dry-run=$D --dry-run",
        ],
        &[
            ("helm uninstall api --dry-run=$DRY", DESTROY),
            ("helm uninstall api --dry-run=\"$DRY\"", DESTROY),
            ("helm uninstall api --dry-run=$(cat flag)", DESTROY),
            ("helm uninstall api --dry-run --dry-run=$DRY", DESTROY),
            ("pulumi destroy --yes --preview-only=$P", DESTROY),
            ("pulumi destroy --yes --preview-only=\"$P\"", DESTROY),
            ("pulumi destroy --preview-only --preview-only=$P", DESTROY),
            // A value that is neither yes nor no is no rehearsal either.
            ("helm uninstall api --dry-run=maybe", DESTROY),
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
    // For the destroying flag a value only known when it runs counts as on.
    posix_rows(
        &[
            "terraform apply -destroy=false",
            "terraform plan -destroy=$D",
        ],
        &[
            ("terraform apply -destroy=$D", DESTROY),
            ("terraform apply -destroy=\"$D\" -auto-approve", DESTROY),
            ("terraform apply -destroy=false -destroy=$D", DESTROY),
            ("terragrunt run-all apply -destroy=$D", DESTROY),
        ],
    );
}

#[test]
fn rehearsal_and_help_flags_are_not_read_past_dashes_or_as_a_value() {
    posix_rows(
        &[
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
        ],
        &[
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
        ],
    );
}

#[test]
fn aws_reads_the_last_of_dry_run_and_no_dry_run() {
    posix_rows(
        &[
            "aws ec2 terminate-instances --instance-ids i-1 --dry-run",
            "aws ec2 terminate-instances --instance-ids i-1 --no-dry-run --dry-run",
            "aws ec2 terminate-instances --no-dry-run --instance-ids i-1 --dry-run",
            "aws s3 rm s3://b --recursive --dryrun",
            // After `--` it is no flag, so the rehearsal stands.
            "aws ec2 terminate-instances --instance-ids i-1 --dry-run -- --no-dry-run",
        ],
        &[
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
}

#[test]
fn hcloud_skips_the_values_of_its_global_options() {
    posix_rows(
        &[
            "hcloud server list",
            "hcloud --config f --context prod server list",
            "hcloud --poll-interval 1s --context prod server describe web",
        ],
        &[
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
    posix_rows(
        &[
            "terragrunt run --all --queue-include-dir a --queue-exclude-dir b -- plan",
            "terragrunt run --all --parallelism 4 -- apply",
            "terragrunt run --all -- apply -destroy=false",
            "terragrunt run-all --terragrunt-include-dir a --terragrunt-exclude-dir b plan",
            "terragrunt run --all -- terraform plan",
            "terragrunt run --all --source s --iam-assume-role r --log-format json -- plan",
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
        ],
    );
    check(
        Shell::Posix,
        &posix(),
        &["terragrunt run --all --queue-include-dir a -- plan"],
        &[
            ("terragrunt run --all -- $cmd", Rule::Unknown),
            (
                "terragrunt run --all --queue-include-dir a -- $cmd",
                Rule::Unknown,
            ),
            ("terragrunt run-all $cmd", Rule::Unknown),
        ],
    );
}

#[test]
fn a_word_that_splits_after_a_quoted_head_or_as_a_brace_list_is_computed() {
    posix_rows(
        &[
            "docker rm -f web",
            "docker rm -f \"$a\"",
            "docker rm -f \"a$b\"",
            "docker rm -f \"$a\"\"$b\"",
            "docker rm -f \"$a\"x",
            "docker rm -f 'web$b'",
            "docker rm -f web\\$b",
            "docker rm -f \"${a:-x,y}\"",
            "docker rm -f \"$a\"'{1,2}'",
            "docker rm -f \"$*\"",
            "docker rm -f web{1}",
            "docker rm -f 'web{1,2'",
        ],
        &[
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
    // Neither PowerShell nor cmd expands braces.
    check(
        Shell::PowerShell,
        &windows(),
        &["docker rm -f \"$a\"", "docker rm -f web"],
        &[("docker rm -f $a", DESTROY)],
    );
}
