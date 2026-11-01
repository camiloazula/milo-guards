//! The rule about resources the guard sees no path for: containers and their
//! volumes, cluster objects, infrastructure stacks and what a cloud CLI
//! deletes.
//!
//! Each program is read like git is: the program, its global options, its
//! command and sub-command, and the few options that change what a command
//! does (`-v`, `--all`, `--dry-run`). Listing, creating and describing are
//! safe; what is left is a table of delete verbs for each CLI.

use super::Checker;
use crate::path::brace_list;
use crate::unit::{has_flag, Arg, Unit};
use crate::{Rule, Shell};

/// What a program's line says.
enum Say<'a> {
    /// Nothing that destroys.
    Safe,
    /// A reason a prompt can show, and the thing it acts on.
    Destroys(&'static str, Option<&'a Arg>),
    /// The command is only known when it runs; `None` is the usual reason
    /// ("runs a docker command only known when it runs"), `Some` its own.
    Unread(Option<&'static str>),
}

use Say::{Destroys, Safe, Unread};

impl Checker<'_> {
    /// Containers, clusters, infrastructure stacks and cloud resources.
    pub(super) fn resources(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let values = values_of(key);
        if helped(args, &values) {
            return;
        }
        let said = match key {
            // Containers.
            "docker" | "podman" | "nerdctl" => engine(args, unit.shell),
            "docker-compose" | "podman-compose" => compose(args),
            // Clusters.
            "kubectl" | "oc" => kubectl(args),
            "microk8s" => microk8s(args),
            "k3s" => k3s(args),
            "minikube" => minikube(args),
            "helm" => helm(args),
            "kind" => kind(args),
            "k3d" => k3d(args),
            // Infrastructure.
            "terraform" | "tofu" => terraform(args),
            "terragrunt" => terragrunt(args),
            "pulumi" => pulumi(args),
            "cdk" => first_word(
                args,
                &values,
                |word| word == "destroy",
                "destroys the stacks of a CDK app",
            ),
            "cdktf" => first_word(
                args,
                &values,
                |word| word == "destroy",
                "destroys the stacks of a CDKTF app",
            ),
            "sst" => first_word(
                args,
                &values,
                |word| word == "remove",
                "removes everything an SST app created",
            ),
            "serverless" | "sls" => first_word(
                args,
                &values,
                |word| word == "remove",
                "removes a Serverless service and its resources",
            ),
            "vagrant" => first_word(
                args,
                &values,
                |word| word == "destroy",
                "destroys virtual machines",
            ),
            // Cloud.
            "aws" => aws(args),
            "gcloud" => cloud(
                args,
                &values,
                6,
                |before, word| {
                    matches!(word, "delete" | "destroy")
                        || (before == Some("storage") && word == "rm")
                },
                "deletes Google Cloud resources",
            ),
            "gsutil" => gsutil(args),
            "az" => cloud(
                args,
                &values,
                5,
                |_, word| {
                    word == "delete"
                        || word == "purge"
                        || word.starts_with("delete-")
                        || word.starts_with("purge-")
                },
                "deletes Azure resources",
            ),
            "doctl" => cloud(
                args,
                &values,
                4,
                |_, word| matches!(word, "delete" | "del" | "d" | "rm"),
                "deletes DigitalOcean resources",
            ),
            "flyctl" | "fly" => cloud(
                args,
                &values,
                3,
                |_, word| matches!(word, "destroy" | "delete" | "rm" | "remove"),
                "destroys a Fly.io app, machine or volume",
            ),
            "vercel" => cloud(
                args,
                &values,
                2,
                |_, word| matches!(word, "remove" | "rm" | "del"),
                "removes Vercel deployments, projects or settings",
            ),
            "heroku" => cloud(
                args,
                &values,
                2,
                |_, word| word == "destroy" || word.ends_with(":destroy"),
                "destroys a Heroku app or add-on",
            ),
            "wrangler" => cloud(
                args,
                &values,
                4,
                |_, word| word == "delete" || word.ends_with(":delete"),
                "deletes Cloudflare resources",
            ),
            "firebase" => cloud(
                args,
                &values,
                1,
                |_, word| word.ends_with(":delete"),
                "deletes Firebase resources",
            ),
            "hcloud" => cloud(
                args,
                &values,
                3,
                |_, word| word == "delete",
                "deletes Hetzner Cloud resources",
            ),
            "scw" => cloud(
                args,
                &values,
                4,
                |_, word| matches!(word, "delete" | "terminate"),
                "deletes Scaleway resources",
            ),
            "oci" => cloud(
                args,
                &values,
                6,
                |_, word| matches!(word, "delete" | "terminate"),
                "deletes Oracle Cloud resources",
            ),
            "eksctl" => cloud(
                args,
                &values,
                2,
                |_, word| word == "delete",
                "deletes an EKS cluster or its parts",
            ),
            "kops" => cloud(
                args,
                &values,
                2,
                |_, word| word == "delete",
                "deletes a kops cluster or its parts",
            ),
            "sam" => first_word(
                args,
                &values,
                |word| word == "delete",
                "deletes an AWS SAM application's stack",
            ),
            _ => return,
        };
        match said {
            Safe => {}
            Destroys(reason, target) => self.add(Rule::DestroyResources, reason, target),
            Unread(Some(reason)) => self.add(Rule::Unknown, reason, None),
            Unread(None) => self.add(
                Rule::Unknown,
                format!(
                    "runs {} {key} command only known when it runs",
                    article(key)
                ),
                None,
            ),
        }
    }
}

/// The article before a program's name: `an aws command`, `a docker command`.
/// Programs read as letters (`sst`) count by the sound of the first one.
fn article(program: &str) -> &'static str {
    if program.starts_with(['a', 'e', 'i', 'o', 'u']) || matches!(program, "sst" | "sls" | "scw") {
        "an"
    } else {
        "a"
    }
}

/// The options a program (and the programs it runs) take a value for, which
/// are the words a rehearsal or help flag can be the value of. A wrapper
/// reads the lists of what it wraps too: reading one word too many as a value
/// only makes a line riskier.
fn values_of(key: &str) -> Vec<&'static str> {
    let list: &[&[&'static str]] = match key {
        "docker" | "podman" | "nerdctl" => &[ENGINE_VALUES, COMPOSE_VALUES, RM_VALUES],
        "docker-compose" | "podman-compose" => &[COMPOSE_VALUES],
        "kubectl" | "oc" | "k3s" => &[KUBECTL_VALUES],
        "microk8s" => &[SMALL_CLUSTER_VALUES, KUBECTL_VALUES],
        "minikube" => &[MINIKUBE_VALUES, KUBECTL_VALUES],
        "helm" => &[HELM_VALUES],
        "kind" | "k3d" => &[SMALL_CLUSTER_VALUES],
        "terragrunt" => &[TERRAGRUNT_VALUES],
        "pulumi" => &[PULUMI_VALUES],
        "cdk" => &[CDK_VALUES],
        "sst" => &[SST_VALUES],
        "serverless" | "sls" => &[SERVERLESS_VALUES],
        "aws" => &[AWS_VALUES],
        "gcloud" => &[GCLOUD_VALUES],
        "gsutil" => &[GSUTIL_VALUES],
        "az" => &[AZ_VALUES],
        "doctl" => &[DOCTL_VALUES],
        "flyctl" | "fly" => &[FLY_VALUES],
        "vercel" => &[VERCEL_VALUES],
        "heroku" => &[HEROKU_VALUES],
        "wrangler" => &[WRANGLER_VALUES],
        "firebase" => &[FIREBASE_VALUES],
        "hcloud" => &[HCLOUD_VALUES],
        "scw" => &[SCW_VALUES],
        "oci" => &[OCI_VALUES],
        "eksctl" => &[EKSCTL_VALUES],
        "kops" => &[KOPS_VALUES],
        _ => &[],
    };
    list.concat()
}

// What each program takes a value for, before its command. A value that is
// missed would be read as the command, so each list holds every global
// option the program has that takes one.

/// Options of docker, podman and nerdctl that take a value.
const ENGINE_VALUES: &[&str] = &[
    "--config",
    "-c",
    "--context",
    "-H",
    "--host",
    "-l",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "--connection",
    "--identity",
    "--url",
    "--root",
    "--runroot",
    "--storage-driver",
    "--storage-opt",
    "--conmon",
    "--cgroup-manager",
    "--events-backend",
    "--hooks-dir",
    "--network-config-dir",
    "--runtime",
    "--runtime-flag",
    "--tmpdir",
    "--imagestore",
    "--module",
    "--namespace",
    "-n",
    "--address",
    "-a",
    "--cni-path",
    "--cni-netconfpath",
    "--data-root",
    "--hosts-dir",
    "--snapshotter",
    "--cni-config-dir",
    "--cdi-spec-dirs",
    "--bridge-ip",
];

/// Options of `docker compose` that take a value.
const COMPOSE_VALUES: &[&str] = &[
    "-f",
    "--file",
    "-p",
    "--project-name",
    "--profile",
    "--project-directory",
    "--env-file",
    "--ansi",
    "--parallel",
    "--progress",
    "--podman-args",
    "--podman-path",
    "--in-pod",
    "--pod-args",
    "--context",
    "-H",
    "--host",
];

/// Options of `docker rm` and `podman rm` that take a value.
const RM_VALUES: &[&str] = &["-t", "--time", "--cidfile", "--filter"];

/// Options of kubectl and oc that take a value, global ones and those of the
/// commands that matter here (`delete`, `drain`, `scale`, `apply`).
const KUBECTL_VALUES: &[&str] = &[
    "-n",
    "--namespace",
    "--context",
    "--cluster",
    "--kubeconfig",
    "--user",
    "-s",
    "--server",
    "--token",
    "--as",
    "--as-group",
    "--as-uid",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cache-dir",
    "--request-timeout",
    "--tls-server-name",
    "--username",
    "--password",
    "--profile",
    "--profile-output",
    "-v",
    "--v",
    "--vmodule",
    "--log-flush-frequency",
    "--loglevel",
    "--config",
    "-f",
    "--filename",
    "-k",
    "--kustomize",
    "-l",
    "--selector",
    "-o",
    "--output",
    "--field-selector",
    "--grace-period",
    "--timeout",
    "--raw",
    "--replicas",
    "--current-replicas",
    "--resource-version",
    "--pod-selector",
    "--chunk-size",
    "--template",
    "--prune-allowlist",
    "--field-manager",
];

/// Options of helm that take a value.
const HELM_VALUES: &[&str] = &[
    "-n",
    "--namespace",
    "--kube-context",
    "--kubeconfig",
    "--kube-as-user",
    "--kube-as-group",
    "--kube-apiserver",
    "--kube-ca-file",
    "--kube-token",
    "--kube-tls-server-name",
    "--burst-limit",
    "--qps",
    "--registry-config",
    "--repository-cache",
    "--repository-config",
    "--description",
    "--cascade",
    "--timeout",
];

/// Options of minikube that take a value.
const MINIKUBE_VALUES: &[&str] = &[
    "-p",
    "--profile",
    "-v",
    "--v",
    "--vmodule",
    "--log_dir",
    "--log_file",
    "--log_file_max_size",
    "--stderrthreshold",
    "-o",
    "--output",
];

/// Options of k3d, kind and microk8s that take a value.
const SMALL_CLUSTER_VALUES: &[&str] = &["--loglevel", "-v", "--verbosity", "--name", "-n"];

/// Options of pulumi that take a value.
const PULUMI_VALUES: &[&str] = &[
    "--color",
    "-C",
    "--cwd",
    "--memprofilerate",
    "--profiling",
    "--tracing",
    "-v",
    "--verbose",
    "-s",
    "--stack",
    "-t",
    "--target",
    "-m",
    "--message",
    "-p",
    "--parallel",
    "--config-file",
    "--policy-pack",
];

/// Options of terragrunt that take a value.
const TERRAGRUNT_VALUES: &[&str] = &[
    "--terragrunt-config",
    "--terragrunt-working-dir",
    "--terragrunt-download-dir",
    "--terragrunt-tfpath",
    "--terragrunt-log-level",
    "--working-dir",
    "--config",
    "--download-dir",
    "--tf-path",
    "--log-level",
    "--queue-include-dir",
    "--queue-exclude-dir",
    "--terragrunt-include-dir",
    "--terragrunt-exclude-dir",
    "--parallelism",
    "--terragrunt-parallelism",
    "--source",
    "--terragrunt-source",
    "--iam-assume-role",
    "--terragrunt-iam-role",
    "--log-format",
];

/// Options of cdk that take a value.
const CDK_VALUES: &[&str] = &[
    "-a",
    "--app",
    "-c",
    "--context",
    "-p",
    "--plugin",
    "-r",
    "--role-arn",
    "--profile",
    "--proxy",
    "--ca-bundle-path",
    "-o",
    "--output",
    "--toolkit-stack-name",
    "-t",
    "--build",
];

/// Options of sst that take a value.
const SST_VALUES: &[&str] = &["--stage", "--profile", "--region", "--config"];

/// Options of serverless that take a value.
const SERVERLESS_VALUES: &[&str] = &[
    "--stage",
    "-s",
    "--region",
    "-r",
    "--aws-profile",
    "--config",
    "-c",
    "--param",
];

/// Options of the aws CLI that take a value.
const AWS_VALUES: &[&str] = &[
    "--profile",
    "--region",
    "--output",
    "--endpoint-url",
    "--query",
    "--color",
    "--ca-bundle",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--cli-binary-format",
];

/// Options of gcloud that take a value, global and common to its commands.
const GCLOUD_VALUES: &[&str] = &[
    "--project",
    "--account",
    "--configuration",
    "--billing-project",
    "--impersonate-service-account",
    "--verbosity",
    "--format",
    "--filter",
    "--flags-file",
    "--access-token-file",
    "--trace-token",
    "--zone",
    "--region",
    "--limit",
    "--sort-by",
    "--page-size",
];

/// Options of gsutil that take a value.
const GSUTIL_VALUES: &[&str] = &["-o", "-h", "-u", "-i"];

/// Options of the az CLI that take a value.
const AZ_VALUES: &[&str] = &[
    "-g",
    "--resource-group",
    "-n",
    "--name",
    "--subscription",
    "-o",
    "--output",
    "--query",
    "-l",
    "--location",
];

/// Options of doctl that take a value.
const DOCTL_VALUES: &[&str] = &[
    "-t",
    "--access-token",
    "-c",
    "--config",
    "--context",
    "-o",
    "--output",
    "-u",
    "--api-url",
];

/// Options of flyctl that take a value.
const FLY_VALUES: &[&str] = &[
    "-a",
    "--app",
    "-c",
    "--config",
    "-t",
    "--access-token",
    "-o",
    "--org",
];

/// Options of vercel that take a value.
const VERCEL_VALUES: &[&str] = &[
    "-t",
    "--token",
    "-S",
    "--scope",
    "--cwd",
    "-A",
    "--local-config",
    "-Q",
    "--global-config",
    "--team",
    "-T",
];

/// Options of heroku that take a value.
const HEROKU_VALUES: &[&str] = &["-a", "--app", "-r", "--remote", "-t", "--team"];

/// Options of wrangler that take a value.
const WRANGLER_VALUES: &[&str] = &[
    "-c",
    "--config",
    "-e",
    "--env",
    "--name",
    "--binding",
    "--namespace-id",
    "--cwd",
    "--env-file",
];

/// Options of firebase that take a value.
const FIREBASE_VALUES: &[&str] = &["--project", "-P", "--config", "--token", "--account"];

/// Options of hcloud that take a value.
const HCLOUD_VALUES: &[&str] = &[
    "--config",
    "--context",
    "--endpoint",
    "--poll-interval",
    "--debug-file",
];

/// Options of scw that take a value.
const SCW_VALUES: &[&str] = &["-p", "--profile", "-c", "--config", "-o", "--output"];

/// Options of oci that take a value.
const OCI_VALUES: &[&str] = &[
    "--profile",
    "--region",
    "--config-file",
    "--endpoint",
    "--output",
    "--query",
    "--cert-bundle",
    "--auth",
];

/// Options of eksctl that take a value.
const EKSCTL_VALUES: &[&str] = &[
    "-r",
    "--region",
    "-p",
    "--profile",
    "-v",
    "--verbose",
    "-C",
    "--color",
];

/// Options of kops that take a value.
const KOPS_VALUES: &[&str] = &["--name", "--state", "--config", "-v", "--v"];

/// Whether an argument is an option: it starts with `-` and is more than
/// that. Read from what is written, so `--namespace=$NS` is one too.
fn is_option(arg: &Arg) -> bool {
    let text = written(arg);
    text.len() > 1 && text.starts_with('-')
}

/// The first word that is not an option, with what follows it. An option
/// listed in `values` takes the next word as its value; `--` ends options.
fn command<'a>(args: &'a [Arg], values: &[&str]) -> Option<(&'a Arg, &'a [Arg])> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        if arg.known() == Some("--") {
            let word = args.get(at)?;
            return Some((word, args.get(at + 1..).unwrap_or_default()));
        }
        if is_option(arg) {
            if arg.known().is_some_and(|text| values.contains(&text)) {
                at += 1;
            }
        } else {
            return Some((arg, args.get(at..).unwrap_or_default()));
        }
    }
    None
}

/// The arguments an option or flag can be read from, and the index of the
/// `--` that ends them, if there is one. pflag and Go's flag package give an
/// option that takes a value the next word even when it starts with `-`, so
/// the value of each option in `values` is left out (`--cache-dir
/// --dry-run=server` is a directory, not a rehearsal), and nothing after `--`
/// is a flag.
fn walk<'a>(args: &'a [Arg], values: &[&str]) -> (Vec<&'a Arg>, Option<usize>) {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => return (found, Some(at)),
            Some(text) if is_option(arg) && values.contains(&text) => at += 1,
            _ => found.push(arg),
        }
        at += 1;
    }
    (found, None)
}

/// The arguments before `--` that are not the value of an option in `values`.
fn flags<'a>(args: &'a [Arg], values: &[&str]) -> Vec<&'a Arg> {
    walk(args, values).0
}

/// Whether the line asks for help, which runs nothing.
fn helped(args: &[Arg], values: &[&str]) -> bool {
    flags(args, values)
        .into_iter()
        .filter_map(Arg::known)
        .any(|text| matches!(text, "--help" | "-help"))
}

/// Every word that is not an option, in order, as [`command`] reads them.
fn words<'a>(args: &'a [Arg], values: &[&str]) -> Vec<&'a Arg> {
    let mut found = Vec::new();
    let mut rest = args;
    while let Some((word, after)) = command(rest, values) {
        found.push(word);
        rest = after;
    }
    found
}

/// A command in a list of the names a program has for it.
fn is_one_of(arg: Option<&Arg>, names: &[&str]) -> bool {
    arg.and_then(Arg::known)
        .is_some_and(|text| names.contains(&text))
}

/// Whether an operand names more than one thing, or something only known
/// when it runs and not as one value: a substitution, a pipe's input, a
/// variable the shell splits into words. In a POSIX shell that is an unquoted
/// variable, and a quoted one that holds an array (`"$@"`, `"${ids[@]}"`)
/// since it expands to one word per element. PowerShell passes an array to a
/// program as one argument per element, so a variable (not `$env:`) and a
/// splat (`@ids`) are computed; a quoted one is a string. cmd expands
/// `%VAR%` and `!VAR!` as text, so an unquoted one is several words.
fn computed(arg: &Arg, shell: Shell) -> bool {
    match arg {
        // The quotes are gone from a known word: a brace list in it was
        // written bare or quoted, and bare is the likelier.
        Arg::Known(text) => shell == Shell::Posix && brace_words(text),
        Arg::Input => true,
        Arg::Unknown(text) | Arg::Template { source: text, .. } => {
            text.contains("$(")
                || text.contains('`')
                || text.contains("<(")
                || match shell {
                    Shell::Posix => {
                        !text.starts_with('"')
                            || text.contains("$@")
                            || text.contains("${@")
                            || text.contains("[@]")
                            || splits(text)
                    }
                    Shell::PowerShell => {
                        text.starts_with('(')
                            || text.starts_with("@(")
                            || (text.starts_with('$')
                                && !text
                                    .get(..5)
                                    .is_some_and(|head| head.eq_ignore_ascii_case("$env:")))
                            || (text.starts_with('@') && text.len() > 1)
                    }
                    Shell::Cmd => {
                        !text.starts_with('"') && (text.contains('%') || text.contains('!'))
                    }
                }
        }
    }
}

/// Whether a word of a POSIX shell is read as several words when it runs
/// though it is not a variable that is only known then: it holds an unquoted
/// `$` (`"$a"$b` splits at what `$b` holds, not at the quoted head) or a
/// brace list outside quotes (`web{1,2}`, `{a,b}`, `x{1..3}`).
fn splits(text: &str) -> bool {
    let mut quote = None;
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            // Inside double quotes a backslash keeps the next character; a
            // variable there does not split.
            (Some('"') | None, '\\') => {
                chars.next();
            }
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            // `$'tab\t'` and `$"text"` are quotes, not expansions.
            (None, '$') if !matches!(chars.peek(), Some((_, '\'' | '"')) | None) => return true,
            (None, '{') if brace_words(text.get(at..).unwrap_or_default()) => return true,
            _ => {}
        }
    }
    false
}

/// Whether `text` holds a brace list (`{a,b}`) or a sequence (`{1..3}`): a
/// word the shell makes several of.
fn brace_words(text: &str) -> bool {
    brace_list(text)
        || match (text.find('{'), text.rfind('}')) {
            (Some(open), Some(close)) if open < close => text[open..close].contains(".."),
            _ => false,
        }
}

/// What a Go-style boolean flag (`-destroy`, `--destroy=false`) is given.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Given {
    On,
    Off,
    /// A value only known when it runs, or one the flag does not read.
    Unknown,
}

/// What `arg` gives the flag `name`, or `None` when it is not that flag.
fn given(arg: &Arg, name: &str) -> Option<Given> {
    let text = written(arg).strip_prefix('-')?;
    let text = text.strip_prefix('-').unwrap_or(text);
    let value = if text == name {
        "true"
    } else {
        text.strip_prefix(name)?.strip_prefix('=')?
    };
    if arg.known().is_none() {
        return Some(Given::Unknown);
    }
    Some(match value.to_ascii_lowercase().as_str() {
        "false" | "f" | "0" | "no" | "off" => Given::Off,
        "true" | "t" | "1" | "client" | "server" => Given::On,
        _ => Given::Unknown,
    })
}

/// Whether a flag that makes a line destroy (`terraform apply -destroy`) is
/// turned on anywhere before `--`. Not the last one written: Go's flag
/// package takes the word after an option that takes a value as its value
/// (`-backup -destroy=false`), so a later `=false` may not be one, and a
/// value only known when it runs counts as on.
fn turned_on(args: &[Arg], name: &str) -> bool {
    flags(args, &[])
        .into_iter()
        .filter_map(|arg| given(arg, name))
        .any(|given| given != Given::Off)
}

/// Whether a flag that makes a line only rehearse (`helm uninstall
/// --dry-run`, `pulumi destroy --preview-only`) is turned on: the last one
/// written, and only a value that is known to say yes counts, since a value
/// only known when it runs may be `false`.
fn rehearsal(args: &[Arg], values: &[&str], name: &str) -> bool {
    flags(args, values)
        .into_iter()
        .filter_map(|arg| given(arg, name))
        .next_back()
        == Some(Given::On)
}

/// A command whose only name is its first word.
fn first_word<'a>(
    args: &'a [Arg],
    values: &[&str],
    hit: fn(&str) -> bool,
    reason: &'static str,
) -> Say<'a> {
    let Some((word, rest)) = command(args, values) else {
        return Safe;
    };
    match word.known() {
        Some(text) if hit(text) => Destroys(reason, words(rest, values).first().copied()),
        Some(_) => Safe,
        None => Unread(None),
    }
}

/// A CLI whose delete verb is one of the first `depth` words (`gcloud
/// compute instances delete vm`); `hit` is given the word before it.
fn cloud<'a>(
    args: &'a [Arg],
    values: &[&str],
    depth: usize,
    hit: fn(Option<&str>, &str) -> bool,
    reason: &'static str,
) -> Say<'a> {
    let words = words(args, values);
    let mut before = None;
    let mut unread = false;
    let mut leaf = false;
    for (at, word) in words.iter().take(depth).enumerate() {
        match word.known() {
            Some(text) => {
                if hit(before, text) {
                    return Destroys(reason, words.get(at + 1).copied());
                }
                // A verb that does not delete takes operands, not another
                // verb: `describe $vm` names a machine.
                leaf = leaf || LEAF_VERBS.contains(&text);
            }
            None => unread = unread || !leaf,
        }
        before = word.known();
    }
    if unread {
        Unread(None)
    } else {
        Safe
    }
}

/// Verbs of the cloud CLIs that read, create or change one thing and take
/// operands after them: a word that is only known when it runs behind one is
/// an operand, not the verb that might delete.
const LEAF_VERBS: &[&str] = &[
    "list", "ls", "describe", "get", "show", "create", "add", "set", "update", "read", "logs",
    "status", "info", "inspect", "start", "stop", "restart", "reboot", "resize", "ssh", "scp",
    "deploy", "login", "whoami", "version",
];

/// Whether a kubectl line only rehearses: `--dry-run=client` or `=server`
/// (or bare, as older versions took it), the last one written.
fn dry_run(args: &[Arg]) -> bool {
    let mut on = false;
    for arg in flags(args, KUBECTL_VALUES) {
        let Some(text) = arg.known() else { continue };
        if text == "--dry-run" {
            on = true;
        } else if let Some(value) = text.strip_prefix("--dry-run=") {
            on = matches!(value, "client" | "server" | "true" | "unchanged");
        }
    }
    on
}

/// What `kubectl scale --replicas` is given.
enum Replicas {
    Zero,
    Other,
    Unread,
}

fn replicas(args: &[Arg]) -> Replicas {
    let mut found = Replicas::Other;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let text = written(arg);
        if text == "--" {
            break;
        }
        if text == "--replicas" {
            found = count(iter.next());
        } else if let Some(value) = text.strip_prefix("--replicas=") {
            found = match arg {
                Arg::Known(_) => count(Some(&Arg::Known(value.to_string()))),
                _ => Replicas::Unread,
            };
        }
    }
    found
}

/// What is written for an argument, expansions as they stand.
fn written(arg: &Arg) -> &str {
    match arg {
        Arg::Known(text) | Arg::Unknown(text) | Arg::Template { text, .. } => text,
        Arg::Input => "",
    }
}

fn count(value: Option<&Arg>) -> Replicas {
    match value {
        Some(arg) => match arg.known() {
            Some(text) if text.trim().parse::<i64>() == Ok(0) => Replicas::Zero,
            Some(_) => Replicas::Other,
            None => Replicas::Unread,
        },
        None => Replicas::Other,
    }
}

fn engine(args: &[Arg], shell: Shell) -> Say<'_> {
    let Some((cmd, rest)) = command(args, ENGINE_VALUES) else {
        return Safe;
    };
    let Some(name) = cmd.known() else {
        return Unread(None);
    };
    match name {
        "rm" => return remove_containers(rest, shell),
        "compose" => return compose(rest),
        "system" | "volume" | "container" | "image" | "network" | "stack" | "service" | "pod"
        | "machine" | "kube" => {}
        _ => return Safe,
    }
    let Some((sub, after)) = command(rest, &[]) else {
        return Safe;
    };
    let Some(sub_name) = sub.known() else {
        return Unread(None);
    };
    let target = words(after, &[]).first().copied();
    match (name, sub_name) {
        ("system", "prune") if has_flag(after, None, Some("volumes")) => {
            Destroys("removes unused containers, images and volumes", target)
        }
        ("system", "prune") => Destroys("removes unused containers, networks and images", target),
        ("system", "reset") => Destroys("deletes every container, image and volume", target),
        ("volume", "rm" | "remove") => Destroys("deletes volumes", target),
        ("volume", "prune") => Destroys("deletes unused volumes", target),
        ("container", "rm" | "remove") => remove_containers(after, shell),
        ("container", "prune") => Destroys("deletes every stopped container", target),
        ("image", "prune") if has_flag(after, Some('a'), Some("all")) => {
            Destroys("deletes every unused image", target)
        }
        ("network", "prune") => Destroys("deletes unused networks", target),
        ("stack" | "service", "rm" | "remove") => Destroys("removes swarm services", target),
        ("pod", "rm") => remove_containers(after, shell),
        ("pod", "prune") => Destroys("deletes every stopped pod", target),
        ("machine", "rm") => Destroys("deletes a virtual machine and its containers", target),
        ("kube", "down") => Destroys("removes the pods a file created", target),
        _ => Safe,
    }
}

/// `docker rm`: one named container is safe, even forced. Several forced at
/// once, a choice made when the line runs, every container, and a container's
/// volumes are not.
fn remove_containers(args: &[Arg], shell: Shell) -> Say<'_> {
    let operands = words(args, RM_VALUES);
    let target = operands.first().copied();
    if has_flag(args, Some('a'), Some("all")) {
        return Destroys("removes every container", target);
    }
    if has_flag(args, None, Some("filter")) {
        return Destroys("removes the containers a filter picks", target);
    }
    if operands.iter().any(|arg| computed(arg, shell)) {
        return Destroys("removes containers chosen when it runs", target);
    }
    if has_flag(args, Some('v'), Some("volumes")) {
        return Destroys("removes a container and its volumes", target);
    }
    if operands.len() > 1 && has_flag(args, Some('f'), Some("force")) {
        return Destroys("force-removes several containers", target);
    }
    Safe
}

fn compose(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, COMPOSE_VALUES) else {
        return Safe;
    };
    let Some(name) = cmd.known() else {
        return Unread(None);
    };
    let volumes = has_flag(rest, Some('v'), Some("volumes"));
    match name {
        "down" if volumes => Destroys("deletes a compose project's volumes", None),
        "rm" if volumes => Destroys("removes containers and their volumes", None),
        _ => Safe,
    }
}

fn kubectl(args: &[Arg]) -> Say<'_> {
    // `minikube kubectl -- delete …`: the `--` is minikube's, and what
    // follows is kubectl's own line, help flag included.
    let args = match args.first().and_then(Arg::known) {
        Some("--") => args.get(1..).unwrap_or_default(),
        _ => args,
    };
    if helped(args, KUBECTL_VALUES) {
        return Safe;
    }
    let Some((cmd, rest)) = command(args, KUBECTL_VALUES) else {
        return Safe;
    };
    let Some(name) = cmd.known() else {
        return Unread(None);
    };
    if !matches!(name, "delete" | "drain" | "scale" | "replace" | "apply") || dry_run(rest) {
        return Safe;
    }
    let operands = words(rest, KUBECTL_VALUES);
    let target = operands.first().copied();
    match name {
        "delete" => {
            let kind = operands
                .first()
                .and_then(|arg| arg.known())
                .map(str::to_ascii_lowercase);
            let kind = kind
                .as_deref()
                .map(|kind| kind.split('/').next().unwrap_or(kind));
            let reason = if matches!(kind, Some("namespace" | "namespaces" | "ns")) {
                "deletes a namespace and everything in it"
            } else if has_flag(rest, Some('A'), Some("all-namespaces")) {
                "deletes objects in every namespace"
            } else if has_flag(rest, None, Some("all")) || kind == Some("all") {
                "deletes every object of a kind"
            } else {
                "deletes cluster objects"
            };
            Destroys(reason, target)
        }
        "drain" => Destroys("evicts every pod from a node", target),
        "scale" => match replicas(rest) {
            Replicas::Zero => Destroys("scales a workload down to nothing", target),
            Replicas::Unread => Unread(Some("scales to a count only known when it runs")),
            Replicas::Other => Safe,
        },
        "replace" if has_flag(rest, None, Some("force")) => {
            Destroys("deletes and recreates cluster objects", target)
        }
        "apply" if has_flag(rest, None, Some("prune")) => {
            Destroys("deletes cluster objects the files do not list", target)
        }
        _ => Safe,
    }
}

/// `microk8s kubectl …`, and its own `reset`.
fn microk8s(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, SMALL_CLUSTER_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("kubectl") => kubectl(rest),
        Some("reset") => Destroys("deletes every workload of a MicroK8s cluster", None),
        Some(_) => Safe,
        None => Unread(None),
    }
}

/// `k3s kubectl …`.
fn k3s(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, &[]) else {
        return Safe;
    };
    match cmd.known() {
        Some("kubectl") => kubectl(rest),
        Some(_) => Safe,
        None => Unread(None),
    }
}

/// `minikube delete`, and `minikube kubectl -- …`.
fn minikube(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, MINIKUBE_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("delete") => Destroys("deletes a local Kubernetes cluster", None),
        Some("kubectl") => kubectl(rest),
        Some(_) => Safe,
        None => Unread(None),
    }
}

fn helm(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, HELM_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("uninstall" | "un" | "delete" | "del") if !rehearsal(rest, HELM_VALUES, "dry-run") => {
            Destroys(
                "uninstalls a Helm release",
                words(rest, HELM_VALUES).first().copied(),
            )
        }
        Some(_) => Safe,
        None => Unread(None),
    }
}

fn kind(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, SMALL_CLUSTER_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("delete") => {
            let what = words(rest, SMALL_CLUSTER_VALUES);
            if is_one_of(what.first().copied(), &["cluster", "clusters"]) {
                Destroys("deletes a local Kubernetes cluster", None)
            } else if what.first().is_some_and(|word| word.known().is_none()) {
                Unread(None)
            } else {
                Safe
            }
        }
        Some(_) => Safe,
        None => Unread(None),
    }
}

fn k3d(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, SMALL_CLUSTER_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("cluster" | "node" | "registry") => {
            let what = words(rest, SMALL_CLUSTER_VALUES);
            if is_one_of(what.first().copied(), &["delete", "del", "rm", "remove"]) {
                Destroys("deletes a local Kubernetes cluster", None)
            } else if what.first().is_some_and(|word| word.known().is_none()) {
                Unread(None)
            } else {
                Safe
            }
        }
        Some(_) => Safe,
        None => Unread(None),
    }
}

const TERRAFORM_DESTROYS: &str = "destroys the infrastructure a configuration manages";

fn terraform(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, &[]) else {
        return Safe;
    };
    match cmd.known() {
        Some("destroy") => Destroys(TERRAFORM_DESTROYS, None),
        Some("apply") if turned_on(rest, "destroy") => Destroys(TERRAFORM_DESTROYS, None),
        Some(_) => Safe,
        None => Unread(None),
    }
}

/// terragrunt: terraform's commands, also run over every module (`run-all
/// destroy`, `run --all -- destroy`, the old `destroy-all`). What follows a
/// `--` is handed to terraform (or to the program `exec` runs), so its first
/// word is the command; before it, any word is read.
fn terragrunt(args: &[Arg]) -> Say<'_> {
    let (own, passed) = match walk(args, TERRAGRUNT_VALUES).1 {
        Some(at) => (
            args.get(..at).unwrap_or_default(),
            Some(args.get(at + 1..).unwrap_or_default()),
        ),
        None => (args, None),
    };
    let words = words(own, TERRAGRUNT_VALUES);
    let named = |names: &[&str]| {
        words
            .iter()
            .any(|word| word.known().is_some_and(|text| names.contains(&text)))
    };
    let destroy = turned_on(own, "destroy");
    if named(&["destroy", "destroy-all"]) || (named(&["apply"]) && destroy) {
        return Destroys(TERRAFORM_DESTROYS, None);
    }
    if let Some((word, rest)) = passed.and_then(|passed| command(passed, &[])) {
        match word.known() {
            Some("destroy") => return Destroys(TERRAFORM_DESTROYS, None),
            Some("apply") if destroy || turned_on(rest, "destroy") => {
                return Destroys(TERRAFORM_DESTROYS, None)
            }
            // `exec -- terraform destroy`.
            Some("terraform" | "tofu") => match terraform(rest) {
                Safe => {}
                said => return said,
            },
            Some(_) => {}
            None => return Unread(None),
        }
    }
    // A word only known when it runs where the command goes: nothing but
    // `run-all`, `run` and their like come before it.
    for word in &words {
        match word.known() {
            None => return Unread(None),
            Some("run-all" | "run" | "hcl" | "exec") => {}
            Some(_) => break,
        }
    }
    Safe
}

fn pulumi(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, PULUMI_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("destroy" | "down") if !rehearsal(rest, PULUMI_VALUES, "preview-only") => {
            Destroys("destroys the resources of a Pulumi stack", None)
        }
        Some("stack") => {
            let what = words(rest, PULUMI_VALUES);
            if is_one_of(what.first().copied(), &["rm", "remove"]) {
                Destroys("deletes a Pulumi stack", None)
            } else if what.first().is_some_and(|word| word.known().is_none()) {
                Unread(None)
            } else {
                Safe
            }
        }
        Some(_) => Safe,
        None => Unread(None),
    }
}

fn aws(args: &[Arg]) -> Say<'_> {
    let words = words(args, AWS_VALUES);
    let Some(service) = words.first() else {
        return Safe;
    };
    let Some(service_name) = service.known() else {
        return Unread(None);
    };
    let Some(command_word) = words.get(1) else {
        return Safe;
    };
    let Some(verb) = command_word.known() else {
        return Unread(None);
    };
    let target = words.get(2).copied();
    if rehearses(args) {
        return Safe;
    }
    match (service_name, verb) {
        ("s3", "rm") if has_flag(args, None, Some("recursive")) => {
            Destroys("deletes every object under a prefix", target)
        }
        ("s3", "rm") => Destroys("deletes objects from a bucket", target),
        ("s3", "rb") => Destroys("deletes a bucket", target),
        ("s3", "sync") if has_flag(args, None, Some("delete")) => {
            Destroys("deletes the objects the source does not have", target)
        }
        (_, "terminate-instances") => Destroys("terminates EC2 instances", target),
        (_, verb)
            if verb.starts_with("delete-")
                || verb.starts_with("batch-delete-")
                || verb.starts_with("terminate-")
                || verb.starts_with("purge-")
                || matches!(
                    verb,
                    "delete" | "schedule-key-deletion" | "deregister-image"
                ) =>
        {
            Destroys("deletes AWS resources", target)
        }
        _ => Safe,
    }
}

/// Whether an aws line only rehearses: `--dry-run` (`--dryrun` for `s3`),
/// unless a later `--no-dry-run` turns it off. The CLI reads the last of the
/// two.
fn rehearses(args: &[Arg]) -> bool {
    let mut on = false;
    for text in flags(args, &[]).into_iter().filter_map(Arg::known) {
        if text == "--no-dry-run" {
            on = false;
        } else if let Some(name) = text.strip_prefix("--") {
            if ["dry-run", "dryrun"].iter().any(|flag| {
                name == *flag || name.strip_prefix(flag).is_some_and(|r| r.starts_with('='))
            }) {
                on = true;
            }
        }
    }
    on
}

fn gsutil(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, GSUTIL_VALUES) else {
        return Safe;
    };
    let target = words(rest, &["-x", "-j", "-J", "-a"]).first().copied();
    match cmd.known() {
        Some("rm") => Destroys("deletes Cloud Storage objects", target),
        Some("rb") => Destroys("deletes a Cloud Storage bucket", target),
        Some("rsync") if has_flag(rest, Some('d'), None) => {
            Destroys("deletes the objects the source does not have", target)
        }
        Some(_) => Safe,
        None => Unread(None),
    }
}
