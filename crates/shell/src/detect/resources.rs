//! The rule about resources the guard sees no path for: containers and their
//! volumes, cluster objects, infrastructure stacks, hosted repositories and
//! sites, and what a cloud CLI or an object store deletes.
//!
//! Each program is read like git is: the program, its global options, its
//! command and sub-command, and the few options that change what a command
//! does (`-v`, `--all`, `--dry-run`). Listing, creating and describing are
//! safe; what is left is a table of delete verbs for each CLI.

use milo_guards_core::spelling::glob;

use super::Checker;
use crate::path::brace_list;
use crate::unit::{has_flag, Arg, Split, Unit};
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
        let read_as = read_as(key);
        let values = values_of(read_as);
        if helped(args, &values) {
            return;
        }
        let said = match read_as {
            // Containers.
            "docker" | "podman" | "nerdctl" => engine(args, unit, self.split),
            "docker-compose" | "podman-compose" => compose(args),
            "docker-machine" => first_word(
                args,
                &values,
                |word| matches!(word, "rm" | "remove"),
                "deletes a virtual machine and its containers",
            ),
            "colima" => first_word(
                args,
                &values,
                |word| word == "delete",
                "deletes a virtual machine and its containers",
            ),
            // Clusters.
            "kubectl" | "oc" => kubectl(args),
            "microk8s" => microk8s(args),
            "k3s" => k3s(args, &[], &["kubectl"]),
            // `kc` is k0s's short name for its kubectl.
            "k0s" => k3s(args, K0S_VALUES, &["kubectl", "kc"]),
            "minikube" => minikube(args),
            "helm" => helm(args),
            "helmfile" => first_word(
                args,
                &values,
                |word| matches!(word, "destroy" | "delete"),
                "uninstalls the Helm releases a helmfile lists",
            ),
            "kind" => kind(args),
            "k3d" => k3d(args),
            "argocd" => cloud(
                args,
                &values,
                3,
                false,
                |_, word| matches!(word, "delete" | "rm" | "delete-resource"),
                "deletes Argo CD apps or their resources",
            ),
            "flux" => cloud(
                args,
                &values,
                2,
                false,
                |_, word| matches!(word, "delete" | "uninstall"),
                "deletes Flux objects from a cluster",
            ),
            "nomad" => nomad(args, &values),
            "skaffold" => first_word(
                args,
                &values,
                |word| word == "delete",
                "deletes what skaffold deployed",
            ),
            "tilt" => first_word(
                args,
                &values,
                |word| word == "down",
                "deletes what tilt deployed",
            ),
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
            // In PowerShell a bare `sls` is the alias of Select-String, and
            // an alias wins over any program on the path: it never runs
            // serverless. `sls.cmd`, a path and `serverless` still do.
            "serverless" | "sls" if !is_select_string_alias(unit) => first_word(
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
            "gcloud" => gcloud(args, &values),
            "gsutil" => gsutil(args),
            "az" => cloud(
                args,
                &values,
                5,
                false,
                |before, word| {
                    (before == Some("storage") && word == "remove")
                        || word == "delete"
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
                false,
                |_, word| {
                    matches!(word, "delete" | "del" | "d" | "rm") || word.starts_with("delete-")
                },
                "deletes DigitalOcean resources",
            ),
            "flyctl" | "fly" => cloud(
                args,
                &values,
                3,
                false,
                |_, word| matches!(word, "destroy" | "delete" | "rm" | "remove"),
                "destroys a Fly.io app, machine or volume",
            ),
            "vercel" => cloud(
                args,
                &values,
                3,
                false,
                |_, word| matches!(word, "remove" | "rm" | "del"),
                "removes Vercel deployments, projects or settings",
            ),
            "heroku" => cloud(
                args,
                &values,
                2,
                true,
                |_, word| {
                    word == "destroy" || word.ends_with(":destroy") || word.ends_with(":delete")
                },
                "destroys a Heroku app or add-on",
            ),
            "wrangler" => cloud(
                args,
                &values,
                4,
                false,
                |_, word| word == "delete" || word.ends_with(":delete"),
                "deletes Cloudflare resources",
            ),
            "firebase" => firebase(args, &values),
            "hcloud" => or_else(
                cloud(
                    args,
                    &values,
                    3,
                    false,
                    |_, word| word == "delete",
                    "deletes Hetzner Cloud resources",
                ),
                || {
                    cloud(
                        args,
                        &values,
                        3,
                        false,
                        |_, word| word == "rebuild",
                        "wipes a Hetzner Cloud server's disk",
                    )
                },
            ),
            "scw" => cloud(
                args,
                &values,
                4,
                false,
                |_, word| matches!(word, "delete" | "terminate"),
                "deletes Scaleway resources",
            ),
            "oci" => cloud(
                args,
                &values,
                6,
                false,
                |_, word| matches!(word, "delete" | "bulk-delete" | "terminate"),
                "deletes Oracle Cloud resources",
            ),
            "eksctl" => cloud(
                args,
                &values,
                2,
                false,
                |_, word| word == "delete",
                "deletes an EKS cluster or its parts",
            ),
            "kops" => cloud(
                args,
                &values,
                2,
                false,
                |_, word| word == "delete",
                "deletes a kops cluster or its parts",
            ),
            "sam" => first_word(
                args,
                &values,
                |word| word == "delete",
                "deletes an AWS SAM application's stack",
            ),
            "amplify" => cloud(
                args,
                &values,
                2,
                false,
                |before, word| word == "delete" || (before == Some("env") && word == "remove"),
                "deletes an Amplify project's cloud resources",
            ),
            "azd" => first_word(
                args,
                &values,
                |word| word == "down",
                "deletes the Azure resources of an azd project",
            ),
            "eb" => first_word(
                args,
                &values,
                |word| word == "terminate",
                "terminates an Elastic Beanstalk environment",
            ),
            "openstack" => cloud(
                args,
                &values,
                4,
                false,
                |_, word| matches!(word, "delete" | "purge"),
                "deletes OpenStack resources",
            ),
            "linode-cli" => cloud(
                args,
                &values,
                3,
                false,
                |_, word| matches!(word, "delete" | "rm" | "rb"),
                "deletes Linode resources",
            ),
            "exo" => cloud(
                args,
                &values,
                4,
                false,
                |_, word| matches!(word, "delete" | "del" | "rm"),
                "deletes Exoscale resources",
            ),
            "ibmcloud" => cloud(
                args,
                &values,
                4,
                false,
                |_, word| {
                    matches!(word, "delete" | "rm")
                        || word.ends_with("-delete")
                        || word.ends_with("-rm")
                        || word.starts_with("delete-")
                },
                "deletes IBM Cloud resources",
            ),
            "multipass" => first_word(
                args,
                &values,
                |word| matches!(word, "delete" | "purge"),
                "deletes virtual machines",
            ),
            "consul" => cloud(
                args,
                &values,
                3,
                false,
                |_, word| word == "delete",
                "deletes Consul data or settings",
            ),
            // Repositories and sites.
            "gh" => forge(
                args,
                &values,
                "deletes a GitHub repository, release or other object",
                "deletes what a GitHub API call names",
                "calls the GitHub API with a method only known when it runs",
            ),
            "glab" => forge(
                args,
                &values,
                "deletes a GitLab project, release or other object",
                "deletes what a GitLab API call names",
                "calls the GitLab API with a method only known when it runs",
            ),
            "netlify" => cloud(
                args,
                &values,
                1,
                true,
                |_, word| word.ends_with(":delete") || word.ends_with(":unset"),
                "deletes a Netlify site or its settings",
            ),
            "supabase" => cloud(
                args,
                &values,
                3,
                false,
                |_, word| word == "delete",
                "deletes Supabase projects or their parts",
            ),
            // Storage.
            "rclone" | "s3cmd" | "mc"
                if rehearsed(args, &values, (read_as != "mc").then_some("-n")) =>
            {
                Safe
            }
            "rclone" => first_word(
                args,
                &values,
                |word| matches!(word, "purge" | "delete" | "deletefile" | "cleanup"),
                "deletes files in a remote store",
            ),
            "s3cmd" => first_word(
                args,
                &values,
                |word| matches!(word, "rb" | "del" | "rm"),
                "deletes S3 buckets or objects",
            ),
            "mc" => first_word(
                args,
                &values,
                |word| matches!(word, "rb" | "rm"),
                "deletes buckets or objects in an object store",
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

/// Whether the unit is PowerShell's `sls`, written bare (any case, no
/// extension, no path): the alias of `Select-String`.
fn is_select_string_alias(unit: &Unit) -> bool {
    unit.shell == Shell::PowerShell
        && unit
            .program
            .known()
            .is_some_and(|program| program.eq_ignore_ascii_case("sls"))
}

/// The article before a program's name: `an aws command`, `a docker command`.
/// Programs read as letters (`sst`) count by the sound of the first one.
fn article(program: &str) -> &'static str {
    if program.starts_with(['a', 'e', 'i', 'o', 'u'])
        || matches!(program, "sst" | "sls" | "scw" | "s3cmd" | "mc" | "mcli")
    {
        "an"
    } else {
        "a"
    }
}

/// The program a front end, a build of another name or a second copy of a
/// program is read as: each takes the same commands as the program it
/// stands for. `kubecolor` colours kubectl's output, `microk8s.kubectl` is
/// the kubectl a snap installs (and `microk8s.helm` and `microk8s.helm3` its
/// helm), `helm3` a second helm; `podman-remote`, `finch` (a nerdctl in a
/// virtual machine) and `nerdctl.lima` take the commands of docker's own
/// line. `mcli` is the `MinIO` client where `mc` is Midnight Commander.
fn read_as(key: &str) -> &str {
    match key {
        "kubecolor" | "microk8s.kubectl" => "kubectl",
        "helm3" | "microk8s.helm" | "microk8s.helm3" => "helm",
        "mcli" => "mc",
        "podman-remote" => "podman",
        "finch" | "nerdctl.lima" => "nerdctl",
        _ => key,
    }
}

/// The options a program (and the programs it runs) take a value for, which
/// are the words a rehearsal or help flag can be the value of. A wrapper
/// reads the lists of what it wraps too: reading one word too many as a value
/// only makes a line riskier.
fn values_of(key: &str) -> Vec<&'static str> {
    let list: &[&[&'static str]] = match key {
        "docker" | "podman" | "nerdctl" => &[ENGINE_VALUES, COMPOSE_VALUES, RM_VALUES, RMI_VALUES],
        "docker-compose" | "podman-compose" => &[COMPOSE_VALUES],
        "docker-machine" => &[DOCKER_MACHINE_VALUES],
        "colima" => &[COLIMA_VALUES],
        "kubectl" | "oc" | "k3s" => &[KUBECTL_VALUES],
        "k0s" => &[K0S_VALUES, KUBECTL_VALUES],
        "microk8s" => &[SMALL_CLUSTER_VALUES, KUBECTL_VALUES, HELM_VALUES],
        "minikube" => &[MINIKUBE_VALUES, KUBECTL_VALUES],
        "helm" => &[HELM_VALUES],
        "helmfile" => &[HELMFILE_VALUES],
        "argocd" => &[ARGOCD_VALUES],
        "flux" => &[FLUX_VALUES],
        "nomad" => &[NOMAD_VALUES],
        "skaffold" => &[SKAFFOLD_VALUES],
        "tilt" => &[TILT_VALUES],
        "gh" | "glab" => &[GH_VALUES],
        "netlify" => &[NETLIFY_VALUES],
        "supabase" => &[SUPABASE_VALUES],
        "openstack" => &[OPENSTACK_VALUES],
        "linode-cli" => &[LINODE_VALUES],
        "exo" => &[EXO_VALUES],
        "azd" => &[AZD_VALUES],
        "eb" => &[EB_VALUES],
        "consul" => &[CONSUL_VALUES],
        "rclone" => &[RCLONE_VALUES],
        "s3cmd" => &[S3CMD_VALUES],
        "mc" => &[MC_VALUES],
        "kind" | "k3d" => &[SMALL_CLUSTER_VALUES],
        "terragrunt" => &[TERRAGRUNT_VALUES],
        "pulumi" => &[PULUMI_VALUES],
        "cdk" => &[CDK_VALUES],
        "cdktf" => &[CDKTF_VALUES],
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
// missed would be read as the command, so a missing one is a false safe: each
// list holds the global options the program has that take one, as far as its
// help, manual and docs show them, and a new one is added when it turns up.

/// Options of docker, podman and nerdctl that take a value.
pub(super) const ENGINE_VALUES: &[&str] = &[
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
    "--cdi-spec-dir",
    "--bridge-ip",
    "--out",
    "--ssh",
    "--tls-ca",
    "--tls-cert",
    "--tls-key",
    "--tls-details",
    "--network-cmd-path",
    "--volumepath",
    "--db-backend",
    "--host-gateway-ip",
    "--registries-conf",
    "--signature-policy",
    "--global-dns",
    "--global-dns-opts",
    "--global-dns-search",
];

/// Options of `docker compose` that take a value.
pub(super) const COMPOSE_VALUES: &[&str] = &[
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
    "--podman-pull-args",
    "--podman-push-args",
    "--podman-build-args",
    "--podman-inspect-args",
    "--podman-run-args",
    "--podman-start-args",
    "--podman-stop-args",
    "--podman-rm-args",
    "--podman-volume-args",
    "--podman-path",
    "--in-pod",
    "--pod-args",
    "--context",
    "-H",
    "--host",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
];

/// Options of `docker rm` and `podman rm` that take a value.
const RM_VALUES: &[&str] = &["-t", "--time", "--cidfile", "--filter"];

/// Options of kubectl and oc that take a value, global ones and those of the
/// commands that matter here (`delete`, `drain`, `scale`, `apply`).
pub(super) const KUBECTL_VALUES: &[&str] = &[
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
    "--as-user-extra",
    "--kuberc",
    "--proxy-url",
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
    "--log-file",
    "--log-dir",
    "--log-file-max-size",
    "--log-backtrace-at",
    "--stderrthreshold",
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
    "--color",
    "--colour",
    "--content-cache",
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
    "-b",
    "--bootstrapper",
    "--user",
    "--log_backtrace_at",
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
    "--tracing-header",
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
    "--telemetry-file",
    "--unstable",
];

/// Options of cdktf that take a value, global and those of the commands that
/// destroy or deploy.
const CDKTF_VALUES: &[&str] = &[
    "--log-level",
    "-a",
    "--app",
    "-o",
    "--output",
    "--parallelism",
    "--outputs-file",
    "--var",
    "--var-file",
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

/// Options of gcloud that take a value, global and common to its commands,
/// and those of the everyday commands that name a thing.
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
    "--tag",
    "--key-file",
    "--secret",
    "--member",
    "--role",
    "--cluster",
    "--location",
    "--source",
    "--config",
    "--timeout",
    "--substitutions",
    "--service-account",
    "--network",
    "--machine-type",
    "--image",
    "--metadata",
    "--labels",
    "--description",
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
    "--project",
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
    "-bn",
    "--bucket-name",
    "-ns",
    "--namespace-name",
    "--compartment-id",
    "--cluster-id",
    "--instance-id",
    "--display-name",
    "--from-json",
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

/// Options of `docker rmi` and `podman rmi` that take a value.
const RMI_VALUES: &[&str] = &["--platform"];

/// Options of docker-machine that take a value.
const DOCKER_MACHINE_VALUES: &[&str] = &[
    "-s",
    "--storage-path",
    "--tls-ca-cert",
    "--tls-ca-key",
    "--tls-client-cert",
    "--tls-client-key",
    "--github-api-token",
    "--bugsnag-api-token",
];

/// Options of colima that take a value.
const COLIMA_VALUES: &[&str] = &["-p", "--profile"];

/// Options of k0s that take a value, before the kubectl it runs.
const K0S_VALUES: &[&str] = &[
    "-c",
    "--config",
    "--data-dir",
    "--debugListenOn",
    "--status-socket",
];

/// Options of helmfile that take a value.
const HELMFILE_VALUES: &[&str] = &[
    "-f",
    "--file",
    "-e",
    "--environment",
    "--state-values-set",
    "--state-values-set-string",
    "--state-values-file",
    "-l",
    "--selector",
    "-n",
    "--namespace",
    "--kube-context",
    "--kubeconfig",
    "-b",
    "--helm-binary",
    "-k",
    "--kustomize-binary",
    "--log-level",
    "-c",
    "--chart",
    "--args",
];

/// Options of argocd that take a value.
const ARGOCD_VALUES: &[&str] = &[
    "--server",
    "--auth-token",
    "--config",
    "--argocd-context",
    "--grpc-web-root-path",
    "-H",
    "--header",
    "--logformat",
    "--loglevel",
    "--port-forward-namespace",
    "--client-crt",
    "--client-crt-key",
    "--server-crt",
    "--kube-context",
    "--server-name",
    "--repo-server-name",
    "--redis-name",
    "--redis-haproxy-name",
    "--controller-name",
    "--http-retry-max",
];

/// Options of flux that take a value. Its `-s` is `delete --silent`, never a
/// server, so kubectl's list is not used.
const FLUX_VALUES: &[&str] = &[
    "--context",
    "--kubeconfig",
    "-n",
    "--namespace",
    "--timeout",
    "--as",
    "--as-group",
    "--as-uid",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--server",
    "--tls-server-name",
    "--token",
    "--user",
    "--kube-api-burst",
    "--kube-api-qps",
];

/// Options of nomad that take a value (Go flags, written after the command).
const NOMAD_VALUES: &[&str] = &[
    "-address",
    "-region",
    "-namespace",
    "-token",
    "-ca-cert",
    "-ca-path",
    "-client-cert",
    "-client-key",
    "-tls-server-name",
];

/// Options of skaffold that take a value.
const SKAFFOLD_VALUES: &[&str] = &["-v", "--verbosity", "--color"];

/// Options of tilt that take a value.
const TILT_VALUES: &[&str] = &["--klog"];

/// Options of gh and glab that take a value.
const GH_VALUES: &[&str] = &["-R", "--repo"];

/// Options of `gh api` and `glab api` that take a value.
const GH_API_VALUES: &[&str] = &[
    "-X",
    "--method",
    "-H",
    "--header",
    "-f",
    "--raw-field",
    "-F",
    "--field",
    "-q",
    "--jq",
    "-t",
    "--template",
    "--input",
    "--hostname",
    "-p",
    "--preview",
    "--cache",
];

/// Options of netlify that take a value.
const NETLIFY_VALUES: &[&str] = &["--auth", "--filter"];

/// Options of supabase that take a value.
const SUPABASE_VALUES: &[&str] = &[
    "--workdir",
    "--profile",
    "-o",
    "--output",
    "--network-id",
    "--dns-resolver",
    "--project-ref",
];

/// Options of openstack that take a value.
const OPENSTACK_VALUES: &[&str] = &[
    "--os-cloud",
    "--os-region-name",
    "--os-auth-url",
    "--os-auth-type",
    "--os-project-name",
    "--os-project-id",
    "--os-project-domain-name",
    "--os-project-domain-id",
    "--os-username",
    "--os-user-id",
    "--os-password",
    "--os-user-domain-name",
    "--os-user-domain-id",
    "--os-domain-name",
    "--os-domain-id",
    "--os-default-domain",
    "--os-token",
    "--os-trust-id",
    "--os-system-scope",
    "--os-interface",
    "--os-identity-api-version",
    "--os-endpoint",
    "--os-cacert",
    "--os-cert",
    "--os-key",
    "--log-file",
];

/// Options of linode-cli that take a value.
const LINODE_VALUES: &[&str] = &[
    "--as-user",
    "--format",
    "--delimiter",
    "--page",
    "--page-size",
    "--column-width",
    "--max-column-width",
];

/// Options of exo that take a value.
const EXO_VALUES: &[&str] = &[
    "-C",
    "--config",
    "-z",
    "--zone",
    "-A",
    "--use-account",
    "-O",
    "--output-format",
    "--output-template",
];

/// Options of azd that take a value.
const AZD_VALUES: &[&str] = &["-C", "--cwd", "-e", "--environment"];

/// Options of the Elastic Beanstalk CLI that take a value.
const EB_VALUES: &[&str] = &["--profile", "-r", "--region", "--endpoint-url"];

/// Options of consul that take a value (Go flags, written after the command).
const CONSUL_VALUES: &[&str] = &[
    "-http-addr",
    "-token",
    "-token-file",
    "-datacenter",
    "-namespace",
    "-partition",
    "-ca-file",
    "-ca-path",
    "-client-cert",
    "-client-key",
    "-tls-server-name",
];

/// Options of rclone that take a value, global ones and the common filters.
const RCLONE_VALUES: &[&str] = &[
    "--config",
    "--log-file",
    "--log-level",
    "--cache-dir",
    "--temp-dir",
    "--transfers",
    "--checkers",
    "--bwlimit",
    "--tpslimit",
    "--retries",
    "--low-level-retries",
    "--timeout",
    "--contimeout",
    "--user-agent",
    "--stats",
    "--exclude",
    "--exclude-from",
    "--include",
    "--include-from",
    "--filter",
    "--filter-from",
    "--files-from",
    "--min-age",
    "--max-age",
    "--min-size",
    "--max-size",
    "--max-depth",
    "--max-transfer",
    "--backup-dir",
    "--suffix",
];

/// Options of s3cmd that take a value.
const S3CMD_VALUES: &[&str] = &[
    "-c",
    "--config",
    "--access_key",
    "--secret_key",
    "--access_token",
    "--host",
    "--host-bucket",
    "--region",
    "--bucket-location",
];

/// Options of `mc`, the client of the `MinIO` object store, that take a value.
const MC_VALUES: &[&str] = &[
    "-C",
    "--config-dir",
    "--limit-upload",
    "--limit-download",
    "-H",
    "--custom-header",
    "--resolve",
    "--conn-read-deadline",
    "--conn-write-deadline",
];

/// Whether an argument is an option: it starts with `-` and is more than
/// that. Read from what is written, so `--namespace=$NS` is one too.
fn is_option(arg: &Arg) -> bool {
    let text = written(arg);
    text.len() > 1 && text.starts_with('-')
}

/// The first word that is not an option, with what follows it. An option
/// listed in `values` takes the next word as its value; `--` ends options.
pub(super) fn command<'a>(args: &'a [Arg], values: &[&str]) -> Option<(&'a Arg, &'a [Arg])> {
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
///
/// A quoted variable that a loop sets (a `for` or `read` in a POSIX shell, a
/// `foreach` or the `$_` of a pipeline in PowerShell) holds one item of what
/// the loop walks, so it names every one of them and counts as computed.
///
/// The same goes for anything that holds an expansion in a command that
/// `repeated` says runs in a loop or a function body, in any shell: the
/// variable need not be the loop's own (`id="$c"`, `name=$(…)`, `shift`,
/// `%%i`), since the body runs again with other values.
fn computed(arg: &Arg, unit: &Unit, split: &Split) -> bool {
    let shell = unit.shell;
    match arg {
        // The quotes are gone from a known word: a brace list in it was
        // written bare or quoted, and bare is the likelier.
        Arg::Known(text) => shell == Shell::Posix && brace_words(text),
        Arg::Input => true,
        // The null value is no word, and holds no list.
        Arg::Null => false,
        Arg::Unknown(_) | Arg::Template { .. } if unit.repeated => true,
        Arg::Unknown(_) | Arg::Template { .. } => {
            let text = arg.text();
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
                            || names_variable(text, |name| split.looped(name))
                    }
                    Shell::PowerShell => {
                        (text.starts_with('"')
                            && names_variable(text, |name| {
                                split.looped(name)
                                    || name == "_"
                                    || name.eq_ignore_ascii_case("psitem")
                            }))
                            || text.starts_with('(')
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

/// Whether `text` reads a variable (`$name`, `${name}`, `${name:-x}`) that
/// `is` accepts by name.
fn names_variable(text: &str, is: impl Fn(&str) -> bool) -> bool {
    text.split('$').skip(1).any(|rest| {
        let rest = rest.strip_prefix('{').unwrap_or(rest);
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        rest.get(..end)
            .is_some_and(|name| !name.is_empty() && is(name))
    })
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

/// Whether an object-store line only rehearses: `--dry-run` (or `short`,
/// its one-letter name, as rclone's and s3cmd's `-n`) is the last one
/// written, and turned on.
fn rehearsed(args: &[Arg], values: &[&str], short: Option<&str>) -> bool {
    flags(args, values)
        .into_iter()
        .filter_map(|arg| match (arg.known(), short) {
            (Some(text), Some(short)) if text == short => Some(Given::On),
            _ => given(arg, "dry-run"),
        })
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
/// compute instances delete vm`); `hit` is given the word before it. With
/// `colon`, a `topic:command` word (`heroku config:set`) is a whole command,
/// so the words after it are operands. A verb that makes or sets something
/// (see [`makes`]) takes names after it, never a verb: `argocd app create
/// delete` makes an app named `delete`.
fn cloud<'a>(
    args: &'a [Arg],
    values: &[&str],
    depth: usize,
    colon: bool,
    hit: fn(Option<&str>, &str) -> bool,
    reason: &'static str,
) -> Say<'a> {
    let words = words(args, values);
    let mut before = None;
    let mut unread = false;
    let mut leaf = false;
    let mut made = false;
    for (at, word) in words.iter().take(depth).enumerate() {
        match word.known() {
            Some(text) => {
                if !made && hit(before, text) {
                    return Destroys(reason, words.get(at + 1).copied());
                }
                made = made || makes(text);
                // A verb that does not delete takes operands, not another
                // verb: `describe $vm` names a machine.
                leaf = leaf || leaf_verb(text) || (colon && text.contains(':'));
            }
            // `FOO=$BAR` after `config:set` is an assignment, never a verb.
            None => unread = unread || !(leaf || assignment(written(word))),
        }
        before = word.known();
    }
    if unread {
        Unread(None)
    } else {
        Safe
    }
}

/// Verbs of the cloud CLIs that read, create, copy or change one thing and
/// take operands after them: a word that is only known when it runs behind
/// one is an operand, not the verb that might delete. A word that is a group
/// in a CLI that reads it (`gcloud run`, `gcloud projects`) is not one: the
/// word after it is a verb.
const LEAF_VERBS: &[&str] = &[
    "list",
    "ls",
    "describe",
    "get",
    "show",
    "create",
    "add",
    "set",
    "update",
    "read",
    "logs",
    "status",
    "info",
    "inspect",
    "start",
    "stop",
    "restart",
    "reboot",
    "resize",
    "ssh",
    "scp",
    "deploy",
    "login",
    "whoami",
    "version",
    "put",
    "submit",
    "access",
    "use",
    "link",
    "cp",
    "mv",
    "rsync",
    "upload",
    "download",
    "upload-batch",
    "download-batch",
    "publish",
    "connect",
    "activate",
    "build",
    "pull",
    "promote",
    "redeploy",
    "tail",
    "dev",
    "execute",
    "authenticate",
    "invoke",
];

/// Whether a known word is a verb that reads, creates or changes one thing:
/// one of [`LEAF_VERBS`], or a longer name for one (`get-credentials`,
/// `add-metadata`, `create-kubeconfig`, `update-labels`, `set-iam-policy`,
/// `list-tags`).
fn leaf_verb(text: &str) -> bool {
    LEAF_VERBS.contains(&text)
        || ["get-", "add-", "create-", "update-", "set-", "list-"]
            .iter()
            .any(|prefix| text.starts_with(prefix))
}

/// Whether a known word is a verb that makes, writes or sets one thing, which
/// no CLI here uses as a group: `create`, `new`, `put`, `set`, and a longer
/// name for creating (`service-instance-create`, `bucket-create`,
/// `create-key`). What follows it is a name, even one that reads like a
/// delete verb.
fn makes(text: &str) -> bool {
    matches!(text, "create" | "new" | "put" | "set")
        || text.ends_with("-create")
        || text.starts_with("create-")
}

/// Whether a word is an assignment (`FOO=$BAR`, `web=2`): a name, then `=`.
fn assignment(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| {
        name.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

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

/// The last `--replicas` the line gives, read from the arguments that are not
/// another option's value (`--cache-dir --replicas=0` is a directory) and
/// before `--`.
fn replicas(args: &[Arg]) -> Replicas {
    let mut found = Replicas::Other;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        let text = written(arg);
        if arg.known() == Some("--") {
            break;
        }
        if text == "--replicas" {
            found = count(args.get(at));
            at += 1;
        } else if let Some(value) = text.strip_prefix("--replicas=") {
            found = match arg {
                Arg::Known(_) => count(Some(&Arg::Known(value.to_string()))),
                _ => Replicas::Unread,
            };
        } else if arg
            .known()
            .is_some_and(|known| KUBECTL_VALUES.contains(&known))
        {
            at += 1;
        }
    }
    found
}

/// What is written for an argument, expansions as they stand.
fn written(arg: &Arg) -> &str {
    match arg {
        Arg::Known(text) | Arg::Unknown(text) | Arg::Template { text, .. } => text,
        Arg::Input => "",
        Arg::Null => "$null",
    }
}

fn count(value: Option<&Arg>) -> Replicas {
    match value {
        Some(arg) => match arg.known() {
            Some(text) => number(text.trim()),
            None => Replicas::Unread,
        },
        None => Replicas::Other,
    }
}

/// What a replica count written out says. kubectl reads it as Go's
/// `strconv.ParseInt` with base 0 does: a sign, then `0x`, `0o` or `0b`, or
/// a leading `0` for octal, with `_` between digits (`0x0`, `0b0`, `0o0`,
/// `0_0` and `00` are all zero). A plain decimal is read as it is; any other
/// value is one the guard does not read, which is not a count it can call
/// safe.
fn number(text: &str) -> Replicas {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return if digits.bytes().all(|byte| byte == b'0') {
            Replicas::Zero
        } else {
            Replicas::Other
        };
    }
    if zero_in_base_zero(digits) {
        Replicas::Zero
    } else {
        Replicas::Unread
    }
}

/// Whether `digits` (no sign) is a zero that `ParseInt(…, 0, …)` takes: a
/// prefix, then only zeros and underscores, each underscore after a digit or
/// the prefix and none last (Go's `underscoreOK`).
fn zero_in_base_zero(digits: &str) -> bool {
    let bytes = digits.as_bytes();
    let (body, mut after_digit) = match bytes {
        // Go reads a prefix only when a digit may follow it: `0x` is `0`
        // then a stray `x`.
        [b'0', prefix, rest @ ..]
            if !rest.is_empty() && matches!(prefix.to_ascii_lowercase(), b'b' | b'o' | b'x') =>
        {
            (rest, true)
        }
        [b'0', ..] => (bytes, false),
        _ => return false,
    };
    let mut underscore_last = false;
    for &byte in body {
        match byte {
            b'0' => {
                after_digit = true;
                underscore_last = false;
            }
            b'_' if after_digit && !underscore_last => underscore_last = true,
            _ => return false,
        }
    }
    after_digit && !underscore_last
}

fn engine<'a>(args: &'a [Arg], unit: &Unit, split: &Split) -> Say<'a> {
    let Some((cmd, rest)) = command(args, ENGINE_VALUES) else {
        return Safe;
    };
    let Some(name) = cmd.known() else {
        return Unread(None);
    };
    match name {
        "rm" => return remove_containers(rest, unit, split),
        "rmi" => return remove_images(rest, unit, split),
        "compose" => return compose(rest),
        "system" | "volume" | "container" | "image" | "network" | "stack" | "service" | "pod"
        | "machine" | "kube" | "play" | "secret" | "config" | "node" | "swarm" => {}
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
        ("container", "rm" | "remove") => remove_containers(after, unit, split),
        ("container", "prune") => Destroys("deletes every stopped container", target),
        ("image", "rm" | "remove") => remove_images(after, unit, split),
        ("image", "prune") if has_flag(after, Some('a'), Some("all")) => {
            Destroys("deletes every unused image", target)
        }
        ("network", "prune") => Destroys("deletes unused networks", target),
        ("stack" | "service", "rm" | "remove") => Destroys("removes swarm services", target),
        ("secret", "rm" | "remove") => Destroys("deletes swarm secrets", target),
        ("config", "rm" | "remove") => Destroys("deletes swarm configs", target),
        ("node", "rm" | "remove") => Destroys("removes nodes from a swarm", target),
        ("swarm", "leave") if has_flag(after, Some('f'), None) || turned_on(after, "force") => {
            Destroys("leaves a swarm, even as its last manager", target)
        }
        ("pod", "rm") => remove_containers(after, unit, split),
        ("pod", "prune") => Destroys("deletes every stopped pod", target),
        ("machine", "rm") => Destroys("deletes a virtual machine and its containers", target),
        ("machine", "reset") => {
            Destroys("deletes every virtual machine and its containers", target)
        }
        ("kube", "down") => Destroys("removes the pods a file created", target),
        // `play kube` is podman's older name for `kube play`.
        ("kube", "play") | ("play", "kube") if has_flag(after, None, Some("down")) => {
            Destroys("removes the pods a file created", target)
        }
        _ => Safe,
    }
}

/// Whether a line is run by `find -exec`, whose `{}` stands for every name
/// the search finds: the line acts on several at once.
fn run_by_find(unit: &Unit) -> bool {
    unit.wrappers.iter().any(|wrapper| wrapper == "find")
}

/// Whether an operand names several containers or images: one only known
/// when it runs that the shell splits (see [`computed`]), or a wildcard the
/// shell expands to every name it matches (`docker rm -f *`): a POSIX shell
/// does, and so does PowerShell on Linux and macOS for a program it runs.
/// cmd never does; the program is handed the pattern as it is.
fn several(arg: &Arg, unit: &Unit, split: &Split) -> bool {
    computed(arg, unit, split)
        || (unit.shell != Shell::Cmd && arg.known().is_some_and(glob::has_wildcard))
}

/// `docker rm`: one named container is safe, even forced. Several forced at
/// once, a choice made when the line runs (a wildcard, what `find` finds),
/// every container, and a container's volumes are not.
fn remove_containers<'a>(args: &'a [Arg], unit: &Unit, split: &Split) -> Say<'a> {
    let operands = words(args, RM_VALUES);
    let target = operands.first().copied();
    if has_flag(args, Some('a'), Some("all")) {
        return Destroys("removes every container", target);
    }
    if has_flag(args, None, Some("filter")) {
        return Destroys("removes the containers a filter picks", target);
    }
    if run_by_find(unit) && !operands.is_empty() {
        return Destroys("removes every container a search finds", target);
    }
    if operands.iter().any(|arg| several(arg, unit, split)) {
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

/// `docker rmi` and `image rm`: an image is pulled or built again, so one
/// named, or a few, is safe. Every image, those a choice made when the line
/// runs names (`$(docker images -aq)`, a wildcard, what `find` finds), and
/// several forced at once are not.
fn remove_images<'a>(args: &'a [Arg], unit: &Unit, split: &Split) -> Say<'a> {
    let operands = words(args, RMI_VALUES);
    let target = operands.first().copied();
    if has_flag(args, Some('a'), Some("all")) {
        return Destroys("removes every image", target);
    }
    if (run_by_find(unit) && !operands.is_empty())
        || operands.iter().any(|arg| several(arg, unit, split))
    {
        return Destroys("removes images chosen when it runs", target);
    }
    if operands.len() > 1 && has_flag(args, Some('f'), Some("force")) {
        return Destroys("force-removes several images", target);
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
    let Some(mut name) = cmd.known() else {
        return Unread(None);
    };
    let mut rest = rest;
    // OpenShift's `oc adm`: its `drain` is kubectl's, and `prune` deletes
    // old images, builds or deployments once `--confirm` is given (without
    // it, the command only lists them).
    if name == "adm" {
        let Some((sub, after)) = command(rest, KUBECTL_VALUES) else {
            return Safe;
        };
        match sub.known() {
            Some("drain") => {}
            Some("prune") if turned_on(after, "confirm") => {
                return Destroys(
                    "deletes old images, builds or deployments",
                    words(after, KUBECTL_VALUES).first().copied(),
                )
            }
            Some(_) => return Safe,
            None => return Unread(None),
        }
        name = "drain";
        rest = after;
    }
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

/// `microk8s kubectl …`, `microk8s helm …` (and `helm3`), and its own
/// `reset`.
fn microk8s(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, SMALL_CLUSTER_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("kubectl") => kubectl(rest),
        Some("helm" | "helm3") => helm(rest),
        Some("reset") => Destroys("deletes every workload of a MicroK8s cluster", None),
        Some(_) => Safe,
        None => Unread(None),
    }
}

/// `k3s kubectl …` and `k0s kubectl …` (or `k0s kc …`): `names` are the
/// program's names for its kubectl.
fn k3s<'a>(args: &'a [Arg], values: &[&str], names: &[&str]) -> Say<'a> {
    let Some((cmd, rest)) = command(args, values) else {
        return Safe;
    };
    match cmd.known() {
        Some(name) if names.contains(&name) => kubectl(rest),
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
        Some("node") => sub(
            rest,
            MINIKUBE_VALUES,
            &["delete"],
            "deletes a node of a local Kubernetes cluster",
        ),
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
    match command(args, &[]) {
        Some((cmd, rest)) => terraform_command(cmd, rest),
        None => Safe,
    }
}

/// A terraform command, `cmd`, with the arguments after it.
fn terraform_command<'a>(cmd: &Arg, rest: &'a [Arg]) -> Say<'a> {
    match cmd.known() {
        Some("destroy") => Destroys(TERRAFORM_DESTROYS, None),
        Some("apply") if turned_on(rest, "destroy") => Destroys(TERRAFORM_DESTROYS, None),
        // What leaves the state is no longer managed, and a workspace's
        // state is gone with it.
        Some("state") if !rehearsal(rest, &[], "dry-run") => sub(
            rest,
            &[],
            &["rm"],
            "removes resources from the Terraform state",
        ),
        Some("workspace") => sub(rest, &[], &["delete"], "deletes a Terraform workspace"),
        Some(_) => Safe,
        None => Unread(None),
    }
}

/// A command whose next word says what it does (`terraform state rm`): one
/// of `names` destroys what follows it, another known word is safe, and a
/// word only known when it runs may be any of them.
fn sub<'a>(rest: &'a [Arg], values: &[&str], names: &[&str], reason: &'static str) -> Say<'a> {
    let what = words(rest, values);
    match what.first().map(|word| word.known()) {
        Some(Some(text)) if names.contains(&text) => Destroys(reason, what.get(1).copied()),
        Some(None) => Unread(None),
        _ => Safe,
    }
}

/// The first answer, unless it is safe: then the second.
fn or_else<'a>(said: Say<'a>, next: impl FnOnce() -> Say<'a>) -> Say<'a> {
    match said {
        Safe => next(),
        said => said,
    }
}

/// terragrunt: terraform's commands, also run over every module (`run-all
/// destroy`, `run --all -- state rm x`, the old `destroy-all`). `run-all`,
/// `run` and `exec` come before the command, which is read like terraform
/// reads it: terragrunt's own word, or else the first word after a `--`,
/// which is handed to terraform (or to the program `exec` runs). A
/// `-destroy` given to terragrunt counts for the `apply` it runs.
fn terragrunt(args: &[Arg]) -> Say<'_> {
    let (own, passed) = match walk(args, TERRAGRUNT_VALUES).1 {
        Some(at) => (
            args.get(..at).unwrap_or_default(),
            args.get(at + 1..).unwrap_or_default(),
        ),
        None => (args, &[][..]),
    };
    let destroy = turned_on(args, "destroy");
    let mut rest = own;
    while let Some((word, after)) = command(rest, TERRAGRUNT_VALUES) {
        match word.known() {
            None => return Unread(None),
            Some("run-all" | "run" | "hcl" | "exec") => rest = after,
            Some(_) => return terragrunt_command(word, after, destroy),
        }
    }
    match command(passed, &[]) {
        Some((word, after)) => terragrunt_command(word, after, destroy),
        None => Safe,
    }
}

/// The command terragrunt runs, `word`, with the arguments after it.
fn terragrunt_command<'a>(word: &Arg, after: &'a [Arg], destroy: bool) -> Say<'a> {
    match word.known() {
        Some("destroy-all") => Destroys(TERRAFORM_DESTROYS, None),
        Some("apply") if destroy => Destroys(TERRAFORM_DESTROYS, None),
        // `exec -- terraform destroy`.
        Some("terraform" | "tofu") => terraform(after),
        _ => terraform_command(word, after),
    }
}

fn pulumi(args: &[Arg]) -> Say<'_> {
    let Some((cmd, rest)) = command(args, PULUMI_VALUES) else {
        return Safe;
    };
    match cmd.known() {
        Some("destroy" | "down" | "dn") if !rehearsal(rest, PULUMI_VALUES, "preview-only") => {
            Destroys("destroys the resources of a Pulumi stack", None)
        }
        Some("state") => sub(
            rest,
            PULUMI_VALUES,
            &["delete"],
            "removes resources from a Pulumi stack's state",
        ),
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
                    "delete"
                        | "schedule-key-deletion"
                        | "deregister-image"
                        | "close-account"
                        | "release-address"
                        | "release-hosts"
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

/// `gcloud`: a delete or destroy verb, `storage rm`, and `storage rsync`
/// with `--delete-unmatched-destination-objects`, which deletes what the
/// source does not have like `gsutil rsync -d`.
fn gcloud<'a>(args: &'a [Arg], values: &[&str]) -> Say<'a> {
    let said = cloud(
        args,
        values,
        6,
        false,
        |before, word| {
            matches!(word, "delete" | "destroy" | "bulk-delete")
                || word.starts_with("delete-")
                || (before == Some("storage") && word == "rm")
        },
        "deletes Google Cloud resources",
    );
    if !matches!(said, Safe) {
        return said;
    }
    let words = words(args, values);
    let storage_rsync = words.first().is_some_and(|w| w.known() == Some("storage"))
        && words.get(1).is_some_and(|w| w.known() == Some("rsync"));
    if storage_rsync && has_flag(args, None, Some("delete-unmatched-destination-objects")) {
        return Destroys(
            "deletes the objects the source does not have",
            words.get(2).copied(),
        );
    }
    said
}

/// `firebase`: a `…:delete`, `…:remove` or `…:uninstall` command;
/// `database:set`, which replaces what is at a path (`/` is the whole
/// database); and `hosting:disable`, which takes a site offline.
fn firebase<'a>(args: &'a [Arg], values: &[&str]) -> Say<'a> {
    or_else(
        cloud(
            args,
            values,
            1,
            true,
            |_, word| {
                word.ends_with(":delete")
                    || word.ends_with(":remove")
                    || word.ends_with(":uninstall")
            },
            "deletes Firebase resources",
        ),
        || {
            let words = words(args, values);
            match words.first().and_then(|word| word.known()) {
                Some("database:set") => Destroys(
                    "replaces data in a Firebase database",
                    words.get(1).copied(),
                ),
                Some("hosting:disable") => Destroys("takes a Firebase site offline", None),
                _ => Safe,
            }
        },
    )
}

/// `nomad`: a `delete` or `purge` among the first words, and a job stopped
/// with `-purge` (`nomad job stop -purge web`, or the older `nomad stop`),
/// which deletes it from the cluster.
fn nomad<'a>(args: &'a [Arg], values: &[&str]) -> Say<'a> {
    or_else(
        cloud(
            args,
            values,
            3,
            false,
            |_, word| matches!(word, "delete" | "purge"),
            "deletes Nomad objects",
        ),
        || {
            let words = words(args, values);
            let at = usize::from(words.first().and_then(|word| word.known()) == Some("job"));
            if words.get(at).and_then(|word| word.known()) == Some("stop")
                && turned_on(args, "purge")
            {
                Destroys(
                    "stops a Nomad job and deletes it",
                    words.get(at + 1).copied(),
                )
            } else {
                Safe
            }
        },
    )
}

/// `gh` and `glab`: a `delete` or `delete-*` after a group (`repo delete`,
/// `release delete-asset`), and an `api` call whose method is `DELETE`. An
/// alias is the CLI's own setting, so `alias delete` is safe.
fn forge<'a>(
    args: &'a [Arg],
    values: &[&str],
    deletes: &'static str,
    api_deletes: &'static str,
    api_unread: &'static str,
) -> Say<'a> {
    let Some((group, rest)) = command(args, values) else {
        return Safe;
    };
    match group.known() {
        Some("alias") => Safe,
        Some("api") => api(rest, api_deletes, api_unread),
        _ => cloud(
            args,
            values,
            2,
            false,
            |_, word| word == "delete" || word.starts_with("delete-"),
            deletes,
        ),
    }
}

/// `gh api` and `glab api`: the method is the last `-X` or `--method`
/// given (`-X DELETE`, `--method=delete`, `-XDELETE`), in any case. One only
/// known when it runs may be `DELETE`.
fn api<'a>(args: &'a [Arg], deletes: &'static str, unread: &'static str) -> Say<'a> {
    let mut method = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        let text = written(arg);
        if arg.known() == Some("--") {
            break;
        }
        if matches!(arg.known(), Some("-X" | "--method")) {
            method = args.get(at).map(|value| value.known());
            at += 1;
        } else if let Some(value) = text
            .strip_prefix("--method=")
            .or_else(|| text.strip_prefix("-X"))
        {
            method = Some(arg.known().map(|_| value));
        } else if arg
            .known()
            .is_some_and(|known| GH_API_VALUES.contains(&known))
        {
            at += 1;
        }
    }
    let target = words(args, GH_API_VALUES).first().copied();
    match method {
        Some(Some(method)) if method.eq_ignore_ascii_case("delete") => Destroys(deletes, target),
        Some(None) => Unread(Some(unread)),
        _ => Safe,
    }
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
