//! What a fourth review of `destroy_resources` found: global options that
//! take a value and were not listed (so the value was read as the command),
//! everyday cloud lines read as unknown because of an option or a verb the
//! tables did not know, and delete verbs that three tables read narrower
//! than their siblings.

mod common;

use common::{check, posix};
use milo_guards_shell::{Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

fn rows(safe: &[&str], risky: &[(&str, Rule)]) {
    check(Shell::Posix, &posix(), safe, risky);
}

#[test]
fn a_global_option_that_takes_a_value_is_skipped_to_find_the_command() {
    rows(
        &[
            "kubectl --proxy-url http://p:3128 get pods",
            "podman --ssh native ps",
            "helm --color always list",
        ],
        &[
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
        ],
    );
}

#[test]
fn everyday_cloud_lines_with_a_computed_operand_are_safe() {
    rows(
        &[
            "gcloud container clusters get-credentials $C --zone z",
            "gcloud builds submit --tag \"gcr.io/$P/app\"",
            "gcloud auth activate-service-account --key-file $F",
            "gcloud secrets versions access latest --secret $S",
            "gcloud projects add-iam-policy-binding $P --member $M --role r",
            "gcloud compute instances add-metadata $VM",
            "heroku config:set FOO=$BAR",
            "heroku config:set $(cat .env)",
            "heroku config:get $KEY",
            "heroku ps:scale web=$N",
            "wrangler secret put $NAME",
            "wrangler kv key put $K $V",
            "wrangler r2 object put b/$K",
            "vercel link --project $P",
            "hcloud context use $C",
            "oci os object put -bn $B",
            "oci ce cluster create-kubeconfig --cluster-id $ID",
        ],
        &[
            // A word only known when it runs, where a verb could be, is
            // still unknown.
            ("gcloud projects $verb prod", Rule::Unknown),
            ("heroku $verb", Rule::Unknown),
            ("wrangler kv:namespace $verb x", Rule::Unknown),
            ("gcloud compute $x instances", Rule::Unknown),
            // A verb that deletes is read behind an operand too.
            ("heroku config:set FOO=$BAR; heroku apps:destroy x", DESTROY),
            ("gcloud compute instances delete $VM", DESTROY),
        ],
    );
}

#[test]
fn the_delete_verbs_of_three_tables_match_their_siblings() {
    rows(
        &[
            "gcloud compute instances describe vm",
            "gcloud compute instance-groups managed list",
            "heroku pg:backups:capture",
            "doctl kubernetes cluster node-pool list c",
        ],
        &[
            ("gcloud firestore bulk-delete --collection-ids=x", DESTROY),
            (
                "gcloud compute instance-groups managed delete-instances mig --instances=a",
                DESTROY,
            ),
            (
                "doctl kubernetes cluster node-pool delete-node c p n",
                DESTROY,
            ),
            ("heroku pg:backups:delete b001", DESTROY),
            ("heroku addons:delete x", DESTROY),
        ],
    );
}
