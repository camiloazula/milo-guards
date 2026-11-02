//! Deleting containers, cluster objects, cloud resources or an
//! infrastructure stack is `destroy_resources`; listing, describing,
//! creating and rehearsing are safe, and a command only known when it runs is
//! `unknown`. One table per kind of tool, then the lines that wrap or run
//! them, PowerShell and cmd, and the reason a prompt can show. How the words
//! of such a line are read (options, rehearsals, variables, loops) is in
//! `destroy_resources_options.rs`.

mod common;

use common::{check, check_effect, posix, rules, windows};
use milo_guards_shell::{classify, effect, Effect, Reach, Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

/// The reason of the one finding of `line`, which breaks `rule`.
fn reason(line: &str, rule: Rule) -> String {
    let assessment = classify(line, Shell::Posix, &posix());
    let findings = assessment.findings();
    assert_eq!(findings.len(), 1, "{line}: {findings:?}");
    assert_eq!(findings[0].rule, rule, "{line}");
    findings[0].reason.clone()
}

#[test]
fn containers() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "docker ps -a",
            "docker run --rm -it alpine sh",
            "docker run --rm alpine rm -rf /tmp/x",
            "docker exec web rm -rf /var/cache",
            "docker rm web",
            "docker rm -f web",
            "docker rm web db",
            "docker rm --force web",
            "docker container rm web",
            "docker rm \"$NAME\"",
            "docker rm -f \"$NAME\"",
            "docker stop web",
            "docker kill web",
            "docker rmi app",
            "docker image rm app",
            "docker image prune",
            "docker image ls",
            "docker network rm app",
            "docker network ls",
            "docker volume ls",
            "docker volume create pgdata",
            "docker volume inspect pgdata",
            "docker system df",
            "docker system info",
            "docker builder prune",
            "docker compose up -d",
            "docker compose down",
            "docker compose down --remove-orphans",
            "docker compose -f stack.yml down",
            "docker compose logs -f",
            "docker compose rm",
            "docker-compose down",
            "docker-compose up -d",
            "docker pull alpine",
            "docker build -t app .",
            "docker --context prod ps",
            "docker -H tcp://host:2375 ps",
            "docker --help",
            "docker system prune --help",
            "podman rm web",
            "podman ps",
            "nerdctl rm web",
            "nerdctl -n k8s.io ps",
            "docker",
            "docker -v",
        ],
        &[
            ("docker system prune", DESTROY),
            ("docker system prune -f", DESTROY),
            ("docker system prune -af --volumes", DESTROY),
            ("docker system prune -a --volumes -f", DESTROY),
            ("docker -H tcp://host:2375 system prune -f", DESTROY),
            ("docker --context prod system prune", DESTROY),
            ("docker volume rm pgdata", DESTROY),
            ("docker volume remove pgdata", DESTROY),
            ("docker volume rm -f pgdata", DESTROY),
            ("docker volume prune", DESTROY),
            ("docker volume prune -f", DESTROY),
            ("docker container prune", DESTROY),
            ("docker container prune -f", DESTROY),
            ("docker image prune -a", DESTROY),
            ("docker image prune -af", DESTROY),
            ("docker image prune --all --force", DESTROY),
            ("docker network prune", DESTROY),
            ("docker network prune -f", DESTROY),
            ("docker rm -f $(docker ps -aq)", DESTROY),
            ("docker rm $(docker ps -aq)", DESTROY),
            ("docker rm `docker ps -aq`", DESTROY),
            ("docker container rm -f $(docker ps -aq)", DESTROY),
            ("docker rm -f $ids", DESTROY),
            ("docker ps -aq | xargs docker rm -f", DESTROY),
            ("docker rm -f web db", DESTROY),
            ("docker rm -f web db cache", DESTROY),
            ("docker rm --force web db", DESTROY),
            ("docker rm -fv web", DESTROY),
            ("docker rm -v web", DESTROY),
            ("docker rm --volumes web", DESTROY),
            ("docker compose down -v", DESTROY),
            ("docker compose down --volumes", DESTROY),
            ("docker compose down --remove-orphans -v", DESTROY),
            ("docker compose -f stack.yml -p app down -v", DESTROY),
            ("docker-compose down -v", DESTROY),
            ("docker-compose -f a.yml down --volumes", DESTROY),
            ("docker compose rm -fsv", DESTROY),
            ("docker stack rm app", DESTROY),
            ("docker service rm web", DESTROY),
            ("podman system prune -af", DESTROY),
            ("podman system reset -f", DESTROY),
            ("podman volume rm pgdata", DESTROY),
            ("podman rm -a", DESTROY),
            ("podman rm --all --force", DESTROY),
            ("podman rm --filter status=exited", DESTROY),
            ("podman pod rm -f $(podman pod ls -q)", DESTROY),
            ("podman pod prune", DESTROY),
            ("podman machine rm -f", DESTROY),
            ("podman kube down pod.yaml", DESTROY),
            ("podman-compose down -v", DESTROY),
            ("nerdctl system prune -af", DESTROY),
            ("nerdctl -n k8s.io volume rm data", DESTROY),
            (
                "nerdctl --namespace k8s.io rm -f $(nerdctl ps -aq)",
                DESTROY,
            ),
            ("docker $cmd ps", Rule::Unknown),
            ("docker system $sub", Rule::Unknown),
            ("docker \"$@\"", Rule::Unknown),
        ],
    );
}

#[test]
fn clusters() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "kubectl get pods",
            "kubectl get ns",
            "kubectl get pods -n prod -o wide",
            "kubectl describe pod web",
            "kubectl logs web",
            "kubectl apply -f deploy.yaml",
            "kubectl apply -f deploy.yaml --dry-run=client",
            "kubectl create namespace dev",
            "kubectl rollout restart deploy web",
            "kubectl rollout status deploy web",
            "kubectl cordon node1",
            "kubectl config get-contexts",
            "kubectl config use-context prod",
            "kubectl delete pod web --dry-run=client",
            "kubectl delete -f pod.yaml --dry-run=server",
            "kubectl delete namespace prod --dry-run",
            "kubectl drain node1 --dry-run=client",
            "kubectl delete --help",
            "kubectl",
            "kubectl --context prod get pods",
            "kubectl -n delete get pods",
            "oc get pods",
            "helm install api ./chart",
            "helm upgrade --install api ./chart",
            "helm list",
            "helm repo remove stable",
            "helm plugin uninstall diff",
            "kind create cluster",
            "kind get clusters",
            "kind delete kubeconfig",
            "minikube start",
            "minikube stop",
            "minikube status",
            "k3d cluster create dev",
            "k3d cluster list",
            "microk8s status",
            "microk8s kubectl get pods",
            "k3s kubectl get pods",
        ],
        &[
            ("kubectl delete namespace prod", DESTROY),
            ("kubectl delete ns prod", DESTROY),
            ("kubectl delete namespace/prod", DESTROY),
            ("kubectl delete pod web", DESTROY),
            ("kubectl delete pods --all", DESTROY),
            ("kubectl delete pods -A", DESTROY),
            ("kubectl delete pods --all-namespaces", DESTROY),
            ("kubectl delete all --all -n prod", DESTROY),
            ("kubectl delete -f deploy.yaml", DESTROY),
            ("kubectl delete -k overlays/prod", DESTROY),
            ("kubectl delete pvc data", DESTROY),
            ("kubectl delete pod -l app=web", DESTROY),
            ("kubectl delete pod web --grace-period=0 --force", DESTROY),
            ("kubectl -n prod delete pod web", DESTROY),
            ("kubectl --namespace prod delete pod web", DESTROY),
            ("kubectl --namespace=prod delete pod web", DESTROY),
            (
                "kubectl --context prod --namespace prod delete pod web",
                DESTROY,
            ),
            ("kubectl --kubeconfig ~/.kube/prod delete pod web", DESTROY),
            ("kubectl -v 6 delete pod web", DESTROY),
            ("kubectl --namespace=$NS delete pod web", DESTROY),
            ("kubectl get pods -o name | xargs kubectl delete", DESTROY),
            ("sudo kubectl delete pod web", DESTROY),
            ("kubectl.exe delete pod web", DESTROY),
            ("oc delete project prod", DESTROY),
            ("kubectl drain node1", DESTROY),
            (
                "kubectl drain node1 --ignore-daemonsets --delete-emptydir-data",
                DESTROY,
            ),
            ("kubectl replace --force -f pod.yaml", DESTROY),
            ("kubectl apply --prune -f dir/ --all", DESTROY),
            ("microk8s kubectl delete ns prod", DESTROY),
            ("microk8s reset", DESTROY),
            ("k3s kubectl delete pod web", DESTROY),
            ("minikube kubectl -- delete ns prod", DESTROY),
            ("kubectl $verb pods", Rule::Unknown),
            ("helm uninstall api", DESTROY),
            ("helm uninstall api -n prod", DESTROY),
            ("helm -n prod uninstall api", DESTROY),
            ("helm --kube-context prod uninstall api", DESTROY),
            ("helm delete api", DESTROY),
            ("helm del api", DESTROY),
            ("helm un api", DESTROY),
            ("kind delete cluster", DESTROY),
            ("kind delete cluster --name dev", DESTROY),
            ("kind delete clusters --all", DESTROY),
            ("minikube delete", DESTROY),
            ("minikube delete --all --purge", DESTROY),
            ("minikube -p dev delete", DESTROY),
            ("k3d cluster delete dev", DESTROY),
            ("k3d cluster delete --all", DESTROY),
            ("k3d node delete n1", DESTROY),
        ],
    );
}

#[test]
fn infrastructure() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "terraform plan",
            "terraform plan -destroy",
            "terraform init",
            "terraform validate",
            "terraform fmt",
            "terraform apply",
            "terraform apply -auto-approve",
            "terraform output",
            "terraform destroy -help",
            "terraform -chdir=infra plan",
            "terraform",
            "tofu plan",
            "tofu apply",
            "terragrunt plan",
            "terragrunt run-all plan",
            "pulumi up",
            "pulumi preview",
            "pulumi stack ls",
            "pulumi stack select dev",
            "cdk deploy",
            "cdk synth",
            "cdk diff",
            "sst deploy",
            "sst dev",
            "serverless deploy",
            "sls invoke -f hello",
            "vagrant up",
            "vagrant status",
            "sam build",
            "sam deploy",
        ],
        &[
            ("terraform destroy", DESTROY),
            ("terraform destroy -auto-approve", DESTROY),
            ("terraform destroy -target=aws_instance.web", DESTROY),
            ("terraform -chdir=infra destroy", DESTROY),
            ("terraform apply -destroy", DESTROY),
            ("terraform apply -destroy -auto-approve", DESTROY),
            ("terraform apply --destroy", DESTROY),
            ("terraform apply -destroy=true", DESTROY),
            ("terraform apply -destroy=false -destroy", DESTROY),
            ("terraform apply -auto-approve -destroy", DESTROY),
            ("tofu destroy", DESTROY),
            ("tofu apply -destroy", DESTROY),
            ("terragrunt destroy", DESTROY),
            ("terragrunt run-all destroy", DESTROY),
            ("terragrunt run --all -- destroy", DESTROY),
            ("terragrunt destroy-all", DESTROY),
            ("terragrunt run-all apply -destroy", DESTROY),
            ("terragrunt --terragrunt-working-dir infra destroy", DESTROY),
            ("pulumi destroy", DESTROY),
            ("pulumi destroy --yes", DESTROY),
            ("pulumi down --yes", DESTROY),
            ("pulumi stack rm dev", DESTROY),
            ("pulumi stack rm dev --force --yes", DESTROY),
            ("pulumi stack remove dev", DESTROY),
            ("pulumi --cwd infra destroy", DESTROY),
            // pulumi is found behind its own stack option.
            ("pulumi --stack dev destroy --yes", DESTROY),
            ("pulumi -s dev destroy", DESTROY),
            ("pulumi --stack dev down", DESTROY),
            ("pulumi --stack=dev destroy", DESTROY),
            ("pulumi -s dev stack rm", DESTROY),
            ("pulumi --stack dev stack rm dev", DESTROY),
            ("pulumi --target urn:x destroy", DESTROY),
            ("pulumi -m msg -s dev destroy", DESTROY),
            ("cdk destroy", DESTROY),
            ("cdk destroy --force", DESTROY),
            ("cdk -a 'node app.js' destroy", DESTROY),
            ("cdk --profile prod destroy", DESTROY),
            ("cdktf destroy", DESTROY),
            ("sst remove", DESTROY),
            ("sst remove --stage prod", DESTROY),
            ("sst --stage prod remove", DESTROY),
            ("serverless remove", DESTROY),
            ("serverless remove --stage prod", DESTROY),
            ("sls remove", DESTROY),
            ("vagrant destroy", DESTROY),
            ("vagrant destroy -f", DESTROY),
            ("sam delete", DESTROY),
            ("sam delete --stack-name app", DESTROY),
            ("terraform $cmd", Rule::Unknown),
        ],
    );
}

#[test]
fn aws() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "aws s3 ls",
            "aws s3 ls s3://bucket --recursive",
            "aws s3 cp a.txt s3://bucket/a.txt",
            "aws s3 sync . s3://bucket",
            "aws s3 mb s3://bucket",
            "aws s3 rm s3://bucket --recursive --dryrun",
            "aws s3 rm s3://bucket/key --dryrun",
            "aws s3 sync . s3://bucket --delete --dryrun",
            "aws s3api list-buckets",
            "aws ec2 describe-instances",
            "aws ec2 run-instances --image-id ami-1",
            "aws ec2 stop-instances --instance-ids i-1",
            "aws iam list-users",
            "aws iam create-user --user-name bob",
            "aws sts get-caller-identity",
            "aws --profile prod sts get-caller-identity",
            "aws configure list",
            "aws --version",
            "aws",
            "aws s3",
            "aws s3api head-object --bucket b --key delete-me",
            "aws logs describe-log-groups --log-group-name-prefix delete",
        ],
        &[
            ("aws s3 rm s3://prod-bucket --recursive", DESTROY),
            ("aws s3 rm s3://prod-bucket/key", DESTROY),
            ("aws s3 rm --recursive s3://prod-bucket", DESTROY),
            ("aws s3 rm s3://b --recursive", DESTROY),
            ("aws --profile prod s3 rm s3://b --recursive", DESTROY),
            ("aws s3 rb s3://bucket", DESTROY),
            ("aws s3 rb s3://bucket --force", DESTROY),
            ("aws s3 sync . s3://bucket --delete", DESTROY),
            ("aws s3 sync . s3://b --delete", DESTROY),
            ("aws s3 sync s3://a s3://b --delete", DESTROY),
            ("aws s3api delete-bucket --bucket b", DESTROY),
            ("aws s3api delete-object --bucket b --key k", DESTROY),
            (
                "aws s3api delete-objects --bucket b --delete file://x.json",
                DESTROY,
            ),
            ("aws ec2 terminate-instances --instance-ids i-1", DESTROY),
            (
                "aws --region us-east-1 ec2 terminate-instances --instance-ids i-1",
                DESTROY,
            ),
            ("aws ec2 delete-volume --volume-id vol-1", DESTROY),
            ("aws ec2 delete-security-group --group-id sg-1", DESTROY),
            ("aws ec2 deregister-image --image-id ami-1", DESTROY),
            (
                "aws rds delete-db-instance --db-instance-identifier x --skip-final-snapshot",
                DESTROY,
            ),
            ("aws cloudformation delete-stack --stack-name x", DESTROY),
            ("aws dynamodb delete-table --table-name t", DESTROY),
            ("aws lambda delete-function --function-name f", DESTROY),
            ("aws iam delete-user --user-name bob", DESTROY),
            (
                "aws ecr batch-delete-image --repository-name r --image-ids imageTag=a",
                DESTROY,
            ),
            ("aws sqs purge-queue --queue-url u", DESTROY),
            ("aws kms schedule-key-deletion --key-id k", DESTROY),
            (
                "aws --output json --query x ec2 delete-volume --volume-id v",
                DESTROY,
            ),
            ("aws $service $verb", Rule::Unknown),
            ("aws s3 $verb s3://b", Rule::Unknown),
        ],
    );
}

/// Every cloud CLI but aws. Each table holds the delete verbs its siblings
/// have: a bulk delete, a sync that deletes what the source lacks, a removal
/// of one node or backup.
#[test]
fn other_clouds() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "gcloud projects list",
            "gcloud config set project prod",
            "gcloud compute instances list",
            "gcloud compute instances list --filter=name~delete",
            "gcloud compute instances list --filter name=delete",
            "gcloud compute instances describe vm",
            "gcloud compute instances describe vm --zone us-central1-a",
            "gcloud compute instances create vm",
            "gcloud compute instances stop vm",
            "gcloud compute instance-groups managed list",
            "gcloud storage ls gs://bucket",
            "gcloud storage cp a gs://bucket",
            "gcloud storage rsync -r . gs://b",
            "gcloud auth login",
            "gsutil ls gs://bucket",
            "gsutil cp a gs://bucket",
            "gsutil -m cp -r dir gs://bucket",
            "gsutil rsync -r dir gs://bucket",
            "gsutil mb gs://bucket",
            "az group list",
            "az vm list -g delete",
            "az vm show -g rg -n delete",
            "az vm create -g rg -n vm --image ubuntu",
            "az account show",
            "az storage blob list --account-name a -c c",
            "doctl compute droplet list",
            "doctl compute droplet create web",
            "doctl auth remove --context x",
            "doctl kubernetes cluster node-pool list c",
            "flyctl apps list",
            "flyctl deploy",
            "fly status",
            "fly apps list",
            "fly machine list",
            "fly m list",
            "fly vol list",
            "vercel",
            "vercel deploy",
            "vercel ls",
            "vercel env ls",
            "heroku apps",
            "heroku logs --tail",
            "heroku apps:info -a x",
            "heroku pg:backups:capture",
            "wrangler deploy",
            "wrangler dev",
            "wrangler tail",
            "wrangler kv namespace list",
            "firebase deploy",
            "firebase projects:list",
            "firebase database:get /",
            "hcloud server list",
            "scw instance server list",
            "oci compute instance list",
            "oci os object list --bucket-name b",
            "eksctl get cluster",
            "eksctl create cluster",
            "kops get clusters",
        ],
        &[
            ("gcloud projects delete prod", DESTROY),
            ("gcloud projects delete prod --quiet", DESTROY),
            (
                "gcloud compute instances delete vm --zone us-central1-a",
                DESTROY,
            ),
            ("gcloud --project prod compute instances delete vm", DESTROY),
            ("gcloud compute instances delete vm --quiet", DESTROY),
            ("gcloud beta compute disks delete d", DESTROY),
            ("gcloud container clusters delete c", DESTROY),
            ("gcloud sql instances delete db", DESTROY),
            ("gcloud run services delete svc", DESTROY),
            ("gcloud functions delete f", DESTROY),
            ("gcloud storage buckets delete gs://b", DESTROY),
            ("gcloud storage rm -r gs://b", DESTROY),
            ("gcloud storage rm gs://b/o", DESTROY),
            ("gcloud alpha storage rm gs://b/o", DESTROY),
            (
                "gcloud storage rsync -r . gs://b --delete-unmatched-destination-objects",
                DESTROY,
            ),
            (
                "gcloud storage rsync --delete-unmatched-destination-objects -r . gs://b",
                DESTROY,
            ),
            ("gcloud kms keys versions destroy 1 --key k", DESTROY),
            ("gcloud --format json compute instances delete vm", DESTROY),
            ("gcloud firestore bulk-delete --collection-ids=x", DESTROY),
            (
                "gcloud compute instance-groups managed delete-instances mig --instances=a",
                DESTROY,
            ),
            ("gsutil rm -r gs://bucket", DESTROY),
            ("gsutil -m rm -r gs://bucket/**", DESTROY),
            ("gsutil rm gs://bucket/obj", DESTROY),
            ("gsutil rb gs://bucket", DESTROY),
            ("gsutil -m rsync -d -r dir gs://bucket", DESTROY),
            ("gsutil rsync -dr dir gs://bucket", DESTROY),
            ("gsutil rsync -d . gs://b", DESTROY),
            ("az group delete --name rg --yes", DESTROY),
            ("az group delete -n rg -y", DESTROY),
            ("az vm delete -g rg -n vm", DESTROY),
            ("az --subscription s group delete -n rg", DESTROY),
            ("az aks delete -g rg -n c", DESTROY),
            ("az storage blob delete -c c -n b", DESTROY),
            ("az storage blob delete-batch -s c", DESTROY),
            (
                "az storage remove --account-name a -c c --recursive",
                DESTROY,
            ),
            ("az keyvault purge -n kv", DESTROY),
            ("az resource delete --ids x", DESTROY),
            ("az sql db delete -g rg -s s -n d", DESTROY),
            ("doctl compute droplet delete web", DESTROY),
            ("doctl compute droplet delete web -f", DESTROY),
            ("doctl compute droplet d web", DESTROY),
            ("doctl -t $TOKEN compute droplet delete web", DESTROY),
            ("doctl kubernetes cluster delete c", DESTROY),
            (
                "doctl kubernetes cluster node-pool delete-node c p n",
                DESTROY,
            ),
            ("doctl databases delete id", DESTROY),
            ("doctl apps delete id", DESTROY),
            ("flyctl apps destroy app", DESTROY),
            ("flyctl apps destroy app -y", DESTROY),
            ("fly apps destroy app", DESTROY),
            ("fly volumes destroy v", DESTROY),
            ("fly machine destroy m", DESTROY),
            ("fly machine rm m", DESTROY),
            ("fly -a app apps destroy app", DESTROY),
            // flyctl's aliases of a group and of a verb.
            ("fly m rm abc", DESTROY),
            ("fly m remove abc", DESTROY),
            ("fly m destroy abc", DESTROY),
            ("fly vol rm v", DESTROY),
            ("fly vol delete v", DESTROY),
            ("fly volumes remove v", DESTROY),
            ("fly apps rm app", DESTROY),
            ("fly apps remove app", DESTROY),
            ("flyctl apps rm app", DESTROY),
            ("fly -a app apps rm app", DESTROY),
            ("vercel remove app", DESTROY),
            ("vercel rm app --yes", DESTROY),
            ("vercel project rm app", DESTROY),
            ("vercel --token $T remove app", DESTROY),
            ("vercel env rm KEY", DESTROY),
            ("heroku apps:destroy -a x --confirm x", DESTROY),
            ("heroku apps:destroy x", DESTROY),
            ("heroku apps destroy -a x", DESTROY),
            ("heroku addons:destroy db -a x", DESTROY),
            ("heroku addons:delete x", DESTROY),
            ("heroku pg:backups:delete b001", DESTROY),
            ("wrangler delete", DESTROY),
            ("wrangler delete --name w", DESTROY),
            ("wrangler d1 delete db", DESTROY),
            ("wrangler kv namespace delete --namespace-id x", DESTROY),
            ("wrangler kv:namespace delete --namespace-id x", DESTROY),
            ("wrangler r2 bucket delete b", DESTROY),
            ("wrangler pages project delete p", DESTROY),
            ("wrangler secret delete KEY", DESTROY),
            ("firebase projects:delete p", DESTROY),
            ("firebase firestore:delete --all-collections", DESTROY),
            ("firebase database:remove / --force", DESTROY),
            ("hcloud server delete web", DESTROY),
            ("scw instance server terminate s", DESTROY),
            ("scw instance server delete s", DESTROY),
            ("oci compute instance terminate --instance-id i", DESTROY),
            ("oci os bucket delete --name b", DESTROY),
            ("oci os object bulk-delete --bucket-name b --force", DESTROY),
            ("eksctl delete cluster --name c", DESTROY),
            ("eksctl delete nodegroup --cluster c --name n", DESTROY),
            ("kops delete cluster --name c --yes", DESTROY),
        ],
    );
}

/// An operand only known when it runs, after a verb that copies, runs, reads
/// or sets something, does not make an everyday cloud line unknown; a verb
/// that deletes is still read behind it.
#[test]
fn everyday_cloud_lines_with_a_computed_operand_are_safe() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "gcloud container clusters get-credentials $C --zone z",
            "gcloud builds submit --tag \"gcr.io/$P/app\"",
            "gcloud auth activate-service-account --key-file $F",
            "gcloud secrets versions access latest --secret $S",
            "gcloud projects add-iam-policy-binding $P --member $M --role r",
            "gcloud compute instances add-metadata $VM",
            "gcloud storage cp $F gs://b/",
            "gcloud storage cp \"$F\" gs://b/",
            "gcloud storage rsync $SRC gs://b",
            "gcloud storage mv $A gs://b/",
            "gcloud pubsub topics publish $T --message x",
            "gcloud container images list-tags $IMG",
            "gcloud sql connect $DB --user root",
            "gcloud config configurations activate $C",
            "heroku config:set FOO=$BAR",
            "heroku config:set $(cat .env)",
            "heroku config:get $KEY",
            "heroku ps:scale web=$N",
            "wrangler secret put $NAME",
            "wrangler kv key put $K $V",
            "wrangler r2 object put b/$K",
            "wrangler tail $W",
            "wrangler dev $F",
            "wrangler d1 execute $DB --command \"select 1\"",
            "vercel link --project $P",
            "vercel pull --environment $E",
            "vercel promote $URL",
            "vercel redeploy $URL",
            "hcloud context use $C",
            "oci os object put -bn $B",
            "oci ce cluster create-kubeconfig --cluster-id $ID",
            "oci session authenticate --profile-name $P",
            "az storage blob upload -f $F -c c -n x",
            "az storage blob upload-batch -d c -s $DIR",
            "az storage blob download -c c -n x -f $F",
            "az storage blob download-batch -d $DIR -s c",
            "az acr build -r $R -t img .",
            "aws lambda invoke --function-name $F out.json",
        ],
        &[
            // A word only known when it runs, where a verb could be, is
            // still unknown.
            ("heroku $verb", Rule::Unknown),
            ("wrangler kv:namespace $verb x", Rule::Unknown),
            ("gcloud compute $x instances", Rule::Unknown),
            ("gcloud run $verb web", Rule::Unknown),
            // A verb that deletes is read behind an operand too.
            ("heroku config:set FOO=$BAR; heroku apps:destroy x", DESTROY),
            ("gcloud compute instances delete $VM", DESTROY),
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

/// A destroying command is found inside a shell's script, behind a wrapper,
/// a path, an assignment, in a list or a pipeline, and when a package runner
/// runs it; quoted or searched for, it is only text.
#[test]
fn wrapped_or_run_by_something_else() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "echo 'docker system prune -af'",
            "echo kubectl delete namespace prod",
            "git commit -m 'terraform destroy'",
            "grep -r 'aws s3 rm' docs",
            "man docker",
            "docker ps -a | grep web",
            "kubectl get pods | grep delete",
            "terraform plan | tee plan.txt",
            "npx cdk diff",
            "pnpm dlx cdk synth",
        ],
        &[
            ("bash -c 'docker system prune -af'", DESTROY),
            ("sh -c \"kubectl delete namespace prod\"", DESTROY),
            ("env KUBECONFIG=x kubectl delete pod web", DESTROY),
            ("nohup terraform destroy -auto-approve &", DESTROY),
            ("time terraform destroy", DESTROY),
            ("cd infra && terraform destroy -auto-approve", DESTROY),
            ("terraform plan && terraform destroy -auto-approve", DESTROY),
            ("kubectl get ns -o name | xargs kubectl delete", DESTROY),
            ("/usr/local/bin/kubectl delete pod web", DESTROY),
            ("DOCKER_HOST=tcp://h:2375 docker system prune -af", DESTROY),
            (
                "for ns in a b; do kubectl delete namespace $ns; done",
                DESTROY,
            ),
            ("npx cdk destroy", DESTROY),
            ("pnpm dlx cdk destroy", DESTROY),
            ("bunx cdk destroy", DESTROY),
            ("npm exec -- cdk destroy", DESTROY),
            ("npx wrangler delete", DESTROY),
            ("npx sst remove", DESTROY),
        ],
    );
}

#[test]
fn it_adds_to_what_other_rules_find() {
    assert_eq!(
        rules("sudo docker system prune -af", Shell::Posix, &posix()),
        vec![Rule::Elevated, DESTROY]
    );
    assert_eq!(
        rules("kubectl delete ns prod; rm -rf ~/x", Shell::Posix, &posix()),
        vec![DESTROY, Rule::Delete]
    );
}

#[test]
fn powershell_and_cmd() {
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "docker ps",
            "docker rm web",
            "docker rm -f web",
            "docker compose down",
            "kubectl get pods",
            "terraform plan",
            "aws s3 ls",
            "az group list",
        ],
        &[
            ("docker system prune -af", DESTROY),
            ("docker.exe system prune -af", DESTROY),
            ("docker volume rm pgdata", DESTROY),
            ("docker rm -f (docker ps -aq)", DESTROY),
            ("docker rm -f $(docker ps -aq)", DESTROY),
            ("docker compose down -v", DESTROY),
            ("kubectl delete namespace prod", DESTROY),
            ("kubectl.exe delete pod web", DESTROY),
            ("helm uninstall api", DESTROY),
            ("terraform destroy -auto-approve", DESTROY),
            ("terraform apply -destroy", DESTROY),
            ("aws s3 rm s3://prod-bucket --recursive", DESTROY),
            (
                "aws.exe ec2 terminate-instances --instance-ids i-1",
                DESTROY,
            ),
            ("gcloud projects delete prod", DESTROY),
            ("az group delete --name rg --yes", DESTROY),
            (
                "docker ps -aq | ForEach-Object { docker rm -f $_ }",
                DESTROY,
            ),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &[
            "docker ps",
            "docker rm web",
            "kubectl get pods",
            "terraform plan",
        ],
        &[
            ("docker system prune -af", DESTROY),
            ("kubectl delete namespace prod", DESTROY),
            ("terraform destroy -auto-approve", DESTROY),
            ("aws s3 rm s3://prod-bucket --recursive", DESTROY),
            ("docker volume rm %VOL%", DESTROY),
        ],
    );
}

#[test]
fn sls_in_powershell_is_select_string() {
    // The alias wins over any program on the path: this never runs serverless.
    let searches = [
        "Get-Content app.log | sls remove",
        "git log --oneline | sls remove",
        "gci -r | sls \"remove\"",
        "sls remove *.txt",
        "sls -Pattern remove -Path *.txt",
        "SLS remove",
    ];
    check(Shell::PowerShell, &windows(), &searches, &[]);
    let reads: Vec<&str> = searches
        .iter()
        .copied()
        .filter(|line| !line.starts_with("git "))
        .collect();
    check_effect(
        Shell::PowerShell,
        &windows(),
        Effect::ReadsOnly(Reach::Workspace),
        &reads,
    );
    // Whatever `git log` itself reads as, the alias adds nothing to it.
    assert_eq!(
        effect(
            "git log --oneline | sls remove",
            Shell::PowerShell,
            &windows()
        ),
        effect(
            "git log --oneline | Select-String remove",
            Shell::PowerShell,
            &windows()
        )
    );
    // A program with an extension, or serverless itself, is still serverless.
    check(
        Shell::PowerShell,
        &windows(),
        &[],
        &[("sls.cmd remove", DESTROY), ("serverless remove", DESTROY)],
    );
    // No alias in cmd, nor on a POSIX shell (`infrastructure` holds that row).
    check(Shell::Cmd, &windows(), &[], &[("sls remove", DESTROY)]);
}

/// The one finding of each line and the reason a prompt can show for it,
/// for what it destroys or for the command only known when it runs.
#[test]
fn a_reason_and_a_target_a_prompt_can_show() {
    for (line, rule, expected) in [
        (
            "kubectl delete namespace prod",
            DESTROY,
            "deletes a namespace and everything in it",
        ),
        (
            "docker system prune -af --volumes",
            DESTROY,
            "removes unused containers, images and volumes",
        ),
        (
            "docker system prune",
            DESTROY,
            "removes unused containers, networks and images",
        ),
        ("docker volume rm pgdata", DESTROY, "deletes volumes"),
        (
            "docker rm -f $(docker ps -aq)",
            DESTROY,
            "removes containers chosen when it runs",
        ),
        (
            "kubectl delete pods --all",
            DESTROY,
            "deletes every object of a kind",
        ),
        (
            "kubectl delete pods -A",
            DESTROY,
            "deletes objects in every namespace",
        ),
        ("kubectl delete pod web", DESTROY, "deletes cluster objects"),
        ("helm uninstall api", DESTROY, "uninstalls a Helm release"),
        (
            "terraform apply -destroy",
            DESTROY,
            "destroys the infrastructure a configuration manages",
        ),
        (
            "aws ec2 terminate-instances --instance-ids i-1",
            DESTROY,
            "terminates EC2 instances",
        ),
        (
            "aws rds delete-db-instance --db-instance-identifier x",
            DESTROY,
            "deletes AWS resources",
        ),
        (
            "aws s3 rm s3://b --recursive",
            DESTROY,
            "deletes every object under a prefix",
        ),
        (
            "docker $cmd ps",
            Rule::Unknown,
            "runs a docker command only known when it runs",
        ),
        (
            "aws $service",
            Rule::Unknown,
            "runs an aws command only known when it runs",
        ),
        (
            "az $x",
            Rule::Unknown,
            "runs an az command only known when it runs",
        ),
        (
            "oc $x",
            Rule::Unknown,
            "runs an oc command only known when it runs",
        ),
        (
            "oci $x",
            Rule::Unknown,
            "runs an oci command only known when it runs",
        ),
        (
            "eksctl $x",
            Rule::Unknown,
            "runs an eksctl command only known when it runs",
        ),
        (
            "sst $x",
            Rule::Unknown,
            "runs an sst command only known when it runs",
        ),
        (
            "gcloud $x",
            Rule::Unknown,
            "runs a gcloud command only known when it runs",
        ),
    ] {
        assert_eq!(reason(line, rule), expected, "{line}");
    }
    let assessment = classify("kubectl delete namespace prod", Shell::Posix, &posix());
    assert_eq!(
        assessment.findings()[0].target.as_deref(),
        Some("namespace")
    );
}
