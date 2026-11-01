//! Deleting containers, cluster objects, cloud resources or an
//! infrastructure stack is `destroy_resources`; listing, describing,
//! creating and rehearsing are safe, and a command only known when it runs is
//! `unknown`.

mod common;

use common::{check, posix, rules, windows};
use milo_guards_shell::{classify, Rule, Shell};

const DESTROY: Rule = Rule::DestroyResources;

fn reason(line: &str) -> String {
    let assessment = classify(line, Shell::Posix, &posix());
    let findings = assessment.findings();
    assert_eq!(findings.len(), 1, "{line}: {findings:?}");
    assert_eq!(findings[0].rule, DESTROY, "{line}");
    findings[0].reason.clone()
}

#[test]
fn the_lines_in_the_issue() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "docker rm web",
            "docker compose down",
            "kubectl get pods",
            "terraform plan",
            "aws s3 ls",
            "docker build -t app .",
        ],
        &[
            ("docker system prune -af --volumes", DESTROY),
            ("docker volume rm pgdata", DESTROY),
            ("docker rm -f $(docker ps -aq)", DESTROY),
            ("kubectl delete namespace prod", DESTROY),
            ("helm uninstall api", DESTROY),
            ("terraform destroy -auto-approve", DESTROY),
            ("aws s3 rm s3://prod-bucket --recursive", DESTROY),
            ("gcloud projects delete prod", DESTROY),
        ],
    );
}

#[test]
fn a_reason_and_a_target_a_prompt_can_show() {
    let assessment = classify("kubectl delete namespace prod", Shell::Posix, &posix());
    let finding = &assessment.findings()[0];
    assert_eq!(finding.rule, DESTROY);
    assert_eq!(finding.reason, "deletes a namespace and everything in it");
    assert_eq!(finding.target.as_deref(), Some("namespace"));
    assert_eq!(DESTROY.name(), "destroy_resources");
    assert_eq!(
        reason("docker system prune -af --volumes"),
        "removes unused containers, images and volumes"
    );
    assert_eq!(
        reason("docker system prune"),
        "removes unused containers, networks and images"
    );
    assert_eq!(reason("docker volume rm pgdata"), "deletes volumes");
    assert_eq!(
        reason("docker rm -f $(docker ps -aq)"),
        "removes containers chosen when it runs"
    );
    assert_eq!(
        reason("kubectl delete pods --all"),
        "deletes every object of a kind"
    );
    assert_eq!(
        reason("kubectl delete pods -A"),
        "deletes objects in every namespace"
    );
    assert_eq!(reason("kubectl delete pod web"), "deletes cluster objects");
    assert_eq!(reason("helm uninstall api"), "uninstalls a Helm release");
    assert_eq!(
        reason("terraform apply -destroy"),
        "destroys the infrastructure a configuration manages"
    );
    assert_eq!(
        reason("aws ec2 terminate-instances --instance-ids i-1"),
        "terminates EC2 instances"
    );
    assert_eq!(
        reason("aws rds delete-db-instance --db-instance-identifier x"),
        "deletes AWS resources"
    );
    assert_eq!(
        reason("aws s3 rm s3://b --recursive"),
        "deletes every object under a prefix"
    );
    let assessment = classify("docker $cmd ps", Shell::Posix, &posix());
    assert_eq!(assessment.findings()[0].rule, Rule::Unknown);
    assert_eq!(
        assessment.findings()[0].reason,
        "runs a docker command only known when it runs"
    );
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
            ("docker system prune -a --volumes -f", DESTROY),
            ("docker -H tcp://host:2375 system prune -f", DESTROY),
            ("docker --context prod system prune", DESTROY),
            ("sudo docker system prune -af", DESTROY),
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
            ("docker rm -f \"$(docker ps -aq)\"", DESTROY),
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
fn a_computed_container_is_judged_like_the_shell_reads_it() {
    // An unquoted variable is split into words; a quoted one is a word.
    assert_eq!(
        rules("docker rm -f $names", Shell::Posix, &posix()),
        vec![DESTROY]
    );
    assert!(rules("docker rm -f \"$name\"", Shell::Posix, &posix()).is_empty());
    assert_eq!(
        rules("docker rm -f \"$(docker ps -aq)\"", Shell::Posix, &posix()),
        vec![DESTROY]
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
            "kubectl scale deploy web --replicas=3",
            "kubectl scale --replicas 2 deploy/web",
            "kubectl scale deploy web --replicas=0 --dry-run=client",
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
            "helm uninstall api --dry-run",
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
            ("kubectl delete pod web --dry-run=none", DESTROY),
            (
                "kubectl delete pod web --dry-run=client --dry-run=none",
                DESTROY,
            ),
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
            ("kubectl scale deploy web --replicas=0", DESTROY),
            ("kubectl scale --replicas=0 deploy/web", DESTROY),
            ("kubectl scale deploy web --replicas 0", DESTROY),
            ("kubectl scale deploy web --replicas=00", DESTROY),
            ("kubectl -n prod scale deploy web --replicas=0", DESTROY),
            ("kubectl scale deploy web --replicas=$N", Rule::Unknown),
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
            "terraform apply -destroy=false",
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
            "pulumi destroy --preview-only",
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
            "aws ec2 terminate-instances --instance-ids i-1 --dry-run",
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
            ("aws --profile prod s3 rm s3://b --recursive", DESTROY),
            ("aws s3 rb s3://bucket", DESTROY),
            ("aws s3 rb s3://bucket --force", DESTROY),
            ("aws s3 sync . s3://bucket --delete", DESTROY),
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
            "gcloud compute instances describe vm --zone us-central1-a",
            "gcloud compute instances create vm",
            "gcloud compute instances stop vm",
            "gcloud storage ls gs://bucket",
            "gcloud storage cp a gs://bucket",
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
            "doctl compute droplet list",
            "doctl compute droplet create web",
            "doctl auth remove --context x",
            "flyctl apps list",
            "flyctl deploy",
            "fly status",
            "vercel",
            "vercel deploy",
            "vercel ls",
            "vercel env ls",
            "heroku apps",
            "heroku logs --tail",
            "heroku apps:info -a x",
            "wrangler deploy",
            "wrangler dev",
            "wrangler tail",
            "wrangler kv namespace list",
            "firebase deploy",
            "firebase projects:list",
            "hcloud server list",
            "scw instance server list",
            "oci compute instance list",
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
            ("gcloud kms keys versions destroy 1 --key k", DESTROY),
            ("gcloud --format json compute instances delete vm", DESTROY),
            ("gsutil rm -r gs://bucket", DESTROY),
            ("gsutil -m rm -r gs://bucket/**", DESTROY),
            ("gsutil rm gs://bucket/obj", DESTROY),
            ("gsutil rb gs://bucket", DESTROY),
            ("gsutil -m rsync -d -r dir gs://bucket", DESTROY),
            ("gsutil rsync -dr dir gs://bucket", DESTROY),
            ("az group delete --name rg --yes", DESTROY),
            ("az group delete -n rg -y", DESTROY),
            ("az vm delete -g rg -n vm", DESTROY),
            ("az --subscription s group delete -n rg", DESTROY),
            ("az aks delete -g rg -n c", DESTROY),
            ("az storage blob delete -c c -n b", DESTROY),
            ("az storage blob delete-batch -s c", DESTROY),
            ("az keyvault purge -n kv", DESTROY),
            ("az resource delete --ids x", DESTROY),
            ("az sql db delete -g rg -s s -n d", DESTROY),
            ("doctl compute droplet delete web", DESTROY),
            ("doctl compute droplet delete web -f", DESTROY),
            ("doctl compute droplet d web", DESTROY),
            ("doctl -t $TOKEN compute droplet delete web", DESTROY),
            ("doctl kubernetes cluster delete c", DESTROY),
            ("doctl databases delete id", DESTROY),
            ("doctl apps delete id", DESTROY),
            ("flyctl apps destroy app", DESTROY),
            ("flyctl apps destroy app -y", DESTROY),
            ("fly apps destroy app", DESTROY),
            ("fly volumes destroy v", DESTROY),
            ("fly machine destroy m", DESTROY),
            ("fly machine rm m", DESTROY),
            ("fly -a app apps destroy app", DESTROY),
            ("vercel remove app", DESTROY),
            ("vercel rm app --yes", DESTROY),
            ("vercel project rm app", DESTROY),
            ("vercel --token $T remove app", DESTROY),
            ("vercel env rm KEY", DESTROY),
            ("heroku apps:destroy -a x --confirm x", DESTROY),
            ("heroku apps:destroy x", DESTROY),
            ("heroku apps destroy -a x", DESTROY),
            ("heroku addons:destroy db -a x", DESTROY),
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
            ("hcloud server delete web", DESTROY),
            ("scw instance server terminate s", DESTROY),
            ("scw instance server delete s", DESTROY),
            ("oci compute instance terminate --instance-id i", DESTROY),
            ("oci os bucket delete --name b", DESTROY),
            ("eksctl delete cluster --name c", DESTROY),
            ("eksctl delete nodegroup --cluster c --name n", DESTROY),
            ("kops delete cluster --name c --yes", DESTROY),
        ],
    );
}

#[test]
fn wrapped_in_something_else() {
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
        ],
        &[
            ("bash -c 'docker system prune -af'", DESTROY),
            ("sh -c \"kubectl delete namespace prod\"", DESTROY),
            ("env KUBECONFIG=x kubectl delete pod web", DESTROY),
            ("nohup terraform destroy -auto-approve &", DESTROY),
            ("time terraform destroy", DESTROY),
            ("cd infra && terraform destroy -auto-approve", DESTROY),
            ("terraform plan && terraform destroy -auto-approve", DESTROY),
            ("docker ps -aq | xargs docker rm -f", DESTROY),
            ("kubectl get ns -o name | xargs kubectl delete", DESTROY),
            ("/usr/local/bin/kubectl delete pod web", DESTROY),
            ("DOCKER_HOST=tcp://h:2375 docker system prune -af", DESTROY),
            (
                "for ns in a b; do kubectl delete namespace $ns; done",
                DESTROY,
            ),
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
    assert_eq!(
        rules("docker rm -f $name", Shell::PowerShell, &windows()),
        vec![DESTROY]
    );
    assert!(rules("docker rm -f \"$name\"", Shell::PowerShell, &windows()).is_empty());
    assert!(rules("docker rm -f $env:NAME", Shell::PowerShell, &windows()).is_empty());
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
fn a_flag_without_a_value_does_not_hide_the_command() {
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
        ],
        &[
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
        ],
    );
}

#[test]
fn pulumi_is_found_behind_its_own_stack_option() {
    check(
        Shell::Posix,
        &posix(),
        &[],
        &[
            ("pulumi --stack dev destroy --yes", DESTROY),
            ("pulumi -s dev destroy", DESTROY),
            ("pulumi --stack dev down", DESTROY),
            ("pulumi --stack=dev destroy", DESTROY),
            ("pulumi -s dev stack rm", DESTROY),
            ("pulumi --stack dev stack rm dev", DESTROY),
            ("pulumi --target urn:x destroy", DESTROY),
            ("pulumi -m msg -s dev destroy", DESTROY),
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

#[test]
fn a_variable_that_expands_to_several_words_is_computed() {
    check(
        Shell::Posix,
        &posix(),
        &["docker rm -f \"$name\"", "docker rm -f \"$*\""],
        &[
            ("docker rm -f \"$@\"", DESTROY),
            ("docker rm -f \"${@}\"", DESTROY),
            ("docker rm -f \"${ids[@]}\"", DESTROY),
            ("docker rm \"$@\"", DESTROY),
            ("docker rm -f ${ids[@]}", DESTROY),
        ],
    );
    check(
        Shell::PowerShell,
        &windows(),
        &[
            "docker rm -f \"$ids\"",
            "docker rm -f $env:NAME",
            "docker rm -f web",
        ],
        &[
            ("docker rm -f $ids", DESTROY),
            ("docker rm $ids", DESTROY),
            ("docker rm -f @ids", DESTROY),
            ("docker rm -f $containers.Id", DESTROY),
            ("$ids = docker ps -aq; docker rm -f $ids", DESTROY),
        ],
    );
    check(
        Shell::Cmd,
        &windows(),
        &["docker rm -f \"%IDS%\"", "docker rm -f web"],
        &[
            ("docker rm -f %IDS%", DESTROY),
            ("docker rm %IDS%", DESTROY),
            ("docker rm -f !IDS!", DESTROY),
        ],
    );
}

#[test]
fn a_rehearsal_turned_off_is_not_one() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "pulumi destroy --preview-only",
            "pulumi destroy --yes --preview-only=true",
            "helm uninstall api --dry-run",
            "helm uninstall api --dry-run=true",
        ],
        &[
            ("pulumi destroy --yes --preview-only=false", DESTROY),
            ("pulumi destroy --preview-only=false", DESTROY),
            (
                "pulumi destroy --preview-only --preview-only=false",
                DESTROY,
            ),
            ("helm uninstall api --dry-run=false", DESTROY),
            ("helm uninstall api --dry-run --dry-run=false", DESTROY),
        ],
    );
}

#[test]
fn flyctl_aliases_are_read() {
    check(
        Shell::Posix,
        &posix(),
        &[
            "fly apps list",
            "fly machine list",
            "fly m list",
            "fly vol list",
        ],
        &[
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
        ],
    );
}

#[test]
fn the_reason_for_an_unknown_command_reads_right() {
    for (line, expected) in [
        (
            "aws $service",
            "runs an aws command only known when it runs",
        ),
        ("az $x", "runs an az command only known when it runs"),
        ("oc $x", "runs an oc command only known when it runs"),
        ("oci $x", "runs an oci command only known when it runs"),
        (
            "eksctl $x",
            "runs an eksctl command only known when it runs",
        ),
        ("sst $x", "runs an sst command only known when it runs"),
        ("gcloud $x", "runs a gcloud command only known when it runs"),
    ] {
        let assessment = classify(line, Shell::Posix, &posix());
        let findings = assessment.findings();
        assert_eq!(findings.len(), 1, "{line}: {findings:?}");
        assert_eq!(findings[0].rule, Rule::Unknown, "{line}");
        assert_eq!(findings[0].reason, expected, "{line}");
    }
}
