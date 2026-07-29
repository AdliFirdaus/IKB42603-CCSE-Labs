# IKB42603 - Lab 0: Environment Setup Report

| Item | Details |
| --- | --- |
| Course | IKB42603 - Cloud Computing Security Essentials |
| Lab | Lab 0 - Environment Setup |
| Student name | Muhammad Adli Firdaus |
| Student ID | 52215225178 |
| Operating System | Kali Linux (VMware Workstation) |
| Date completed | 29 July 2026 |

## Objective

The objective of this exercise is to prepare and verify the local lab environment required before starting Lab 1. Based on the IKB42603 Lab 0 Setup Cheatsheet, the environment must support the following components:

- **Docker** - runs containers and the LocalStack cloud simulator
- **AWS CLI v2** - sends AWS-style commands to LocalStack
- **kind** - runs a local Kubernetes cluster inside Docker
- **kubectl** - controls the Kubernetes cluster
- **OpenSSL** - encryption, keys, and certificates (used in Lab 3)
- **oathtool** - generates MFA/TOTP codes (used in Lab 4)

All services in this setup run entirely locally, with no real cloud account or credit card required. LocalStack is used as a local AWS-compatible simulator, and `kind` (Kubernetes-in-Docker) is used to run a Kubernetes cluster inside Docker.

## Environment Summary

| Component | Verified Version / Status | Evidence |
| --- | --- | --- |
| Docker | Docker Engine `28.5.2`; `hello-world` container ran successfully | Step 1 |
| AWS CLI | `aws-cli/2.36.9`, Python `3.14.6`, Kali Linux | Step 2 |
| kind | `kind version 0.23.0` | Step 3 |
| kubectl | Client `v1.36.3`, Kustomize `v5.8.1` | Step 3 |
| OpenSSL | `OpenSSL 3.6.3` | Step 4 |
| oathtool | OATH Toolkit `2.6.14` | Step 4 |
| LocalStack | Running and healthy on port `4566` (image `localstack:3.0`, version `3.0.2`) | Step 5-6 |
| Kubernetes (kind) | Cluster `ccse-lab1` running; node `ccse-lab1-control-plane` in `Ready` state | Step 7 |
| AWS CLI - LocalStack integration | Dummy credentials configured; `sts get-caller-identity` returned test identity | Step 8 |

## Evidence and Results

### Step 1 - Install and Verify Docker

Docker is required to run containers, the LocalStack simulator, and the `kind` Kubernetes cluster. On Kali Linux (Debian-based), Docker was installed using the official Docker APT repository rather than the convenience script, to ensure a stable, repository-tracked installation:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

Installation was verified with:

```bash
docker --version
docker run --rm hello-world
```

Docker Engine reported version `28.5.2`. The `hello-world` container was then run with automatic removal enabled (`--rm`), and the container returned the standard **"Hello from Docker!"** confirmation message. This confirms that the Docker client, daemon, image pull, and container execution pipeline are all functioning correctly end-to-end.

![Docker version and hello-world verification](<Screenshot 2026-07-29 192503.png>)

### Step 2 - Install and Verify AWS CLI v2

AWS CLI v2 is required to issue AWS-style commands against LocalStack in later labs (no real AWS account is needed). It was installed using the official Linux ZIP package:

```bash
curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o awscliv2.zip
unzip awscliv2.zip && sudo ./aws/install
```

Verification:

```bash
aws --version
```

The system reported **AWS CLI version 2.36.9**, running on Python `3.14.6` under Kali Linux (`kali-amd64`). This confirms the CLI binary is correctly installed and resolvable on the system `PATH`.

![AWS CLI version verification](<Screenshot 2026-07-29 192538.png>)

### Step 3 - Install and Verify Kubernetes Tools (kind and kubectl)

`kind` provisions a disposable Kubernetes cluster inside Docker, while `kubectl` is the client used to interact with that cluster. Both were installed as follows:

```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.23.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

sudo apt-get update
sudo apt-get install -y kubectl
```

Verification:

```bash
kind --version
kubectl version --client
```

`kind` reported **version 0.23.0**. `kubectl` reported **client version v1.36.3** with **Kustomize version v5.8.1** bundled. Both tools are confirmed installed and callable from the terminal, ready to provision and manage the local cluster used in Lab 1 Session B.

![kind and kubectl verification](<Screenshot 2026-07-29 192607.png>)

### Step 4 - Verify OpenSSL and OATH Toolkit

OpenSSL provides the cryptographic primitives (keys, certificates, encryption) used later in Lab 3, while `oathtool` generates MFA/TOTP codes used in Lab 4. Both ship as standard packages on Kali Linux and required no separate installation beyond the base OS image, aside from `oathtool` which was installed via:

```bash
sudo apt install oathtool -y
```

Verification:

```bash
openssl version
oathtool --version
```

**OpenSSL 3.6.3** and **OATH Toolkit 2.6.14** were both confirmed available, satisfying the prerequisite tooling for the cryptography- and authentication-focused labs later in the course.

![OpenSSL and OATH Toolkit verification](<Screenshot 2026-07-29 192634.png>)

### Step 5 - Start and Validate LocalStack

LocalStack provides a local, AWS-API-compatible environment so that IAM, KMS, and CloudWatch Logs commands in later labs can be issued without a real AWS account. Because the current public `latest` tag of LocalStack requires a paid license (verified during setup, where `docker run` against `latest` failed with a "License activation failed" error), the environment was instead pinned to the last free Community Edition tag:

```bash
docker run -d --name localstack -p 4566:4566 -p 4510-4559:4510-4559 localstack/localstack:3.0
curl http://localhost:4566/_localstack/health
```

Port `4566` exposes the main LocalStack gateway (the single endpoint used for all AWS service calls), while the `4510-4559` range exposes LocalStack's external service ports. The health endpoint returned a JSON response listing all available emulated AWS services and confirmed **LocalStack version 3.0.2** was running, indicating the simulator started successfully and is ready to accept AWS CLI requests.

![LocalStack startup and health check](<Screenshot 2026-07-29 192718.png>)

### Step 6 - Confirm Running Containers

Container status was confirmed with:

```bash
docker ps
```

The output confirmed **two containers running concurrently**: the `kind` control-plane container (from Step 7) and the `localstack/localstack:3.0` container. LocalStack was reported as **healthy**, with port `4566` correctly published and mapped to the host, confirming the container is reachable from outside Docker's internal network.

![Docker containers running](<Screenshot 2026-07-29 192742.png>)

### Step 7 - Create and Verify the kind Cluster

A local, disposable Kubernetes cluster named `ccse-lab1` was created inside Docker:

```bash
kind create cluster --name ccse-lab1
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

Cluster creation completed successfully, with `kind` reporting each provisioning stage (node image preparation, control-plane startup, CNI installation, and StorageClass installation) as successful. `kubectl cluster-info` confirmed the Kubernetes control plane and CoreDNS were both reachable at `127.0.0.1`, and `kubectl get nodes` confirmed the single node `ccse-lab1-control-plane` was in the **Ready** state, running Kubernetes `v1.30.0`.

![kind cluster creation and node verification](<Screenshot 2026-07-29 192855.png>)

### Step 8 - Configure AWS CLI for LocalStack

Since LocalStack accepts any credential values (it does not validate against a real AWS account), the AWS CLI was configured with dummy test credentials, and an endpoint variable was set to point all subsequent AWS CLI calls at the local LocalStack gateway instead of real AWS:

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

EP='--endpoint-url=http://localhost:4566'
aws $EP sts get-caller-identity
```

The `sts get-caller-identity` call returned the expected LocalStack test identity (`Account: 000000000000`, `Arn: arn:aws:iam::000000000000:root`), confirming that AWS CLI requests are correctly routed to and answered by LocalStack rather than real AWS infrastructure. This identity also serves as the baseline "root" identity referenced in Lab 1, before a dedicated least-privilege admin user is created.

![AWS CLI configured against LocalStack](<Screenshot 2026-07-29 193013.png>)

## Pre-Lab Verification Checklist

| Check | Status |
| --- | --- |
| `docker --version` prints a version, and `docker run hello-world` succeeds | Completed |
| `aws --version` prints `aws-cli/2.x` | Completed |
| `kind --version` and `kubectl version --client` both work | Completed |
| `openssl version` and `oathtool --version` both work | Completed |
| LocalStack starts and `curl .../health` responds | Completed |
| `docker ps` shows LocalStack as healthy | Completed |
| `kind create cluster` succeeds and `kubectl get nodes` shows a Ready node | Completed |
| `aws $EP sts get-caller-identity` returns an identity | Completed |
| Working inside a native Linux bash shell (Kali) | Completed |

## Troubleshooting Notes

One issue was encountered and resolved during this setup:

| Symptom | Cause | Resolution |
| --- | --- | --- |
| `docker run localstack/localstack:latest` failed with "License activation failed" (exit code 55) | The `latest` tag now defaults to LocalStack's paid Pro image, which requires a valid `LOCALSTACK_AUTH_TOKEN` | Container was recreated using the pinned free Community Edition tag `localstack/localstack:3.0` |
| Docker installation via `apt-get install docker-ce ...` initially failed with "Package not available" | The Docker APT repository line was generated using Kali's own `VERSION_CODENAME` (e.g. `kali-rolling`), which the official Docker Debian repository does not recognise | The repository source was corrected to explicitly reference the Debian codename `bookworm`, which Kali's package base is derived from |

## Conclusion

The Lab 0 environment was set up and fully verified on Kali Linux. Docker, AWS CLI v2, `kind`, `kubectl`, OpenSSL, and OATH Toolkit were all installed and confirmed functional. LocalStack is running, healthy, and reachable through the AWS CLI using dummy credentials, and the `ccse-lab1` `kind` Kubernetes cluster is running with a single control-plane node in the `Ready` state. All items on the Pre-Lab Verification Checklist have been satisfied, and the environment is ready for the Lab 1 (Cloud Account Security, Identity & Access Management) activities.
