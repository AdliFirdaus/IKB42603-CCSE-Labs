# Cloud Computing - Quiz Study Notes (Simple)

**Score:** 27/30

---

![Quiz Part 1](Quiz%20study/Screenshot%202026-08-04%20155819.png)

- Smallest deployable unit in Kubernetes → **Pod** (not Node)
- NOT a cloud characteristic → **Manual Provisioning**
- ARN service component (`arn:aws:s3:::my-bucket`) → **s3**

---

![Quiz Part 2](Quiz%20study/Screenshot%202026-08-04%20155832.png)

- List Kubernetes nodes → **kubectl get nodes**
- LocalStack purpose → **Simulates AWS services locally**
- A node is → **A worker machine**
- Docker mainly used to → **Run containers**

---

![Quiz Part 3](Quiz%20study/Screenshot%202026-08-04%20155849.png)

- Private + Public cloud combined → **Hybrid Cloud**
- Policies should attach to → **IAM Groups**
- Never create access keys for → **Root User**
- LocalStack default endpoint → **http://localhost:4566**

---

![Quiz Part 4](Quiz%20study/Screenshot%202026-08-04%20155909.png)

- Verify current AWS identity → **aws sts get-caller-identity**
- Unlimited privileges identity → **Root User**
- Service model, customer manages OS → **IaaS**
- Collection of IAM users → **IAM Group**

---

![Quiz Part 5](Quiz%20study/Screenshot%202026-08-04%20155922.png)

- ARN stands for → **Amazon Resource Name**
- Cloud computing refers to → *(quiz says "Buying more physical servers" - this looks wrong; real definition is "Delivering computing resources over the Internet")*
- Kubernetes cluster consists of → **Multiple nodes**
- IAM component with permissions → **IAM Policy**

---

![Quiz Part 6](Quiz%20study/Screenshot%202026-08-04%20155931.png)

- Access keys mainly used for → **Programmatic access**
- Most control deployment model → **Private Cloud**
- ARN component = account owner → *(quiz says "Resource ID" - this also looks wrong; should be "Account ID")*

---

![Quiz Part 7](Quiz%20study/Screenshot%202026-08-04%20155940.png)

- Google Docs example of → **SaaS**
- Auto grow/shrink characteristic → **Rapid Elasticity**
- Full admin AWS policy → **AdministratorAccess**
- Least privilege principle → **Principle of Least Privilege**

---

![Quiz Part 8](Quiz%20study/Screenshot%202026-08-04%20155952.png)

- Service model with VMs → **IaaS**
- Temporary IAM identity → **IAM Role**
- Tool for local K8s cluster → **kind**
- Compromised key, do first → **Deactivate or rotate the key**

---

## Quick Recap Table

| Term | Meaning |
| --- | --- |
| Pod | Smallest K8s unit |
| Node | Worker machine |
| kind | Creates local K8s cluster |
| LocalStack | Simulates AWS locally, port 4566 |
| Root User | Full access, never use daily |
| IAM Role | Temporary identity |
| IAM Group | Collection of users |
| IAM Policy | Contains permissions |
| Least Privilege | Only permissions needed |
| IaaS | You manage the OS |
| SaaS | Fully managed app (e.g. Google Docs) |
| Hybrid Cloud | Private + Public mix |
| Private Cloud | Most control |
