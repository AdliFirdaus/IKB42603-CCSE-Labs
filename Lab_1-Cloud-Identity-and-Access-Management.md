# IKB42603 - Lab 1: Cloud Account Security, Identity & Access Management

| Item | Details |
| --- | --- |
| Course | IKB42603 - Cloud Computing Security Essentials |
| Lab | Lab 1 - Cloud Account Security, Identity & Access Management |
| Student name | Muhammad Adli Firdaus |
| Student ID | 52215225178 |
| Operating System | Kali Linux (VMware Workstation) |
| Date completed | 29 July 2026 |

## Objective

This lab applies the principle of least privilege to both cloud identity (AWS IAM, via LocalStack) and container-orchestration identity (Kubernetes RBAC). By the end of the lab, the following outcomes are demonstrated:

1. A local cloud lab environment stood up using Docker and LocalStack (an AWS-compatible simulator).
2. Root usage replaced with scoped IAM users, groups, and policies, following the principle of least privilege.
3. Fine-grained permissions created and tested, distinguishing what an identity is *allowed* versus *denied* to do.
4. Role-Based Access Control (RBAC) implemented and verified in Kubernetes - the platform's actual enforcement engine.
5. Identity hygiene reasoned about through access key creation, listing, and rotation.

The lab is split into two sessions: **Session A** (Week 1) covers cloud identity using LocalStack IAM, and **Session B** (Week 2) covers enforced access control using Kubernetes RBAC.

## Task 1 - Cloud Identity Landscape

| Concept | AWS Term | Purpose |
| --- | --- | --- |
| All-powerful owner | Root user | Has unrestricted access to every resource and setting in the account. Should only be used for the initial account setup and a small number of account-level tasks (e.g. closing the account), never for day-to-day operations, since it cannot be scoped down. |
| Human/app identity | IAM User | Represents a single person or application that needs to interact with the account. Has its own long-term credentials (password and/or access keys) and its own set of permissions. |
| Permission bundle | IAM Policy | A JSON document that explicitly defines what actions are allowed or denied on which resources. Policies are the actual mechanism by which permissions are granted - users, groups, and roles have no permissions of their own until a policy is attached. |
| Collection of users | IAM Group | A container of IAM Users that share the same set of permissions. Policies are attached once to the group, and every member automatically inherits them, which keeps permission management consistent and auditable at scale. |
| Temporary identity | IAM Role | An identity with no long-term credentials that can be temporarily assumed by a user, application, or another AWS service. Used where credentials should not persist indefinitely, reducing the risk of long-term credential leakage. |

## Session A (Week 1) - Cloud Identity with LocalStack

### Environment Setup

LocalStack was started as a background Docker container, and confirmed healthy on port `4566` (see Lab 0 - Environment Setup Report, Steps 5-6, for full startup evidence).

### Task 2 - Create a Least-Privilege Admin (Stop Using Root)

The root identity was first confirmed, then a dedicated admin identity was created and granted permissions **through a group**, rather than directly on the user - so that permissions remain centrally managed rather than scattered across individual identities.

```bash
EP='--endpoint-url=http://localhost:4566'

# Confirm the current (root) operating identity
aws $EP sts get-caller-identity
```

The response confirmed the session was operating as the **root** identity (`Account: 000000000000`, `Arn: arn:aws:iam::000000000000:root`), establishing the baseline before least-privilege identities were introduced.

![Root identity via sts get-caller-identity](<Screenshot 2026-07-29 193013.png>)

```bash
# Create a group and attach the AdministratorAccess policy to the GROUP, not the user
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create a dedicated personal admin user
aws $EP iam create-user --user-name CloudAdmin_Adli

# Place the user inside the group, so permissions flow from the group
aws $EP iam add-user-to-group --group-name Admins --user-name CloudAdmin_Adli

# Verify membership
aws $EP iam get-group --group-name Admins
```

The `get-group` response confirmed **CloudAdmin_Adli** as a member of the **Admins** group, with the `AdministratorAccess` policy already attached at the group level. Attaching the policy to the group rather than the user means that any future admin identity can be granted the same permission set simply by joining the group, with no repeated policy attachment required.

![CloudAdmin_Adli group membership confirmed via get-group](<INSERT-SCREENSHOT-get-group-Admins.png>)

### Task 3 - Enforce Least Privilege with a Scoped Policy

A second, deliberately restricted identity was created to represent a teammate who should only be able to read data, never modify it - demonstrating fine-grained authorization.

```bash
# Create a read-only user
aws $EP iam create-user --user-name Analyst_Adli

# Attach a scoped, read-only policy (S3 read only)
aws $EP iam attach-user-policy --user-name Analyst_Adli \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# List what the user can do
aws $EP iam list-attached-user-policies --user-name Analyst_Adli
```

The response confirmed that **Analyst_Adli** has exactly one policy attached - `AmazonS3ReadOnlyAccess` - and nothing broader. This is the practical basis for blast-radius reduction: if this identity's credentials were compromised, the attacker would only be able to read S3 objects. They could not modify, delete, or exfiltrate-and-destroy data, create new IAM identities, alter permissions, or access any other AWS service, unlike a compromise of the `CloudAdmin_Adli` or root identity, which would grant unrestricted control over the entire account.

![Analyst_Adli read-only policy confirmed via list-attached-user-policies](<INSERT-SCREENSHOT-list-attached-user-policies.png>)

### Task 4 - Credential Hygiene & Access Key Rotation

Programmatic access to AWS relies on access keys rather than passwords. An access key was created for the Analyst identity, then rotated (deactivated) to demonstrate the credential-hygiene workflow expected of any long-lived secret.

```bash
# Create an access key for the Analyst
aws $EP iam create-access-key --user-name Analyst_Adli
```

The command returned a new **AccessKeyId** (`LKIAQAAAAAAADSFBHWHR`) with status `Active`.

![Access key created for Analyst_Adli](<INSERT-SCREENSHOT-create-access-key.png>)

```bash
# List access keys to confirm the key and its current status
aws $EP iam list-access-keys --user-name Analyst_Adli
```

The listing confirmed the key `LKIAQAAAAAAADSFBHWHR` in `Active` status.

![Access key listed as Active](<Screenshot_2026-07-29_193659.png>)

```bash
# Rotate: deactivate the key rather than deleting it outright
aws $EP iam update-access-key --user-name Analyst_Adli \
  --access-key-id LKIAQAAAAAAADSFBHWHR --status Inactive

# Confirm the rotation took effect
aws $EP iam list-access-keys --user-name Analyst_Adli
```

The follow-up listing confirmed the same key's status had changed from `Active` to `Inactive`, demonstrating that a key can be immediately revoked without deleting the identity itself - the standard first response to a suspected key leak, since it stops the key from authenticating while preserving an audit trail.

![Access key rotated to Inactive](<Screenshot_2026-07-29_193709.png>)

*End of Session A.*

## Session B (Week 2) - Enforced Access Control with Kubernetes RBAC

LocalStack demonstrates the mechanics of IAM, but does not itself enforce those permissions against real infrastructure. Kubernetes RBAC does enforce access control directly, so this session verifies access being genuinely blocked, not just declared.

### Cluster Setup

A disposable local Kubernetes cluster was created using `kind`:

```bash
kind create cluster --name ccse-lab1
```

Cluster provisioning completed successfully, with each stage (node image, control-plane startup, CNI installation, StorageClass installation) reported as successful, and the `kubectl` context automatically set to `kind-ccse-lab1`.

![kind cluster ccse-lab1 created](<Screenshot_2026-07-29_193309.png>)

```bash
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

The control plane and CoreDNS were confirmed reachable at `127.0.0.1`, and the single node `ccse-lab1-control-plane` was confirmed in the **Ready** state, running Kubernetes `v1.30.0`.

![Cluster info and node Ready state confirmed](<Screenshot_2026-07-29_193249.png>)

### Task 5 - Separate Environments with Namespaces

Namespaces were created to represent separate environments that should be isolated from one another:

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

Both `dev` and `prod` namespaces were confirmed as `Active`, alongside the cluster's default system namespaces.

![dev and prod namespaces created](<Screenshot_2026-07-29_193347.png>)

### Task 6 - Define a Role and Bind It (Least Privilege)

A Role scoped to read-only pod access within `dev` was created and bound to a dedicated service account representing a developer identity. In Kubernetes, a **Role** only defines a set of permissions; it grants nothing on its own until a **RoleBinding** attaches it to a specific subject.

```bash
# Create a service account to represent a developer
kubectl create serviceaccount dev-user -n dev

# Create a Role allowing only get/list/watch on pods, scoped to dev
kubectl create role pod-reader -n dev \
  --verb=get,list,watch --resource=pods

# Bind the Role to the service account
kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader --serviceaccount=dev:dev-user
```

All three objects - the ServiceAccount, the Role, and the RoleBinding - were confirmed created successfully.

![ServiceAccount, Role, and RoleBinding created](<Screenshot_2026-07-29_193451.png>)

### Task 7 - Test That Access Control Works

The `kubectl auth can-i` command was used to prove the permission boundary directly, rather than merely inspecting the configuration:

```bash
SA=system:serviceaccount:dev:dev-user

kubectl auth can-i list pods -n dev --as=$SA
kubectl auth can-i delete pods -n dev --as=$SA
kubectl auth can-i list pods -n prod --as=$SA
```

| Check | Result | Explanation |
| --- | --- | --- |
| `list pods` in `dev` | **yes** | Explicitly granted by the `pod-reader` Role |
| `delete pods` in `dev` | **no** | The Role's verb list (`get, list, watch`) does not include `delete` |
| `list pods` in `prod` | **no** | The RoleBinding only exists in the `dev` namespace; RBAC is namespace-scoped and denies by default outside that scope |

This confirms Kubernetes RBAC enforces least privilege at the platform level: the developer service account can do exactly what its Role permits, and nothing more, even within the same cluster.

The RoleBinding was also inspected directly to provide a definitive record of the applied configuration:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

The YAML output confirmed the `dev-user-binding` RoleBinding correctly references `Role: pod-reader` as its `roleRef` and `ServiceAccount: dev-user` in namespace `dev` as its subject.

![can-i results (yes/no/no) and RoleBinding YAML verification](<Screenshot_2026-07-29_193539.png>)

## Short-Answer Questions

**Q1. Why is attaching policies to groups better than attaching them directly to users?**

Attaching a policy to a group centralises permission management: a single policy change on the group propagates automatically to every member, rather than requiring the same change to be repeated on each individual user. This reduces the risk of inconsistent or drifted permissions across identities, makes access easier to audit (permissions can be reasoned about at the group level rather than user-by-user), and simplifies onboarding/offboarding, since adding or removing a user from a group instantly grants or revokes the group's permission set.

**Q2. What is the difference between an IAM User and an IAM Role?**

An IAM User is a persistent identity representing a specific person or application, with its own long-term credentials (a password and/or access keys) that remain valid until explicitly rotated or revoked. An IAM Role, in contrast, has no long-term credentials of its own; it is *assumed* temporarily by a user, application, or AWS service, and grants only short-lived, automatically-expiring security credentials for the duration of that session. Roles are therefore preferred wherever access does not need to persist indefinitely, since there is no long-lived secret that can be leaked or forgotten.

**Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.**

The `Analyst_Adli` account was deliberately scoped to only the `AmazonS3ReadOnlyAccess` policy - the minimum permission needed for its intended purpose. If this account's credentials were compromised, the attacker's actions would be limited strictly to reading S3 objects: they could not delete or modify data, create or alter IAM identities, provision new resources, or access any other AWS service. This is the essence of blast-radius reduction - the "radius" of possible damage from a compromised identity is bounded by exactly the permissions that identity was given, which is why the Analyst account was never granted anything beyond what its role actually required.

**Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?**

A Role is a namespaced object that defines *what* actions are permitted - a set of verbs (e.g. `get`, `list`, `watch`) on a set of resources (e.g. `pods`) - but does not, by itself, grant that permission to anyone. A RoleBinding is the object that actually grants a Role to a specific subject (a user, group, or ServiceAccount) within a namespace. A Role with no RoleBinding pointing to it grants no access at all; both objects must exist together for access to take effect.

**Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?**

The `dev-user-binding` RoleBinding was created only in the `dev` namespace, binding `pod-reader` solely to that scope. Kubernetes RBAC is namespace-scoped and denies by default: without an equivalent Role and RoleBinding explicitly created inside `prod`, no permissions exist there for that service account, so the request is denied. This demonstrates the principle of **least privilege combined with default-deny authorization** - an identity has no access anywhere except where it has been explicitly granted, so a permission boundary in one environment (`dev`) does not silently extend into another (`prod`), even within the same cluster.

## Security Best-Practices Checklist

- [x] Root user is not used for daily tasks (a dedicated admin identity, `CloudAdmin_Adli`, was created)
- [x] Permissions are granted via groups/roles, not directly to individual users
- [x] At least one least-privilege (read-only) identity was created and tested (`Analyst_Adli`)
- [x] Access keys were listed and a rotation (deactivation) was demonstrated
- [x] Kubernetes RBAC blocks an unauthorised action (delete pods, cross-namespace access)

## Conclusion

Lab 1 demonstrated the practical application of least privilege across two distinct layers of a cloud environment. At the AWS identity layer (via LocalStack), root usage was replaced with a dedicated administrator identity managed through a group, and a separately scoped read-only Analyst identity was created and tested, with its access keys rotated to reflect proper credential hygiene. At the container-orchestration layer, Kubernetes RBAC was configured and directly verified using `kubectl auth can-i`, confirming that a developer service account could read pods within its assigned namespace but was correctly denied both a destructive action (`delete`) and cross-namespace access (`prod`). Together, these results confirm that least privilege was enforced - not merely configured - at both the cloud identity and platform levels, satisfying the lab's core learning outcomes.
