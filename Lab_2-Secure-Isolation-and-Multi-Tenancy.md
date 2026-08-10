# IKB42603 - Lab 2: Secure Isolation & Multi-Tenancy

| Item | Details |
| --- | --- |
| Course | IKB42603 - Cloud Computing Security Essentials |
| Lab | Lab 2 - Secure Isolation & Multi-Tenancy |
| Student name | Muhammad Adli Firdaus |
| Student ID | 52215225178 |
| Operating System | Kali Linux (VMware Workstation) |
| Date completed | 9 August 2026 |

## Objective

This lab demonstrates isolation across the three dimensions of shared cloud infrastructure - **compute**, **network**, and **storage** - using Docker and Kubernetes. The lab is split into two sessions:

- **Session A** models two tenants sharing one cluster and exposes the *default-open* risk of shared infrastructure - by default, nothing stops one tenant's workloads from reaching another's.
- **Session B** applies the controls that close that gap: a default-deny NetworkPolicy, RBAC-scoped secret access, and an examination of data remanence with secure deletion.

By the end of this lab, the following outcomes are demonstrated:
1. Compute isolation via separate Kubernetes namespaces per tenant.
2. The default-open behaviour of shared infrastructure, and why it is a risk.
3. Network isolation enforced with a default-deny NetworkPolicy, proven with a before/after test.
4. Storage isolation, so one tenant cannot read another tenant's secrets.
5. Data remanence, and a demonstration of secure deletion.

## Session A (Week 3) - Compute Isolation & the Default-Open Risk

### Cluster Setup with Policy Enforcement (Calico)

The default `kind` network does not enforce NetworkPolicy, so the cluster was created with the default CNI disabled, and **Calico** was installed in its place - Calico is a CNI that actually enforces NetworkPolicy rules at the network layer.

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

The cluster `ccse-lab2` was created successfully, with the `kubectl` context automatically set to `kind-ccse-lab2`.

![kind cluster ccse-lab2 created with Calico-ready config](Evidence-Lab2/Screenshot%202026-08-09%20212025.png)

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

The Calico manifest was applied, creating all required CRDs, ClusterRoles, ClusterRoleBindings, the `calico-node` DaemonSet, and the `calico-kube-controllers` Deployment.

![Calico manifest applied - all resources created](Evidence-Lab2/Screenshot%202026-08-09%20212034.png)

```bash
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

The rollout completed successfully, confirming Calico's networking components were fully up and ready to enforce policy across the cluster.

![Calico DaemonSet successfully rolled out](Evidence-Lab2/Screenshot%202026-08-09%20212042.png)

### Task 1 - Two Tenants on One Cluster

Two namespaces, `tenant-a` and `tenant-b`, were created to model two customers sharing the same physical infrastructure. An `nginx` deployment was created and exposed as a Service in each.

```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b

kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80

kubectl get pods,svc -n tenant-a
```

Both namespaces were created, both deployments reached a `Running` state, and both Services were assigned a ClusterIP (`tenant-a`'s Service confirmed at `10.96.107.12`).

![tenant-a and tenant-b namespaces, deployments, and services created](Evidence-Lab2/Screenshot%202026-08-09%20221030.png)

### Task 2 - Observe the Default-Open Risk

To prove that pods in one namespace can reach pods in another by default, a disposable test pod was launched in `tenant-a` to `curl` `tenant-b`'s Service directly.

```bash
B_IP=$(kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}')
echo $B_IP
```

`tenant-b`'s ClusterIP resolved to `10.96.218.224`.

Because the `tenant-a-quota` ResourceQuota (see Task 3) requires every pod to explicitly declare CPU/memory requests, the probe pod was defined via a manifest rather than `kubectl run` directly, so that resource requests could be specified:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: probe
  namespace: tenant-a
spec:
  containers:
  - name: probe
    image: curlimages/curl
    command: ["curl", "-s", "-m", "5", "http://$B_IP", "-o", "/dev/null", "-w", "HTTP %{http_code}\n"]
    resources:
      requests:
        cpu: "50m"
        memory: "32Mi"
  restartPolicy: Never
EOF

sleep 5
kubectl logs probe -n tenant-a
```

The probe returned **HTTP 200** - confirming that `tenant-a` successfully reached `tenant-b`'s web server across the namespace boundary. This is the multi-tenancy risk being demonstrated: on shared infrastructure, isolation is **not automatic** and must be explicitly configured.

![Probe pod confirms HTTP 200 - tenant-a can reach tenant-b (before isolation)](Evidence-Lab2/Screenshot%202026-08-09%20222846.png)

### Task 3 - Contain the Noisy Neighbour (Resource Quotas)

Isolation also applies to resource consumption. A `ResourceQuota` was applied to `tenant-a` to cap its CPU, memory, and pod count, preventing it from exhausting the shared node.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

kubectl describe resourcequota tenant-a-quota -n tenant-a
```

The quota was applied and confirmed active, with current usage tracked against the hard limits (`pods: 1/5`, `requests.cpu: 0/1`, `requests.memory: 0/512Mi` at the time of creation).

![ResourceQuota tenant-a-quota created and confirmed via describe](Evidence-Lab2/Screenshot%202026-08-09%20221244.png)

*End of Session A. The HTTP 200 result from Task 2 was retained for direct comparison against Session B's "after" test.*

## Session B (Week 4) - Network & Storage Isolation

### Task 4 - Default-Deny Network Isolation

A default-deny `NetworkPolicy` was applied to `tenant-b`, denying all ingress traffic by default and permitting only what is explicitly allowed (none, in this case) - this is the core segmentation principle: **deny by default, permit by exception**.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

The **same probe** from Task 2 was re-run against the same `tenant-b` ClusterIP, using a new pod (`probe2`) to avoid clashing with the earlier one:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: probe2
  namespace: tenant-a
spec:
  containers:
  - name: probe
    image: curlimages/curl
    command: ["curl", "-s", "-m", "5", "http://$B_IP", "-o", "/dev/null", "-w", "HTTP %{http_code}\n"]
    resources:
      requests:
        cpu: "50m"
        memory: "32Mi"
  restartPolicy: Never
EOF

sleep 8
kubectl logs probe2 -n tenant-a
kubectl delete pod probe2 -n tenant-a
```

This time, the probe returned **HTTP 000** (connection timed out) - a direct contrast to the HTTP 200 result recorded before the policy was applied. This before/after pair is the strongest evidence that Calico is actively enforcing the NetworkPolicy and that cross-tenant traffic is now blocked.

![NetworkPolicy applied and re-run probe returns HTTP 000 (blocked)](Evidence-Lab2/Screenshot%202026-08-09%20223130.png)

**Before vs. After Summary**

| Test | Result |
| --- | --- |
| Before `default-deny-ingress` (Task 2) | HTTP 200 (reachable) |
| After `default-deny-ingress` (Task 4) | HTTP 000 (blocked / timed out) |

### Task 5 - Storage & Secret Isolation

A Secret was created in each tenant's namespace, and a service account scoped **only** to `tenant-a` was tested against both namespaces to prove that RBAC enforces secret-level storage isolation.

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

| Check | Result | Explanation |
| --- | --- | --- |
| `get secrets` in `tenant-a` | **yes** | The `reader` Role explicitly grants `get` on secrets, bound to `app-a` within `tenant-a` |
| `get secrets` in `tenant-b` | **no** | The RoleBinding only exists in `tenant-a`; RBAC is namespace-scoped and denies by default outside that scope |

This confirms that even though both tenants' secrets exist on the same underlying cluster storage, RBAC prevents `tenant-a`'s service account from ever reading `tenant-b`'s secret.

![Secrets created per tenant; auth can-i confirms tenant-a can read its own secret but not tenant-b's](Evidence-Lab2/Screenshot%202026-08-09%20223235.png)

### Task 6 - Data Remanence & Secure Deletion

This task demonstrates that a normal file delete does not necessarily erase the underlying data from disk (**data remanence**), and contrasts it with a secure overwrite-before-delete approach.

**Part 1 - Normal delete (remanence check):**

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

A file containing the string `SENSITIVE-PATIENT-RECORD` was created inside the `ccse-vol` volume, deleted with a normal `rm`, and the volume was then scanned for the string. The scan completed (`scan-done`) without producing a positive match in this run, but the exercise establishes the underlying mechanism: `rm` only removes the filesystem's directory entry/pointer to the data - it does not guarantee the underlying disk blocks are overwritten, meaning residual data can, in general, still be recoverable by lower-level disk/forensic tools until those blocks are reused or explicitly overwritten.

![Remanence check - file created, deleted normally, and volume scanned](Evidence-Lab2/Screenshot%202026-08-09%20223307.png)

**Part 2 - Secure wipe (overwrite before delete):**

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
  echo wiped'
```

This time, before deletion, the file's contents were explicitly overwritten with zero-bytes using `dd`, and only then deleted - this is the "shred before delete" pattern, which reduces the chance of the original sensitive content being recoverable from the underlying storage block, unlike a plain `rm`.

*[SCREENSHOT PLACEHOLDER - secure wipe `dd` command output. Not available for this submission; command and expected output ("wiped") documented above from the executed command.]*

> **Cloud context note (per the lab manual):** In real cloud storage, customers typically do not control the physical storage blocks - they are abstracted, virtualised, and shared across many tenants by the provider. Because of this, directly overwriting physical media is often not possible or verifiable in the cloud. The practical, provider-agnostic answer to remanence in the cloud is therefore **cryptographic erasure**: encrypt data at rest, and "delete" it by destroying the encryption key, rendering the remaining ciphertext computationally infeasible to recover - covered in Lab 3.

## Verification Commands

```bash
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

*[SCREENSHOT PLACEHOLDER - verification command output. Not available for this submission; `default-deny-ingress` in `tenant-b` was already confirmed active in Task 4 above, and the `tenant-a-quota` ResourceQuota was already confirmed active in Task 3 above.]*

## Short-Answer Questions

**Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?**

By default, all pods in a Kubernetes cluster share one flat network, so pods can reach each other across namespaces regardless of tenant. This is dangerous in multi-tenant cloud because a compromised workload from one tenant could directly access or attack another tenant's services.

**Q2. Explain the default-deny principle and how your NetworkPolicy implements it.**

Default-deny means blocking all traffic by default and only allowing what is explicitly permitted. My NetworkPolicy implements this using podSelector: {} (all pods) with policyTypes: [Ingress] and no allow rules, so no incoming traffic is permitted into tenant-b.

**Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?**

VMs have stronger isolation because each runs its own OS kernel, so a compromised VM can't easily affect others. Containers share the host kernel, making them lighter but less isolated. A VM boundary should be used when running untrusted or highly sensitive workloads that need stronger separation.

**Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?**

Data remanence is when deleted data still physically remains on disk and can be recovered, since delete usually just removes the file pointer, not the actual bytes. Cryptographic erasure is preferred in the cloud because customers don't control physical storage - destroying the encryption key instantly makes the data unrecoverable without needing disk access.

**Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?**

| Task | Isolation Dimension |
| --- | --- |
| Task 1 - Two tenants, separate namespaces | Compute |
| Task 2 - Default-open cross-tenant probe | Network |
| Task 3 - ResourceQuota | Compute |
| Task 4 - Default-deny NetworkPolicy | Network |
| Task 5 - Secret isolation via RBAC | Storage |
| Task 6 - Data remanence & secure deletion | Storage |

## Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces (`tenant-a`, `tenant-b`)
- [x] A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after: HTTP 200 → HTTP 000)
- [x] Resource quotas prevent a noisy-neighbour from exhausting shared capacity (`tenant-a-quota`)
- [x] Per-tenant secrets are unreadable by other tenants (RBAC enforced: `yes`/`no` via `auth can-i`)
- [x] Secure deletion / cryptographic erasure is understood for data remanence

## Conclusion

Lab 2 demonstrated isolation across all three dimensions of shared cloud infrastructure. Compute isolation was established through separate namespaces and enforced through a ResourceQuota preventing resource exhaustion by a single tenant. Network isolation was directly proven with a before/after test: cross-tenant traffic succeeded (HTTP 200) on the default, unprotected cluster, and was blocked (HTTP 000) once a default-deny NetworkPolicy was applied via Calico - confirming that isolation on shared infrastructure is not automatic and must be explicitly configured. Storage isolation was verified through RBAC-scoped access to per-tenant Secrets, and the concept of data remanence was examined, with cryptographic erasure identified as the practical solution for cloud environments where physical storage is abstracted away from the customer. Together, these results confirm that Docker- and Kubernetes-based multi-tenancy can be made secure, but only through explicit, deliberate isolation controls at every layer.
