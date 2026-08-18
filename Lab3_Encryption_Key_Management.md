# Lab 3 — Data Protection: Encryption & Key Management

**Course:** IKB42603 – Cloud Computing Security Essentials
**Weeks:** 5–6 · Sessions A & B
**Environment:** Kali Linux (VMware Workstation)
**Tools Used:** OpenSSL, Docker, LocalStack KMS, AWS CLI v2

> **Note on redaction:** All KMS Key IDs, ARNs, and generated data-key material (plaintext and wrapped) shown in the evidence below have been redacted (black boxes) before inclusion in this report. This is standard practice when documenting cryptographic material — even in a sandboxed LocalStack lab environment, key identifiers and key material should not be published in plaintext in a shared or submitted document. The surrounding commands and system responses remain fully visible to demonstrate the workflow and outcome of each step.

---

## Session A (Week 5) — Encryption Fundamentals

### Task 1 — Symmetric Encryption (AES-256)

A sample record was encrypted and decrypted using AES-256-CBC. The encrypted file was confirmed unreadable, and the decrypted output matched the original exactly.

![Task 1 — AES symmetric encryption and decryption](images/task1-aes-symmetric.png)

**Result:** `MATCH: decryption successful`

---

### Task 2 — Asymmetric Encryption & Digital Signatures

A 2048-bit RSA key pair was generated. The record was encrypted with the public key and decrypted with the private key. A digital signature was then created with the private key and verified with the public key.

![Task 2 — RSA asymmetric encryption and signature verification](images/task2-rsa-asymmetric.png)

**Result:** `Verified OK`

---

### Task 3 — Encryption in Transit (TLS)

A self-signed TLS certificate was generated. After an initial failed attempt using an unconfigured `nginx` container (which does not serve HTTPS by default without additional configuration), the file was instead served using OpenSSL's built-in `s_server`, and retrieved successfully over an encrypted HTTPS channel.

![Task 3 — File served and retrieved over TLS](images/task3-tls-success.png)

**Result:** File content received successfully via `curl -k https://localhost:8443/record.txt`, confirming the channel was encrypted and functional.

**Session A cleanup:**

![Stopping the OpenSSL TLS server and confirming Session A files](images/session-a-cleanup.png)

---

## Session B (Week 6) — Key Management, Envelope Encryption & Erasure

### Task 4 — Create and Use a KMS Master Key

A customer master key (CMK) was created in LocalStack KMS for tenant A, and used to directly encrypt a small plaintext value.

![Task 4 — Creating the tenant-A master key](images/task4-create-key-tenantA.png)

![Task 4 — Encrypting data directly with the master key](images/task4-kms-encrypt.png)

---

### Task 5 — Envelope Encryption

A data key was generated via `kms generate-data-key`, returning both a plaintext copy and a copy wrapped (encrypted) by the master key. The plaintext copy was used locally to encrypt the record with OpenSSL, then deleted from disk — leaving only the wrapped copy (`datakey.enc`).

![Task 5 — Generating the data key](images/task5-generate-datakey.png)

![Task 5 — Full envelope encryption workflow: wrapping, local encryption, and plaintext-key cleanup](images/task5-envelope-encryption-full.png)

**Result:** After cleanup, only `datakey.enc` (the KMS-wrapped data key) and `record.env.enc` (the envelope-encrypted record) remained on disk. The plaintext data key (`datakey.bin`, `datakey.b64`) no longer existed.

---

### Task 6 — Per-Tenant Keys & Cryptographic Erasure

A second, separate master key was created for tenant B, demonstrating key isolation between tenants.

![Task 6 — Creating the tenant-B master key](images/task6-create-key-tenantB.png)

Tenant A's key was then scheduled for deletion. LocalStack correctly rejected a subsequent `disable-key` call, since the key was already in the more advanced `PendingDeletion` state.

![Task 6 — Scheduling deletion of the tenant-A key](images/task6-schedule-deletion-disable.png)

An attempt was then made to decrypt the wrapped data key (`datakey.enc`) — which depends on tenant A's now-deleted-pending master key.

![Task 6 — Failed decrypt attempt after key erasure](images/task6-decrypt-fail-erasure.png)

**Result:** The decrypt operation failed with `KMSInvalidStateException`, confirming that once the wrapping master key is disabled/pending deletion, the wrapped data key — and therefore the data it protects — is permanently unrecoverable. This demonstrates **cryptographic erasure**.

---

### Task 7 — Integrity & Tamper-Evidence

The SHA-256 hash of the original record was computed, then compared against a tampered copy to demonstrate that even a single-character change produces a completely different hash.

![Task 7 — SHA-256 hash comparison, original vs. tampered file](images/task7-hash-tamper.png)

A simple hash chain was then constructed, where each log entry's hash incorporates the previous entry's hash — making the sequence tamper-evident.

![Task 7 — Hash chain of sequential log entries](images/task7-hash-chain.png)

---

## Verification

```bash
aws --endpoint-url=http://localhost:4566 kms list-keys
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

![Verification — KMS keys listed and RSA signature verified](images/verification-kms-listkeys.png)

**Result:** Both tenant-A and tenant-B master keys are listed in LocalStack KMS, and the RSA signature verification returns `Verified OK`.

---

## Short-Answer Questions

**1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.**

Symmetric encryption (e.g. AES) uses a single shared key for both encryption and decryption. It is computationally fast and well-suited for encrypting large volumes of data, but it carries a key-distribution problem: the same key must reach every party who needs to decrypt, and if that key is intercepted in transit, confidentiality is fully compromised. Asymmetric encryption (e.g. RSA) uses a mathematically linked key pair — a public key for encryption and a private key for decryption — so no shared secret ever needs to travel between parties. This solves the distribution problem, but asymmetric operations are significantly slower and less efficient for large data. In practice, the two are combined: asymmetric encryption is used to securely exchange a symmetric key, which then handles the bulk data encryption — this is exactly the principle behind TLS and the envelope-encryption pattern demonstrated in Task 5.

**2. Why is key management described as the weakest link, not the algorithm?**

Modern encryption algorithms such as AES-256 and RSA-2048 are computationally infeasible to break directly with current technology. In practice, breaches almost always occur not because the algorithm was broken, but because the key itself was mishandled — stored in plaintext, hardcoded in source code, over-shared, never rotated, or left accessible after it should have been revoked. An attacker who obtains the key does not need to attack the mathematics at all. This lab illustrated the point directly: the cryptographic strength of AES-256 in Task 1 was irrelevant to how safely the passphrase was handled, and in Task 6, security was enforced not by defeating the algorithm but by controlling access to the key itself. This is why cloud security practice places heavy emphasis on key management services, access policies, and key lifecycle control rather than algorithm selection.

**3. Explain envelope encryption and why only the master key needs hardware-grade protection.**

Envelope encryption separates the roles of "protecting data" and "protecting the key that protects data." Instead of encrypting large data directly with a master key, a KMS generates a one-time data key, which is used locally to encrypt the actual data. The data key is then itself encrypted ("wrapped") by the master key and stored alongside the encrypted data, while the plaintext data key is discarded immediately after use — exactly as demonstrated in Task 5. This means the master key never leaves the KMS and never directly touches large volumes of data; it only ever wraps and unwraps small data keys on demand. Because the master key is the single point that, if compromised, would expose every data key it has ever wrapped, it is the one component that justifies the cost of hardware-grade protection (e.g. an HSM). Data keys, by contrast, are numerous, short-lived, and individually low-value, so they do not need the same level of protection.

**4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?**

In a cloud environment, the physical storage medium is virtualized, replicated across multiple disks, and often abstracted away entirely from the tenant — so there is no reliable way to overwrite every physical copy of a piece of data, and a provider (or attacker with sufficient access) could still recover it from an underlying replica or backup. Cryptographic erasure sidesteps this problem entirely: if data was encrypted with a per-tenant key, and that key is deleted or disabled, the ciphertext becomes permanently unrecoverable — regardless of how many physical copies of the ciphertext still exist — because there is no key left to reverse the encryption. Task 6 demonstrated this directly: disabling/scheduling deletion of tenant A's master key made the wrapped data key, and therefore the data it protected, provably and permanently inaccessible, without needing to touch or overwrite the underlying storage at all.

**5. How does a hash chain make a log tamper-evident?**

A hash chain links each log entry to the one before it by including the previous entry's hash as part of the input to the current entry's hash calculation. This means every entry's hash is dependent on the entire history that came before it. If an attacker alters, deletes, or reorders any single entry in the log, that entry's hash changes — and because every subsequent entry's hash was computed using the now-incorrect previous hash, the entire chain from that point forward no longer matches its recorded values. This was shown in Task 7, where a simple loop chained three log entries together using each iteration's SHA-256 output as the seed for the next. Anyone verifying the log can recompute the chain and immediately detect at which point it was broken, making silent tampering effectively impossible without also being detected.

---

## Security Best-Practices Checklist

- [x] Data encrypted at rest (AES) and decryption verified.
- [x] Asymmetric keys used correctly (encrypt with public, sign with private).
- [x] Data protected in transit with TLS.
- [x] Envelope encryption used; plaintext data key not left on disk.
- [x] Per-tenant keys used; cryptographic erasure demonstrated.
- [x] Integrity verified with hashing / hash chain.

---

## Cleanup & Teardown

```bash
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt
docker stop localstack && docker rm localstack
```
