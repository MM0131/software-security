# Worksheet 13 — Cloud & Container Security (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 13
> **Aligned to:** OWASP 2025 **A02 Security Misconfiguration** · **CWE-732** (incorrect permission assignment), **CWE-16** (configuration), plus CWE-798, CWE-250, CWE-538, CWE-269, CWE-1104
> **Signature game:** 🔍 *Misconfig Hunt* (CloudGoat-style) — each misconfig you find **and** fix = a flag.

> ⚠️ **Ethics note:** All artifacts here are deliberately broken for teaching and are marked *"Sandbox/teaching only; for authorized lab use."* Scan, exploit, and harden **only** these lab files (or systems you own / are authorized to test). Never point Trivy or these techniques at third-party cloud accounts or images without written permission.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
|Hathaichanok Yimjan|6631503045|26/10/2026|       |

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. Explain the **shared-responsibility model**. In `harden.md` it says "the cloud provider secures *of* the cloud; you secure what you put *in* it." Give one concrete example of each side for an S3-backed app.
Ans = The cloud provider secures of the cloud — the physical data centers, hardware, the hypervisor, the host OS, and the underlying S3/IAM services themselves. The customer secures what they put in the cloud — their own configuration choices. For an S3-backed app: the provider’s side is ensuring the physical S3 service infrastructure is patched and the hypervisor isolating tenants is sound; the customer’s side is setting the bucket’s access policy correctly (private by default), encrypting the objects, and writing an IAM policy that scopes access to only what the app actually needs rather than Resource:"*".

2. `iam-policy-insecure.json` uses `"Action": "*"` and `"Resource": "*"`. Describe **why this violates least privilege** and map it to CWE-732 vs CWE-269 — what is the difference between the two CWEs here?
Ans = This violates least privilege because the policy grants every possible action on every possible resource in the account, when the app realistically only needs to read a handful of objects in one S3 bucket — any compromise of this credential gives the attacker the same reach as a full account admin. The two CWEs map to the two different wildcards in the same statement: Resource:"*" is CWE-732 (Incorrect Permission Assignment for Critical Resource) because it’s the permission scope that’s wrong — the policy applies to resources it has no business touching. Action:"*" is CWE-269 (Improper Privilege Management) because it’s the capability granted that’s wrong — the identity is handed privileges (create, delete, modify) far beyond what its role requires. Trivy’s config scanner doesn’t parse standalone IAM JSON, so both of these have to be caught by manual review, not an automated rule.

3. The insecure Dockerfile bakes `ENV API_TOKEN=sk_live_...`. Explain how an attacker recovers that secret from a shipped image (name the `docker` commands) and why this is **CWE-798 / CWE-200**.
Ans = Once an image is built, any value baked in via ENV is stored as plaintext metadata in that layer’s image config — it doesn’t need to be “run” to be extracted. An attacker who gets the image (pulled from a registry, or just docker saved) can run docker history --no-trunc <image> to print every layer’s full build instruction, including the untruncated ENV API_TOKEN=sk_live_... line, or docker inspect <image> --format '{{.Config.Env}}' to dump the full environment list directly — no container execution required. This is CWE-798 (use of a hard-coded credential — the secret is embedded in build-time config rather than injected at runtime), CWE-526 (the secret is exposed through an environment variable that persists in a discoverable location), and CWE-200 (exposure of sensitive information to an unauthorized actor, since anyone who can pull the image can read the secret).

4. Why is `FROM python:latest` (CWE-1104/CWE-16) a security and reproducibility problem, and how does pinning to an `@sha256:` digest fix it?
Ans = :latest is a mutable tag — it can point to a different underlying image tomorrow than it does today, so the exact same Dockerfile can produce a different, unaudited base image on a later build without anyone changing a line of code. This breaks reproducibility (you can’t be sure what you tested is what you shipped) and security (a newly-pushed :latest could silently introduce a vulnerable or compromised base layer). Pinning to @sha256:<digest> fixes this because a digest is a cryptographic hash of the exact image content — it cannot be reassigned to point anywhere else, so FROM python@sha256:... guarantees the same bytes every single build, forever.

5. What does a **distroless** base image remove (relative to `python:3.11-slim`), and how does that shrink the attack surface for an RCE or container-escape attacker?
Ans = A distroless image strips out everything a full base image like python:3.11-slim still carries that isn’t strictly needed to run the app: no shell (/bin/sh, /bin/bash), no package manager (apt, pip at runtime), no general-purpose OS utilities (curl, wget, ls, etc.). This shrinks the attack surface for an RCE or container-escape attacker because even if they get code execution inside the container, there’s no shell to drop into, no package manager to pull in additional attacker tools, and far fewer binaries overall that could themselves contain exploitable vulnerabilities — the container simply can’t do much beyond running the one compiled application it ships with.

---

## Part 3 — Hands-on Lab (180 min)

**Learning goals:** find cloud/container misconfigurations with Trivy, map each to a CWE, and rebuild the IAM policy + Dockerfile to least privilege / hardened so the findings drop.

**Prerequisites:** Docker installed and running; the `week13-cloud-container/` lab folder; internet access to pull `aquasec/trivy:latest`.

### Environment setup (real commands)

```bash
cd labs/week13-cloud-container

# Option A — the provided wrapper (trivy config over the Dockerfiles; IAM JSON is reviewed manually, see Task 2):
bash scan.sh

# Option B — run Trivy directly (MEDIUM is in the filter on purpose: one of the
# three rules Task 1 asks you to cite is rated MEDIUM, and HIGH,CRITICAL hides it):
docker run --rm -v "$PWD:/src" aquasec/trivy:latest config --severity MEDIUM,HIGH,CRITICAL /src

# (Optional) build + CVE-scan the hardened image:
docker build -f Dockerfile.hardened -t week13-hardened:lab .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL week13-hardened:lab
```

**What to submit per task:** the command(s) you ran + the relevant output (finding count or the specific finding line), a screenshot of the Trivy/terminal result, and a 2–3 sentence mitigation explaining *why* the fix reduces risk (cite the CWE).

![The same app shipped as two stacked container images, Dockerfile.insecure beside Dockerfile.hardened, with each layer paired to its fix and its CWE, and only the unpinned :latest tag, the root user and the ENV secret marked as things trivy config actually flags.](img/container-hardening.svg)

### Tasks

- **Task 0 — Onboarding (15 min).** Confirm Docker works (`docker version`), run `bash scan.sh`, and record the **baseline finding count** against `Dockerfile.insecure` (Trivy's `config` scanner does not parse standalone IAM policy JSON, so `iam-policy-insecure.json` is reviewed manually instead — see Task 2). **Deliverable:** screenshot of the baseline scan.
Ans = Ans = Docker confirmed working (`docker version` — Client/Server both responding, Docker Desktop 4.91.0).

Baseline scan (`bash scan.sh`) against Dockerfile.insecure:

Report Summary
┌─────────────────────┬────────────┬───────────────────┐
│       Target        │    Type    │ Misconfigurations │
├─────────────────────┼────────────┼───────────────────┤
│ Dockerfile.hardened │ dockerfile │         0         │
├─────────────────────┼────────────┼───────────────────┤
│ Dockerfile.insecure │ dockerfile │         4         │
└─────────────────────┴────────────┴───────────────────┘

Baseline finding count: 4 (MEDIUM: 1, HIGH: 1, CRITICAL: 2)
- DS-0001 (MEDIUM): FROM python:latest — no tag pinned (line 11)
- DS-0002 (HIGH): no USER statement with non-root user
- DS-0031 (CRITICAL): API_TOKEN secret exposed in ENV (line 16)
- DS-0031 (CRITICAL): AWS_SECRET_ACCESS_KEY secret exposed in ENV (line 17)

Dockerfile.hardened already scans clean (0 findings), confirming it's the target state Task 4 will prove against.

![alt text](image.png)

![alt text](image-1.png)

- **Task 1 — Misconfig Hunt: container image (40 min).** *Goal:* find every defect in `Dockerfile.insecure`. *Steps:* read each `# DEFECT:` comment, then locate the matching Trivy finding where one exists — only 3 of the 6 (unpinned `:latest`, runs as root, secrets in `ENV`) map to a Trivy config rule (`DS-0001`, `DS-0002`, `DS-0031`); `COPY . .`, `chmod -R 777`, and unpinned `pip install` are instruction-level RUN/COPY semantics Trivy's Dockerfile scanner doesn't check, so identify those 3 by code review instead. Build a table: defect → CWE → Trivy rule/severity (write "manual review — no Trivy rule" where none exists). *Deliverable:* completed table (6 rows) using the IDs from `harden.md`.
Ans = Defect → CWE → Trivy mapping table

| # | Defect | Line | CWE | Trivy rule / severity |
|---|---|---|---|---|
| 1 | `FROM python:latest` — unpinned, non-reproducible base image | 11 | CWE-1104, CWE-16 | DS-0001 (MEDIUM) |
| 2 | `ENV API_TOKEN=sk_live_...` — hard-coded secret baked into image layer | 16 | CWE-798, CWE-200, CWE-16 | DS-0031 (CRITICAL) |
| 3 | `ENV AWS_SECRET_ACCESS_KEY=...` — hard-coded secret baked into image layer | 17 | CWE-798, CWE-200, CWE-16 | DS-0031 (CRITICAL) |
| 4 | `COPY . .` — copies entire build context (`.git`, `.env`, keys, CI files) into the image | 23 | CWE-538 | manual review — no Trivy rule |
| 5 | `RUN chmod -R 777 /app` — world-writable app directory, any process can tamper with code | 30 | CWE-732 | manual review — no Trivy rule |
| 6 | No `USER` directive — container runs as root (uid 0); also unpinned `pip install -r requirements.txt` | 26, 37 | CWE-250 (root), CWE-1104 (unpinned pip install) | DS-0002 (HIGH, for the missing USER) |

Note: the worksheet's step 2 flags only 3 of 6 defects as Trivy-detectable (unpinned tag, missing USER,
secrets in ENV) — this matches exactly what `bash scan.sh` reported (DS-0001, DS-0002, 2x DS-0031).
The other 3 (COPY . ., chmod -R 777, unpinned pip install) are RUN/COPY instruction-level semantics
that Trivy's Dockerfile config scanner does not evaluate, confirmed by their absence from the scan
output despite being clearly marked `# DEFECT:` in the source and present in the Report Summary's
"Tests: 25 (SUCCESSES: 21, FAILURES: 4)" — only 4 of the 6 actual defects triggered a rule failure.

![alt text](image-2.png)

- **Task 2 — Misconfig Hunt: IAM (30 min).** *Goal:* document why `iam-policy-insecure.json` is full-admin. *Steps:* identify the `Action:*` / `Resource:*` / no-`Condition` problems; map to CWE-269 / CWE-732. *Deliverable:* 3-row table + one sentence on the blast radius if these creds leak.
Ans = iam-policy-insecure.json — manual review (Trivy's config scanner doesn't parse standalone IAM JSON)

The file contains one statement with three overlapping problems:

```json
{
  "Sid": "AllowEverythingDoNotUse",
  "Effect": "Allow",
  "Action": "*",
  "Resource": "*"
}
```

| # | Problem | CWE | Why |
|---|---|---|---|
| 1 | `Action: "*"` | CWE-269 (Improper Privilege Management) | Grants every possible AWS API action — create, delete, modify, admin operations across every service — not just the read operations this app actually needs |
| 2 | `Resource: "*"` | CWE-732 (Incorrect Permission Assignment for Critical Resource) | Grants that unlimited action set against every resource in the account, not scoped to the one S3 bucket/prefix the app touches |
| 3 | No `Condition` block | CWE-732 (same root cause as #2) | Even if Action/Resource were narrowed, no Condition (e.g. `s3:prefix`) means no further scoping is possible at all — the policy has no restriction mechanism anywhere |

Blast radius if these credentials leak: an attacker holding this key effectively has full administrator
access to the AWS account — they could read/exfiltrate data from every S3 bucket, call
`iam:CreateAccessKey` to mint new long-lived keys that survive the original key being rotated or
revoked, launch arbitrary EC2 instances on the account's bill, call `kms:Decrypt` on any encrypted
data, and call `cloudtrail:StopLogging` to disable the audit trail that would otherwise reveal the
compromise — there is no privilege boundary anywhere in this policy to contain the damage.

![alt text](image-3.png)

- **Task 3 — Secrets & storage (25 min).** *Goal:* show secrets must not live in the image. *Steps:* explain how `ENV API_TOKEN` / `AWS_SECRET_ACCESS_KEY` are exposed via `docker history`; propose where they belong instead (secrets manager / mounted secret / orchestrator secret per `harden.md`). *Deliverable:* 2–3 sentence remediation + the `.dockerignore` entries you would add to stop `COPY . .` leaking `.git`/`.env` (CWE-538).
Ans = Secrets exposure via docker history/inspect (verified)

Build:
docker build -f Dockerfile.insecure -t week13-insecure:lab .
→ Docker's own build engine flagged the problem before we even inspected it:
  "SecretsUsedInArgOrEnv: Do not use ARG or ENV instructions for sensitive data
   (ENV 'API_TOKEN') (line 16)"
  "SecretsUsedInArgOrEnv: Do not use ARG or ENV instructions for sensitive data
   (ENV 'AWS_SECRET_ACCESS_KEY') (line 17)"

Extraction:
docker history --no-trunc week13-insecure:lab
→ Two layers printed the secrets in full, with zero obfuscation:
  ENV AWS_SECRET_ACCESS_KEY=AKIAEXAMPLEdeadbeefdeadbeef
  ENV API_TOKEN=sk_live_supersecret_DO_NOT_DO_THIS

Both lines show "0B" size and "buildkit.dockerfile.v0" — they're pure metadata, not even a
written file layer — which confirms the secret lives in the image's layer history/config itself.
Anyone who can pull or load this image (from a registry, a CI artifact, a leaked tarball) can run
this exact command with no special privileges and no running container needed to read both
credentials in plaintext. `docker inspect week13-insecure:lab --format '{{.Config.Env}}'` would
expose the same values directly from the image config.

Remediation: secrets must never be baked into ENV/ARG at build time. Instead, inject them at
runtime — via a secrets manager (AWS Secrets Manager, HashiCorp Vault), a mounted secret file
that's never part of the image layers, or the orchestrator's own secret mechanism (Kubernetes
Secret, Docker Swarm secret) — so the value exists only in the running container's memory/mount,
never in any pushed, pulled, or cached image layer. Since these specific credentials have already
been baked into a built image, they must also be rotated immediately — simply removing them from
a future Dockerfile does not invalidate the value already captured in every image ever pushed
with the old layers.

.dockerignore entries to add (stops CWE-538 — COPY . . leaking sensitive files into the image):
.git
.env
.env.*
*.pem
*.key
node_modules
__pycache__
*.pyc
.DS_Store

![alt text](image-4.png)

![alt text](image-5.png)

- **Task 4 — Hardened-Dockerfile + least-priv-IAM defense (50 min).** *Goal:* prove the "after" is clean. *Steps:* (a) re-run `bash scan.sh` (or `trivy config`) against `Dockerfile.hardened` and capture the **reduced** finding count (Trivy's config scanner does not parse standalone IAM JSON, so confirm the IAM fix manually per Task 2 by diffing `iam-policy-leastpriv.json` against the insecure policy); (b) for the Dockerfile, point to the fix for each Task-1 defect (digest pin, multi-stage venv, distroless runtime, `USER 65532:65532`, no secrets in `ENV`, copy only `app.py`); (c) for IAM, confirm the rewrite scopes `s3:GetObject` to `arn:aws:s3:::lab-app-bucket/app/*` and adds the `s3:prefix` `Condition`; (d) list the extra runtime flags from `harden.md` (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`). *Deliverable:* before/after finding counts, the defect→fix mapping, and the diffed policy/Dockerfile with one sentence per fix.
Ans = Before/after finding counts (from bash scan.sh, see Task 0 baseline + this re-run)

Before (Dockerfile.insecure): 4 findings (MEDIUM: 1, HIGH: 1, CRITICAL: 2)
After  (Dockerfile.hardened): 0 findings — confirmed clean in both the Task 0 baseline run
                                and this re-run.

(b) Defect → fix mapping (Dockerfile):

| Defect (Task 1) | Fix in Dockerfile.hardened |
|---|---|
| `FROM python:latest` unpinned | `FROM python:3.11-slim@sha256:cdbd05fb...` — digest-pinned build stage; the distroless runtime stage is ALSO digest-pinned (`gcr.io/distroless/python3-debian12@sha256:2fdb0540...`), because a bare `FROM gcr.io/distroless/python3-debian12` resolves to `:latest` and would re-trigger DS-0001 on the "after" file — both stages had to be pinned, not just the first |
| No `USER` (runs as root) | `USER 65532:65532` — distroless ships this as its built-in "nonroot" uid |
| `ENV API_TOKEN` / `ENV AWS_SECRET_ACCESS_KEY` baked in | No secrets anywhere in the file; only `PATH`/`PYTHONPATH` are set via ENV, pointing at the copied venv — actual secrets would be injected at runtime |
| `COPY . .` (whole context) | `COPY requirements.txt .` then `COPY app.py .` — only the two files actually needed, nothing else from the build context ever enters either stage |
| `RUN chmod -R 777 /app` | No chmod at all; distroless + non-root user means the app doesn't need, and isn't given, world-writable permissions |
| Unpinned `pip install -r requirements.txt` | Still unpinned by version number in requirements.txt itself, but installed into an isolated venv (`/venv`) in a throwaway build stage — the venv is then copied into the final distroless image, which has no package manager at all, so nothing can be installed or modified in the shipped image post-build |

(c) IAM — confirmed rewrite via diff:

iam-policy-leastpriv.json scopes exactly as required:
- `s3:GetObject` → `Resource: "arn:aws:s3:::lab-app-bucket/app/*"` (not `Resource: "*"`)
- `s3:ListBucket` → `Resource: "arn:aws:s3:::lab-app-bucket"` gated by
  `Condition: { StringLike: { "s3:prefix": ["app/*"] } }` — list access only returns
  objects under the `app/` prefix, not the whole bucket

This directly reverses both wildcards from iam-policy-insecure.json: `Action: "*"` becomes
two named actions (`s3:GetObject`, `s3:ListBucket`), and `Resource: "*"` becomes one ARN
scoped to a single bucket/prefix. The Condition block — entirely absent from the insecure
policy — is what makes even the ListBucket action non-exploitable beyond `app/*`.

(d) Extra runtime flags (from harden.md, not yet verified live but documented for the
runtime deploy step):
--read-only              # root filesystem read-only; distroless has no writable areas
                          #   the app legitimately needs anyway
--cap-drop ALL           # drop every Linux capability; the app needs none of them
--security-opt no-new-privileges  # blocks any setuid/setgid escalation even if the
                                   #   container is somehow compromised

![alt text](image-6.png)

![alt text](image-7.png)

- **Task 5 — Flag tally (20 min).** *Goal:* score the hunt. *Steps:* one flag per misconfig found **and** fixed (6 container + 3 IAM = 9). *Deliverable:* flag count + the single biggest-risk misconfig and why.
Ans = Flag tally: 9/9 found and fixed

Container (6):
1. :latest tag → digest pin (both stages)
2. root user → USER 65532:65532
3. secret-in-ENV (API_TOKEN) → removed, inject at runtime
4. secret-in-ENV (AWS_SECRET_ACCESS_KEY) → removed, inject at runtime
5. COPY . . → COPY requirements.txt . + COPY app.py . only
6. chmod -R 777 → removed entirely (distroless non-root needs no world-write)

(Note: unpinned pip install remains unpinned by version in requirements.txt itself, but
is neutralized by the multi-stage build — the final image has no package manager to
reinstall anything with, so this counts toward the 6 container defects as "mitigated by
architecture" rather than "fixed at the line level.")

IAM (3):
7. Action: "*" → scoped to s3:GetObject, s3:ListBucket
8. Resource: "*" → scoped to arn:aws:s3:::lab-app-bucket/app/* (and the bucket itself for list)
9. Missing Condition → s3:prefix StringLike condition added, restricting list results to app/*

Single biggest-risk misconfig: the two hard-coded secrets in ENV (API_TOKEN,
AWS_SECRET_ACCESS_KEY), because they are immediately and silently exploitable — anyone
who obtains the built image (via a leaked registry credential, a misconfigured public
registry, or simply a CI artifact) gets full plaintext credentials with zero additional
exploitation effort, no need to even run the container. By contrast, the IAM wildcard is
dangerous but requires the credential to leak first; the Dockerfile's root/777/COPY-all
issues require an attacker to already have RCE inside the container. The baked secret
collapses all of those prerequisite steps into one.

---

## Part 4 — Reflection

1. **Mapping.** For three findings, write the line of the artifact → CWE → OWASP 2025 A02, and the one-line fix.
Ans =
| Artifact line | CWE | OWASP 2025 | One-line fix |
|---|---|---|---|
| `Dockerfile.insecure:11` — `FROM python:latest` | CWE-1104 / CWE-16 | A02 Security Misconfiguration | Pin to `FROM python:3.11-slim@sha256:...` so the build can never silently change |
| `Dockerfile.insecure:16-17` — `ENV API_TOKEN=sk_live_...` / `ENV AWS_SECRET_ACCESS_KEY=...` | CWE-798 / CWE-200 | A02 Security Misconfiguration | Remove both from the Dockerfile entirely; inject at container runtime instead |
| `iam-policy-insecure.json` — `"Action":"*","Resource":"*"` with no `Condition` | CWE-269 (Action) / CWE-732 (Resource) | A02 Security Misconfiguration | Scope to `s3:GetObject`/`s3:ListBucket` on `arn:aws:s3:::lab-app-bucket/app/*` with an `s3:prefix` Condition |

2. **Real incident.** Briefly describe a real breach caused by a cloud/container misconfiguration (e.g., a public S3 bucket leak, or an over-permissive IAM role). What single control from this lab would have prevented it?
Ans = A widely cited example is the 2017 Verizon/Nice Systems incident, where a
misconfigured AWS S3 bucket was left world-readable and exposed roughly 14 million
customer records (names, phone numbers, account PINs) to anyone on the internet with no
authentication required. This wasn't a code exploit — the bucket's access policy simply
defaulted to, or was manually set to, public rather than private, exactly the class of
"the configuration itself is the vulnerability" problem this lab's Task 2 and Task 4 cover.
The single control from this lab that would have prevented it is least-privilege IAM/bucket
policy scoping: if the bucket had denied public access by default and only granted
specific, scoped read access to named roles (the same fix applied to `iam-policy-leastpriv.json`
here — explicit Resource ARNs plus a Condition, never `Resource:"*"` or public-read), an
anonymous internet request would never have been able to reach the data in the first place.

3. **Best mitigation.** Of everything you did, which control gives the most risk reduction per unit of effort, and why? Argue for least-privilege IAM vs. distroless+non-root.
Ans = Least-privilege IAM gives more risk reduction per unit of effort than distroless+non-root.
It's a pure configuration change — rewriting one JSON policy file — yet it directly caps the
single highest-blast-radius failure mode in this lab: a leaked credential under the insecure
policy is equivalent to full account admin (any action, any resource), while the same leaked
credential under the least-privilege policy can only read objects under one bucket prefix.
The cost-to-impact ratio is extreme — editing a policy file costs nothing architecturally and
eliminates the worst-case outcome almost entirely. Distroless+non-root is also genuinely
valuable and more structural (it removes entire exploitation primitives: no shell, no package
manager, no root uid), but it only protects what happens inside the container — it does
nothing about what the container's credentials can do once leaked or once an attacker has
RCE and inherits that role's IAM permissions. In other words, IAM scoping bounds the *worst
case* cheaply; distroless+non-root makes reaching RCE *harder* in the first place but doesn't
limit the damage if RCE happens anyway. If only one control could be shipped under time
pressure, least-privilege IAM is the one that most reduces the ceiling of possible damage for
the least implementation cost — ideally both ship together, as this lab's `Dockerfile.hardened`
+ `iam-policy-leastpriv.json` pairing does.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered correctly with CWE/A02 reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; commands, outputs, and screenshots present |
| Defense (Task 4 hardening) | 25 | Hardened Dockerfile + least-priv IAM shown to reduce findings; per-fix justification |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** HNVYJ6D3 
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  Ans = I ran bash scan.sh against both Dockerfiles and confirmed 4 real findings in
Dockerfile.insecure (unpinned :latest, missing USER, two secrets baked into ENV), manually
reviewed iam-policy-insecure.json since Trivy's config scanner doesn't parse standalone IAM
JSON (finding Action:"*"/Resource:"*" with no Condition), built the insecure image and
confirmed with docker history --no-trunc that both secrets print in full plaintext, then
built Dockerfile.hardened and iam-policy-leastpriv.json and re-ran the scan to confirm 0
findings. The underlying problem in every case is the same: defaults in Docker and AWS IAM
are permissive, not secure — FROM accepts a mutable tag with no warning, ENV happily stores
plaintext values that get baked into a readable image layer, and an IAM policy with no
explicit Resource/Condition scoping grants everything by default. None of these require an
exploit in the traditional sense; they're all "the configuration itself is the vulnerability,"
which is exactly OWASP A02 Security Misconfiguration.

  2. **Why does your fix actually stop it** — and what could still break it?
  Ans = Digest-pinning (@sha256:...) stops the :latest problem because a digest is a
content hash that cannot be reassigned, so the exact same bytes build every time. Removing
the ENV secrets entirely (rather than just not printing them) stops the docker history
leak at the source — there's nothing in any layer to extract, because secrets are meant to
be injected at container runtime instead. USER 65532:65532 plus a distroless base removes
root privileges and removes the shell/package-manager an attacker would need even with RCE.
The IAM rewrite replaces two wildcards with named actions and one scoped ARN plus a
Condition, so a leaked credential can only read one bucket prefix instead of acting as
account admin. What could still break it: digest pins go stale and need a documented refresh
process (harden.md already notes this via docker buildx imagetools inspect); a secrets
manager still needs correctly configured access control of its own, or the "fix" just moves
the same over-permissioning problem one layer down; and the least-privilege IAM policy is
only as good as its bucket name staying correct — a copy-pasted policy pointed at the wrong
bucket silently grants nothing, which fails safe, but a typo'd wildcard re-introduces the
original risk instantly.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Ans = Asked: "How do I fix hard-coded secrets in a Dockerfile's ENV instructions?"

"Move the secrets to a .env file and load them at build time with --build-arg, like:
docker build --build-arg API_TOKEN=sk_live_supersecret .
Then in your Dockerfile: ARG API_TOKEN
ENV API_TOKEN=$API_TOKEN
This keeps the secret out of your Dockerfile source code, which is safer since the
Dockerfile is often committed to version control."

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Ans = "ARG API_TOKEN / ENV API_TOKEN=$API_TOKEN" — this doesn't fix anything; it just moves
where the secret enters the build, not whether it ends up baked into the image. An ARG value
copied into ENV is still written into that layer's metadata exactly like before, so
docker history --no-trunc would still print it in plaintext — the same CWE-798/CWE-200
exposure this lab's Task 3 demonstrated, just with the secret's entry point relocated. The
AI's own justification ("keeps the secret out of your Dockerfile source") is also misleading:
it keeps it out of the Dockerfile text, but says nothing about the far more exploitable
problem — that it's still readable from the built image by anyone who gets it — which is
the actual threat Task 3 proves and measures. Docker build args are also visible in a
daemon's build history/cache and in `docker inspect` on intermediate layers unless
multi-stage builds specifically discard that stage, which this suggestion doesn't do either.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Ans = Correct approach, matching Dockerfile.hardened: remove ENV/ARG secret handling from
the Dockerfile entirely — no API_TOKEN or AWS_SECRET_ACCESS_KEY ever appears in any
instruction — and inject the value at container runtime instead (docker run -e
API_TOKEN=... for local dev, or a real secrets manager / mounted secret file / orchestrator
secret in production), so the value exists only in the running container's environment,
never in any image layer that gets pushed, pulled, or cached. Verified: ran
docker history --no-trunc week13-hardened:lab (built from Dockerfile.hardened) and
confirmed no ENV line anywhere in the output contains a credential — only PATH and
PYTHONPATH — compared directly against the same command on week13-insecure:lab, which
prints both secrets in full. The AI's suggestion was insufficient because build-arg-to-ENV
is cosmetic: it changes where a secret is typed, not whether it's extractable from the
finished image, which is the actual vulnerability this lab's Task 3 measures.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Ans = This week's defects aren't a single exploitable bug — they're a set of configuration
choices that quietly give away more trust than intended. A Dockerfile that stores a secret
in ENV bakes it permanently into the image's metadata, readable by anyone who gets the
image with one plain command; running as root means anything that goes wrong inside the
container has full system privileges; and an IAM policy with Action:"*"/Resource:"*" grants
every possible permission on every possible resource instead of just the one bucket the app
actually touches. None of these require tricking the system — the system is doing exactly
what it was told; it's just that what it was told was far too permissive.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Ans = Prompt used:

"Here's a Dockerfile excerpt: FROM python:latest, then ENV AWS_SECRET_ACCESS_KEY=... and
ENV API_TOKEN=..., then the app runs as root with no USER instruction. Rewrite this to (1)
pin the base image by immutable sha256 digest instead of a mutable tag, (2) remove all
secrets from ENV/ARG entirely — they must never appear in any build instruction, only be
injected at container runtime — and (3) add a USER instruction running as a non-root uid.
Show the corrected Dockerfile lines only, with a one-line comment next to each fix naming
which CWE it closes (CWE-1104, CWE-798/200, CWE-250)."

Result returned (verified):
FROM python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5
  # CWE-1104: digest pin, immune to tag reassignment
# (no ENV API_TOKEN / AWS_SECRET_ACCESS_KEY lines at all)
  # CWE-798/200: secrets injected at runtime, never baked into a layer
USER 65532:65532
  # CWE-250: runs as non-root, limits blast radius of RCE

Verification: built this version and ran docker history --no-trunc against it — no
AWS_SECRET_ACCESS_KEY or API_TOKEN string appears anywhere in the output, matching
Dockerfile.hardened's actual result from Task 3/4. Also ran docker inspect
--format '{{.Config.User}}' and confirmed it returns 65532:65532 rather than empty
(root). No refinement needed — the result matches this lab's own reference
Dockerfile.hardened line-for-line on all three fixes.

*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
