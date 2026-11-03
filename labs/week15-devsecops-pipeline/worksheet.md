# Worksheet 15 — DevSecOps: Putting It Together (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 15
> **Aligned to:** OWASP 2025 **A09 Security Logging & Alerting Failures** · **A10 Mishandling of Exceptional Conditions** (scanners also cover A02/A03) · **CWE-636** (fail open), CWE-532 (logging sensitive data), CWE-209, CWE-489, CWE-798
> **Signature game:** 🔴🔵 *Break the Build* (Red vs Blue) — Blue scores per catch, Red scores per bypass.

> ⚠️ **Ethics note:** The pipeline and `sample-service.py` are a teaching template (`"Sandbox/teaching only; for authorized lab use."`). Run the security gate and the "Red team" bypass attempts **only** against a repo you own (your fork / a throwaway repo). Do not push deliberately-vulnerable code or planted secrets to shared/production repositories.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
|Hathaichanok Yimjan|6631503045|4/11/2026| Where |

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. `README-pipeline.md` says each tool runs **twice** (report step, then gate step). Explain why a single failing scan would *hide* findings, and how "report-then-gate" with `if: always()` gives you both SARIF results and a red build.
Ans = Report-then-gate

If a scan fails immediately, GitHub Actions normally skips later steps, so its findings may not reach the Security tab. The report step generates SARIF without failing the build, and the upload step uses if: always() so it can run even after an earlier failure. The gate step then enforces the security policy and turns the build red when blocking findings are detected. The Security tab may also show lower-severity findings that the gate allows.

2. What is the difference between **fail-closed** and **fail-open**? In `sample-service.py`, point to the `except Exception` branch in `/admin` and the commented INSECURE variant — why is fail-open **A10 / CWE-636**?
Ans = Fail-closed vs fail-open

Fail-closed denies access when an unexpected error occurs, while fail-open allows access despite the error. In /admin, the except Exception branch returns {"error":"forbidden"} with HTTP 403, while the commented INSECURE variant returns the secret. The insecure version is A10 / CWE-636 because an error bypasses the access check and exposes protected information.

3. The `permissions:` block in `security-ci.yml` is `contents: read`, `security-events: write`. Why is this **least privilege** for a CI token, and what could go wrong with a broad `write-all` token?
Ans = Least privilege

The CI token uses contents: read to read the repository and security-events: write to upload security scan results. This follows least privilege because it grants only the access needed for these tasks. A broad write-all token increases the damage a malicious or compromised workflow could cause, such as changing repository content.

4. The security log lines never print the token value (`reason=bad_token`, not the token itself). Why is logging the secret **CWE-532**, and what should be logged instead so a SIEM can still alert (A09)?
Ans = Safe security logging

Logging a token is CWE-532 because anyone who can read the logs might obtain and misuse that secret. Instead, the application should log the timestamp, event type, outcome, source IP, failure reason, and a safe user identifier when available. These fields let a SIEM detect repeated authentication failures and generate alerts without exposing credentials, supporting A09.

5. Name the three scanners in the pipeline and what each catches: **Semgrep** (SAST), **Trivy** (SCA + IaC/secret), **Gitleaks** (secrets + git history). Which OWASP categories does each map to per the README table?
Ans = Semgrep performs SAST to detect insecure code patterns and maps to the OWASP Top 10 depending on the rule. Trivy detects vulnerable dependencies, infrastructure and Dockerfile misconfigurations, and secrets; the README maps it to A03 / A02. Gitleaks detects hard-coded secrets in code and Git history, and the README maps it to CWE-798 rather than a specific OWASP category.

---

## Part 3 — Hands-on Lab (180 min in class)

> The task budgets below add up to 205 min. That is deliberate over-provisioning, not a schedule:
> Tasks 2–4 are dominated by Actions queue and scan wall-clock, so push in class and finish the
> write-up at home. Your instructor will say which task runs as homework.

![Two panels: the CI gate in security-ci.yml, where a MEDIUM DS-0001 finding slips past the HIGH,CRITICAL threshold and the build goes green, and the /admin handler, where one except branch returns 200 with the flag while the other returns 403 and logs it.](img/fail-closed.svg)

**Learning goals:** wire a security CI gate that fails closed on HIGH/CRITICAL, observe structured security logging + fail-closed handling locally, then play Break-the-Build.

**Prerequisites:** a GitHub repo you own (fork or throwaway) with Actions enabled; `git`; Docker; Python + Flask for the local service.

### Environment setup (real commands)

```bash
# --- A) Wire the gate into a repo you own (README-pipeline.md §1) ---
mkdir -p .github/workflows
cp labs/week15-devsecops-pipeline/security-ci.yml .github/workflows/security-ci.yml
git add .github/workflows/security-ci.yml
git commit -m "ci: add security gate (Semgrep + Trivy + Gitleaks)"
git push        # runs on push/PR to main

# --- B) Run the sample service locally (logging + fail-closed) ---
pip install flask
python labs/week15-devsecops-pipeline/sample-service.py
# In another shell:
curl -s -X POST localhost:5001/login -H 'Content-Type: application/json' -d '{"token":"nope"}'   # 401 authn_failure
curl -s localhost:5001/admin -H 'Authorization: bob-token'    # 403 authz_failure
curl -s localhost:5001/admin -H 'Authorization: alice-token'  # 200 (admin)
```

**What to submit per task:** the command / PR link, the relevant output or log lines / Actions step result, a screenshot, and a 2–3 sentence note on the control involved (cite the A0x / CWE).

### Tasks

- **Task 0 — Onboarding (15 min).** Run the sample service; trigger the three curls above. **Deliverable:** screenshot of the structured `event=...` security log lines for authn_failure, authz_failure, and authz_success.
Ans = Ran `python labs/week15-devsecops-pipeline/sample-service.py` to start the sample
service on `http://127.0.0.1:5001`, then triggered the three curl requests:

```bash
curl -s -X POST localhost:5001/login -H 'Content-Type: application/json' -d '{"token":"nope"}'
# -> {"error":"authentication failed"}

curl -s localhost:5001/admin -H 'Authorization: bob-token'
# -> {"error":"forbidden"}

curl -s localhost:5001/admin -H 'Authorization: alice-token'
# -> {"secret":"the cake is a lie"}
```

Structured security log lines produced by the server:

![alt text](image.png)

- **Task 1 — Logging & fail-closed (35 min, A09/A10).** *Goal:* prove fail-closed behavior. *Steps:* read `/admin` in `sample-service.py`; explain why the broad `except Exception` returns **403, not the secret**, and why `type(exc).__name__` (not the message) is logged (CWE-209). Identify the line that would make it fail *open* (the commented INSECURE variant). *Deliverable:* the log lines + a 2–3 sentence explanation of fail-closed vs fail-open.
Ans = The two log lines show that the system denied Bob's access because he was not an admin, while Alice was allowed to access the admin page. The commented INSECURE variant is return jsonify(secret="the cake is a lie") inside except Exception. It would grant access when an error occurs instead of denying it.

The code uses `except Exception` to catch unexpected errors and return a 403 response, which is called fail-closed because access is denied when an error occurs. It also logs only the exception type instead of the full error message to prevent sensitive information from being exposed (CWE-209).

If the code used the insecure version that returns the secret inside the exception handler, it would become fail-open and could expose sensitive information when an error occurs.

![alt text](image-1.png)

- **Task 1b — Break the Build, live (25 min, A10 / CWE-636).** *Goal:* exploit a real fail-open, then prove the fix. *Steps:* `cd labs/week15-devsecops-pipeline && docker compose up` (spawns the **insecure** service on `:8090` and the **secure** one on `:8091`). As **Red**, hit the insecure admin route with **no** Authorization header — the fail-open path leaks the admin panel *and* your per-student flag:
  ```
  curl -s localhost:8090/admin                                  # {"panel":"UNLOCKED","secret":"FLAG{devsecops_...}"}  <- fail OPEN
  curl -s localhost:8091/admin                                  # {"error":"forbidden"}   (403)  <- fail CLOSED + logged
  curl -s localhost:8091/admin -H 'Authorization: alice-token'  # still UNLOCKS for a real admin (anti-cheat)
  ```
  Submit the leaked `FLAG{...}`. *Deliverable:* the flag, the two contrasting `/admin` responses (`:8090` leak vs `:8091` deny), and the exact line in `insecure_service.py` that fails open. *(The instructor auto-grader re-runs these exploits against your hardened box — you pass only if every bypass is blocked **and** a valid admin token still works.)*
  Ans = Without an Authorization header, the insecure service on port 8090 returned
{"panel":"UNLOCKED","secret":"FLAG{devsecops_fail_open_leaks_admin}"}.
The secure service on port 8091 returned {"error":"forbidden"}, while a request
with alice-token still returned the admin panel.

This demonstrates fail-open behavior: an error in the authorization path
allows access instead of denying it (A10 / CWE-636). The secure service denies
unauthorized access while preserving access for a valid administrator.

  ![alt text](image-2.png)

  The fail-open statement is line 49 in insecure_service.py:
return jsonify(panel="UNLOCKED", secret=SECRET)

It returns the secret inside except Exception after the token lookup on line 42 raises KeyError. The flag shown is the local demo flag.

- **Task 2 — Stand up the gate (35 min).** *Goal:* get the workflow running. *Steps:* push `security-ci.yml`, open the Actions run, confirm the three jobs (`semgrep`, `trivy`, `gitleaks`) execute and SARIF appears in the Security tab. *Deliverable:* screenshot of the Actions run + the Code scanning alerts page.
Ans = I ran the security-ci workflow on branch WK15-6631503045.
The Actions run shows that Semgrep, Trivy, and Gitleaks executed.
Semgrep passed, while Trivy and Gitleaks failed. The additional Tests job
also failed, but its cause requires inspection of the job log.

The Code scanning page shows two HIGH-severity Trivy alerts associated
with sharp in slides/pptx/package-lock.json. Gitleaks also reported
findings in the repository history. This confirms that the scanners ran
and Trivy uploaded results, but the workflow has not passed yet.

![alt text](image-3.png)

![alt text](image-4.png)

- **Task 3 — Blue team: pass the gate (30 min).** *Goal:* a green build. *Steps:* ensure the protected repo has no HIGH/CRITICAL findings and no secrets; fix or justify-and-document any (no blanket-ignore, per README §4). *Deliverable:* link to the passing run.
Ans = The security pipeline passed successfully at commit be3d944. I pinned GitHub Actions to full commit SHAs, updated the Trivy action reference, and documented narrowly scoped exceptions for Docker host binding and four public demo-token findings. All three jobs—Semgrep, Trivy, and Gitleaks—passed with the security gates still enabled.

Passing run:https://github.com/MM0131/week15-6631503045/actions/runs/41691780082

![alt text](image-5.png)

- **Task 4 — Red team: Break the Build (40 min).** *Goal:* make the gate say **no**. *Steps:* on a branch/PR, inject *one* planted defect (per README §5), each of which is caught by a *different* job: an outdated vulnerable dependency (e.g. an old `urllib3`) → Trivy SCA; a Dockerfile that runs as **root** — drop the `USER` line, or write `USER root` → Trivy config (`DS-0002`, HIGH); or a hard-coded token → Gitleaks. Open the PR and watch the matching gate step fail. *Deliverable:* screenshot of the **failing** gate step + which job caught it (Trivy SCA / Trivy config / Gitleaks) and which `exit-code: "1"` / `--error` step enforced it.
  > **Why root and not `chmod 777`.** Both gate steps filter to `--severity HIGH,CRITICAL`, and Trivy's Dockerfile scanner has no rule for `chmod` at all — it checks instruction-level `RUN`/`COPY` semantics, exactly as Week 13 Task 1 says. `chmod 777` therefore returns **nothing**, at any severity, and the build goes green: a defect that slips the gate is a Task 5 *Red point*, not a Task 4 screenshot. `:latest` is no good either — that is `DS-0001` and Trivy rates it MEDIUM, which this gate filters out. Running as root is `DS-0002` HIGH, so it fails the build for real.
  Ans = I added urllib3==1.26.4 to red-demo/requirements.txt on branch red/vulnerable-dependency and opened a pull request. Trivy SCA reported eight HIGH-severity vulnerabilities in this dependency.

The “Gate — fail on HIGH/CRITICAL (SCA)” step enforced exit-code: "1" and failed the build. This demonstrates that the dependency security gate rejected the planted defect, supporting OWASP A03 Software Supply Chain Failures.

PR: https://github.com/MM0131/week15-6631503045/pull/1
Failing run: https://github.com/MM0131/week15-6631503045/actions/runs/41693463359

![alt text](image-6.png)

- **Task 5 — Score Break-the-Build (25 min).** *Goal:* tally Red vs Blue. *Steps:* one Blue point per finding the gate caught, one Red point per finding that slipped through; for any bypass, propose the rule that would have caught it. *Deliverable:* scoreboard + one proposed gate improvement.
Ans = The scoreboard below covers the Task 4 experiment in PR #1.

| Test | Observed result | Blue points | Red points |
|---|---|---:|---:|
| urllib3==1.26.4 in red-demo/requirements.txt | Trivy detected 8 HIGH findings; the SCA gate exited with code 1. | 8 | 0 |
| **Total** | **One planted dependency; eight vulnerability findings** | **8** | **0** |

Screenshot evidence: see the Task 4 screenshot and failing run. No bypass was observed in this experiment.

One vulnerable dependency was planted, but it produced eight separate vulnerability findings. No bypass was observed in this experiment; this does not prove that the gate catches every possible defect.

Proposed gate improvement: Add a required CI test that calls the secure /admin endpoint without a token, with an invalid token, and with a non-admin token, and verifies that access is denied without returning the secret. Also verify that a valid admin token still succeeds. This would complement the scanners by testing access-control behavior directly and helping detect fail-open regressions (A10 / CWE-636).

Evidence: https://github.com/MM0131/week15-6631503045/actions/runs/41693463359

---

## Part 4 — Reflection

1. **Mapping.** For three controls you exercised, give: control → A09/A10 (or A02/A03 for a scanner) → CWE → one-line rationale.
Ans = 
| Control | OWASP 2025 | CWE | Rationale |
|---|---|---|---|
| Structured authentication and authorization logging without token values | A09 Security Logging & Alerting Failures | CWE-778: Insufficient Logging | Recording events, outcomes, and safe user identifiers supports investigation and alerting. |
| Denying access when authorization raises an unexpected exception | A10 Mishandling of Exceptional Conditions | CWE-636: Not Failing Securely | An error must not allow an unauthorized user to receive the admin secret. |
| Trivy dependency scanning with a failing HIGH/CRITICAL gate | A03 Software Supply Chain Failures | CWE-1395: Dependency on Vulnerable Third-Party Component | The gate detected vulnerabilities in urllib3==1.26.4 and failed the PR check. |

2. **Real incident.** Briefly describe a real breach worsened by missing logging/alerting or by a fail-open error path. Which control here would have changed the outcome?
Ans = The Anthem breach reported in 2015 affected approximately 78.8 million people. HHS identified insufficient procedures for reviewing system activity and failures to identify and respond to security incidents. Structured security logs combined with monitoring, alerts, and a response process could have helped detect suspicious activity earlier and potentially reduced the impact; logging alone would not guarantee prevention.

3. **Best mitigation.** Argue which matters more for a small team: the *fail-closed* code in `sample-service.py`, or the *CI gate* in `security-ci.yml` — and why both together beat either alone.
Ans = For a small team, I would prioritize fail-closed authorization because it protects sensitive data when the running application encounters an unexpected error. A CI gate is also valuable because it detects known vulnerabilities and insecure patterns before deployment, but it cannot prove that every runtime access check works correctly. Using both provides stronger protection: the gate checks changes before release, while fail-closed code denies access when errors occur during execution.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered with correct A09/A10/CWE reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; PR/run links, log lines, screenshots present |
| Defense (gate + fail-closed) | 25 | Gate shown to fail closed on a planted defect; fail-closed path explained |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** FLAG{devsecops_3c8f3e0bba9a3392}
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  Ans = I compared the insecure and secure admin endpoints without an Authorization header. The insecure endpoint returned the admin panel and demo secret because its error path allowed access instead of denying it. I also planted urllib3==1.26.4 in a separate PR, where Trivy detected eight HIGH-severity vulnerabilities and failed the SCA gate.

  2. **Why does your fix actually stop it** — and what could still break it?
  Ans = The secure endpoint denied the unauthenticated request while still allowing a valid admin token. The CI gate also rejected the vulnerable dependency because its findings met the HIGH/CRITICAL threshold and the gate used exit-code: "1". Untested authorization paths, overly broad exceptions, disabled checks, or vulnerabilities missing from scanner rules could still leave gaps.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Ans = “To fix a fail-open authorization handler, deny access when an unexpected exception occurs. Record an authz_error event with outcome=deny and only the exception type, then return a generic HTTP 403 response without the secret. Test missing, invalid, and non-admin tokens, and confirm that a valid admin token still works.”

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Ans = Exact line: “Test missing, invalid, and non-admin tokens, and confirm that a valid admin token still works.”

This test plan misses an important edge case: an unexpected exception during authorization. These requests may only exercise normal access checks, so they cannot prove that the exception handler denies access safely. A complete test must also force an exception and check the response and security log.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Ans = I corrected the verification plan by adding a forced-exception test using unittest.mock.patch on the authorization lookup in the existing secure_service.py. All five cases passed: missing, invalid, and non-admin tokens returned 403; a valid admin token returned 200; and a forced RuntimeError returned 403 with an authz_error log that exposed neither the token, secret, nor exception message. The AI’s original test plan was insufficient because normal access tests alone did not verify the exception-handling path.

![alt text](image-7.png)

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Ans = The admin endpoint checks whether a request belongs to an administrator before returning protected information. In the insecure version, an error during this check leads to a response containing the admin secret, so a request without a token can gain access. The secure version denies the unauthenticated request while still allowing a valid administrator.



**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
Ans = “Review the attached insecure_service.py and secure_service.py from my authorized local teaching lab. Fix any fail-open authorization path so that missing, invalid, and non-admin tokens cannot obtain the admin secret. Unexpected exceptions must return a generic HTTP 403 response and log authz_error with outcome=deny and only the exception type, without logging tokens or secrets. Preserve successful access for a valid admin token. Provide the minimal diff and isolated automated tests, including a forced exception in the authorization lookup. Report actual test results separately from expected results, and do not claim verification unless the tests were executed.”


I ran verify_authz.py against the existing secure_service.py using Flask’s test client. Missing, invalid, and non-admin tokens returned 403, while a valid admin token returned 200. A forced RuntimeError also returned 403 and generated an authz_error log without exposing the token, secret, or exception message. All five checks passed. This verifies the existing secure implementation; no application code change was needed.

Evidence: see the Audit the AI Question 3 screenshot.

*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
