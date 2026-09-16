# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|Hataichanok Yimjan|6631503045|16/9/2569|-------|
|      |           |      |       |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?
Ans = Authentication verifies who the requester is (checking that a submitted token or credential genuinely belongs to a claimed identity), while authorization determines what that verified identity is allowed to do or access once their identity is known. In vulnerable_app.py, authentication technically still happens — current_user() does decode and validate the token — but its result is never checked against the object being requested, so authorization is missing: the endpoint confirms who you are but never confirms whether you're allowed to see the specific order you asked for.

2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?
Ans = IDOR (Insecure Direct Object Reference) happens when an application exposes a reference to an internal object — like a raw ID or filename — directly in the URL or request, and lets any authenticated user request any value of that reference without checking whether they actually own the object. /api/orders/<oid> is exploitable because it accepts any oid from any logged-in user and returns the matching order without checking who owns it, so simply incrementing or guessing the ID number lets an attacker walk through other users' data. The single check in solution_app.py (L64) that closes this is an ownership comparison — verifying that the order's owner field matches the authenticated user's identity before returning the data, rejecting the request otherwise.

3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?
Ans = A JWT's header specifies which algorithm was used to sign it, and if the server's verification code accepts "none" as a valid algorithm, it tells the library to skip signature verification entirely and simply trust whatever claims are in the payload. Since anyone can construct a JWT with {"alg": "none"} in the header and an empty signature, listing "none" in the server's accepted algorithms=[...] list means the server will happily decode and trust a token that was never actually signed by anyone — the attacker doesn't need to know any secret at all, they just need the server to accept the algorithm they chose.

4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?
Ans = Even with alg:none disabled, if the server signs tokens with HS256 using the literal string "secret" as the key, an attacker can simply guess or brute-force that common value and use it to sign their own forged token with a valid, verifiable signature — the server then has no way to tell the forged token apart from a legitimate one, since the signature checks out mathematically. A strong, random, sufficiently long secret makes brute-forcing computationally infeasible, and pinning the algorithm (rejecting any token whose header doesn't explicitly say HS256) prevents an attacker from downgrading to a weaker or unsigned algorithm to bypass the strong secret entirely — both defenses have to work together, since a strong secret alone doesn't help if the algorithm itself can still be swapped out.

5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?
Ans = The exp (expiration) claim gives every token a hard expiry time, so even a valid, correctly-signed token becomes useless to an attacker who steals or replays it after that window closes, limiting the damage of a leaked token. The aud (audience) claim restricts which specific service or endpoint the token is valid for, preventing a token issued for one legitimate purpose from being reused or replayed against a different, unintended service. The secure version rejects tokens missing either claim because an attacker forging a token from scratch could otherwise mint one with no expiry (permanently valid) or omit the intended audience check, so requiring both closes off convenient shortcuts an attacker would take when crafting a forged token.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*
![alt text](image.png)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.

```sim
jwt-forge
```
Ans = The /api/orders/<oid> endpoint authenticates the request (verifies alice's token is valid) but never checks whether the order's owner field matches the authenticated user before returning it. Because the server trusts any valid token to fetch any oid, simply changing the number in the URL from 1 to 2 returns bob's private order — including his flag — with no authorization check at all. This is the defining pattern of IDOR: authentication succeeded, but authorization was completely absent.
![alt text](image-1.png)

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).
Ans = The alg:none attack works because the server's current_user() function reads the algorithm from the token's own header and, if it says "none", decodes the token with verify_signature: False — meaning it trusts whatever claims are inside without checking any cryptographic proof that a legitimate party created them. Since the attacker fully controls the header, payload, and (empty) signature of a self-crafted token, listing "none" as an acceptable algorithm effectively means the server has no real authentication at all for that code path — anyone can claim to be bob (or any user) simply by writing it into the payload, with zero cryptographic verification standing in the way.
![alt text](image-2.png)

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.
Ans = bash
FORGED2=$(docker compose exec -T authz-lab python -c "import jwt; print(jwt.encode({'sub': 'bob'}, 'secret', algorithm='HS256'))")

Token:

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib2IifQ.-51G5JQmpJleARHp8rIljBczPFanWT93d_N_7LQGUXU

Screenshot: ⏳ (รอ stamp ใหม่)

Why secret strength + key management matter (2-3 sentences):

The server signs and verifies JWTs using the literal 6-character string "secret" as its HMAC key, which is short and guessable enough that an attacker doesn't need to break any cryptography — they simply try the common value and it works, letting them forge a validly signed token for any user they choose, including one they were never issued. A strong secret should be long, randomly generated, and never a predictable word, ideally 32+ bytes as PyJWT's own warning recommends for HS256, so that even with unlimited guessing an attacker can't feasibly recover it. Proper key management also means keeping that secret out of source code (using environment variables or a secrets manager) and rotating it if ever suspected of compromise, since a leaked or weak signing key completely defeats the purpose of using signed tokens in the first place.
![alt text](image-3.png)

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.
Answer= As additional proof the chain is complete, the same forged bob token was also used to read order 1, which belongs to alice — not bob. This confirms the forged identity isn't limited to accessing "bob's own" objects; once authentication is defeated, the IDOR flaw exposes every user's data to any forged identity, regardless of which name was written into the token's payload.
![alt text](image-4.png)

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.
Answer= 
| Attack | Vulnerable behavior (vulnerable_app.py) | Result on solution_app.py | Status | Fix line |
|---|---|---|---|---|
| IDOR — `/api/orders/2` with **alice's real token** | 200 OK, leaks bob's order (no ownership check) | **403 Forbidden** | ✅ | **L64** — ownership check: compares order's `owner` field against `current_user()` before returning data |
| JWT Forgery — `alg:none` (`$FORGED`) | 200 OK, unsigned token accepted | **401 Invalid token** | ✅ | **L50** — algorithm pinned to `HS256` only; `none` is no longer accepted |
| JWT Forgery — weak secret `"secret"` (`$FORGED2`) | 200 OK, forged HS256 token accepted | **401 Invalid token** | ✅ | **L10** (strong random secret replaces `"secret"`) + **L40** (requires `aud`/`exp` claims) |

![alt text](image-5.png)
## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.
Answer= The IDOR flaw in `/api/orders/<oid>` maps to **CWE-639 (Authorization Bypass Through User-Controlled Key)** and **OWASP A01 Broken Access Control**, since the vulnerability is purely about missing ownership checks on an object reference. The two JWT forgery paths map to **A07 Authentication Failures**: the `alg:none` bypass is **CWE-347 (Improper Verification of Cryptographic Signature)** because the server accepts a token with no valid signature at all, while the guessable `"secret"` key is **CWE-321 (Use of Hard-coded Cryptographic Key)** because the signing key itself is weak and predictable rather than the verification logic being broken.

2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. *(Alternative: the Peloton API IDOR disclosure.)*
Answer= The Optus breach happened because an internet-facing API endpoint returned customer PII for any request that supplied a valid-looking identifier, with no check confirming the caller was authorized to view that specific customer's record — structurally identical to Task 1, where `/api/orders/<oid>` returned any order to any authenticated user regardless of who actually owned it. In both cases authentication was not the failure point (a legitimate, working credential was used); the failure was that authorization was either missing entirely or trivially bypassable, letting one valid session enumerate and read data belonging to thousands of other accounts. Task 4 extends this further: once identity itself can be forged (as with the `alg:none` and weak-secret attacks), the attacker doesn't even need a legitimate account to begin the same enumeration, showing how a broken authentication layer compounds an IDOR into a much larger-scale exposure — which is the scale Optus experienced.

3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?
Answer= The deny-by-default ownership check (L64) protects the most attack surface, because it is the *last line of defense* that holds even if authentication is somehow compromised — as Task 4 showed, a forged token still can't read someone else's order once ownership is verified server-side. Pinning the algorithm and using a strong secret only fix the authentication layer; they stop someone from forging *who* they are, but do nothing if the authorization check is missing entirely, since even a fully legitimate, correctly-signed token (like alice's real one in Task 1) can still read data it shouldn't. Server-side authorization is non-negotiable because it is the only control that can never be bypassed by manipulating something the client sends — a client can lie about its identity, forge a signature, or replay a token, but it cannot fabricate a database-side ownership match it doesn't actually have.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** __FLAG{idor_demo}____
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
  Answer= I logged in as alice to get a valid token, then simply changed the order ID in the URL from `1` to `2` and received bob's order data using alice's own credentials — this worked because `get_order` in `vulnerable_app.py` calls `current_user()` to confirm the token is valid but never compares the authenticated user against the order's owner field before returning it. I then forged two more tokens without ever knowing bob's password: one using `alg:none`, which worked because the server's decode call listed `"none"` as an acceptable algorithm and so skipped signature verification entirely, and one signed with the literal string `"secret"` as the HMAC key, which worked because that key is short and guessable enough to sign a token that passes real HS256 verification.

  2. **Why does your fix actually stop it** — and what could still break it?
  Answer= The fix stops all three attacks because each targets a different, isolated gap: the ownership check at L64 now rejects any request where the token's identity doesn't match the order's owner (closing the IDOR regardless of how "valid" the token is), the algorithm pin at L50 rejects any token whose header doesn't explicitly say `HS256` (closing the `alg:none` bypass), and the strong random secret plus required `aud`/`exp` claims (L10, L40) make brute-forcing the signing key infeasible and prevent a forged token from being accepted even if the attacker guesses at a signature. What could still break it: if the strong secret were ever leaked (e.g. committed to a public repo, logged accidentally, or reused across environments), an attacker could sign perfectly valid tokens again despite the algorithm pin — key management and rotation matter just as much as key strength. Similarly, if a future developer added a new endpoint and forgot to repeat the L64 ownership check, that endpoint would reopen the exact same IDOR even though the JWT layer stayed secure.


---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
Answer= 
> Prompt used: "How do I fix a Flask app that accepts JWTs signed with alg:none?"
>
> AI's response (paraphrased): "Just check that the algorithm in the decoded token header isn't 'none' before trusting it. You can do this by decoding the token first without verification to read the header, checking the alg field, and rejecting it if it says none."

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).
Answer= The AI's suggested fix decodes the token *without verification first* to inspect the header — this is itself dangerous, because calling `jwt.decode(token, options={"verify_signature": False})` to "peek" at the algorithm executes on attacker-controlled input before any trust decision is made, and depending on the library version this pattern has historically been the exact vector used to smuggle algorithm-confusion attacks (e.g. RS256→HS256 key confusion), not just `alg:none`. The fix also only blocks the literal string `"none"` rather than pinning to an explicit allow-list — it's a blocklist, not an allow-list, so any other algorithm the developer didn't think to exclude (or a future PyJWT version's own None-like variants) would still pass through.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
Answer= ```python
# Correct: pin the exact expected algorithm, no manual pre-decode of the header
payload = jwt.decode(
    token,
    SECRET_KEY,
    algorithms=["HS256"],   # allow-list, not a blocklist of "none"
    audience="week06-lab",
    options={"require": ["exp", "aud"]},
)
```
This is what I verified against — this is essentially the pattern used in `solution_app.py` (L50), and running `$FORGED` (alg:none) and `$FORGED2` (weak secret) against it both returned `401 invalid token` as shown in the Task 5 evidence above. The AI's blocklist approach was insufficient because it only reasons about the one attack it was told about, while `algorithms=[...]` as an explicit allow-list closes the entire class of algorithm-confusion attacks at once, not just the specific one named in the prompt.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.
Answer= This week's vulnerable endpoint checks that you're *logged in* with a real token, but never checks whether the specific order you're asking for actually *belongs to you* — so just changing the number in the URL lets you read anyone's data. On top of that, the login system trusts tokens that either have no real signature at all (`alg:none`) or are signed with an easily-guessable password (`"secret"`), so an attacker doesn't even need a real account — they can just build a fake ID card the server accepts as genuine.


**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*
Answer= > "Fix this Flask endpoint so it: (1) only accepts JWTs signed with HS256 using an explicit `algorithms=["HS256"]` allow-list — never decode with `verify_signature: False` first, (2) requires both `exp` and `aud` claims to be present via `options={"require": [...]}`, and (3) after authenticating the user, compares the authenticated username against the resource's owner field and returns 403 if they don't match. Use a cryptographically random 32+ byte secret, not a literal string. Show the corrected `current_user()` and `get_order()` functions."

**Verified result:**
Running the three attacks from Task 1–3 against the fixed code returned:
- alice's real token on `/api/orders/2` (not her order) → `403 Forbidden`
- `alg:none` forged token → `401 Invalid token`
- weak-secret forged token → `401 Invalid token`

This matches `solution_app.py`'s behavior exactly (see Task 5 evidence), confirming the prompt produced a correct, verified fix on the first pass without needing refinement.
