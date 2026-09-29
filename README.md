# PromptShield

**A runtime policy-enforcement proxy for LLM APIs — real-time detection and blocking of prompt injection, jailbreaks, and sensitive-data leakage.**

> Status: early / active development. Detection engine, policy DSL,
> enforcement, audit logging, rate limiting, the FastAPI proxy, and the CI
> gate are all working end to end (42 passing tests + a measured benchmark
> — see [Benchmark results](#benchmark-results)). Real Sentinel ingestion
> and the OpenAI backend use standard, well-tested SDKs but haven't been
> run against live production traffic. See [Roadmap](#roadmap) for what's
> real today vs. planned.

## The problem

Detecting bad LLM traffic after the fact — reviewing logs, alerting on
patterns already seen — isn't enough once an LLM feature is in production.
By the time a Sentinel alert fires, the injected prompt already ran and the
leaked secret already left the building. This project is the runtime
control layer: a policy-enforcement point that sits between the caller and
the model, so a bad request never reaches the LLM and a bad completion
never reaches the caller.

## What it does

1. **Inspects every inbound prompt** for direct prompt injection and
   jailbreak framing (a curated, transparent pattern library — see
   [Limitations](#limitations-stated-honestly) for why this is rule-based
   rather than a trained classifier), encoded-payload obfuscation
   (base64/rot13, decoded and re-scanned rather than just flagged as
   "contains base64"), and PII (regex, with a Luhn-validated credit-card
   check to cut false positives, plus optional Presidio enrichment).
2. **Inspects every outbound completion** for leaked secrets (API key
   formats for OpenAI/AWS/GitHub/Slack, private key blocks, generic
   `api_key=` assignments) and system-prompt recitation (fuzzy-matched
   against the configured system prompt, not naive substring search).
3. **Enforces a YAML policy** — `allow` / `redact` / `block` / `flag` per
   detector, evaluated the same "policy as code" way as this author's
   RiskWeave project's Kyverno gate: rules are data, not buried in
   conditionals. A `redact` action with nothing precise to redact fails
   safe to `block` rather than silently letting the original text through.
4. **Logs every decision as structured JSON**, in a schema designed to
   ship straight into the same Sentinel workspace as this author's
   Meridian project — see [`queries/promptshield_detections.kql`](queries/promptshield_detections.kql).
5. **Rate-limits per client** (in-memory for this MVP — see roadmap).
6. Ships as a **drop-in OpenAI-compatible reverse proxy**: `POST
   /v1/chat/completions` accepts the same body shape the OpenAI SDK sends,
   so pointing an existing app at it is a base-URL change, not a rewrite.

## Architecture

```
 Caller ──► PromptShield /v1/chat/completions
              │
              ├─► inbound gate (injection, obfuscation, pii)
              │       │
              │       ├─ policy.yaml ──► block / redact / flag / allow
              │       └─ audit_log.py (JSONL) ──► Sentinel / KQL
              │
              ├─► upstream LLM (mock backend for dev/CI, or real OpenAI/
              │    Azure OpenAI/compatible endpoint)
              │
              └─► outbound gate (secrets, system_prompt_leak, pii)
                      │
                      ├─ policy.yaml ──► block / redact / flag / allow
                      └─ audit_log.py (JSONL) ──► Sentinel / KQL
```

## Quick start

```bash
git clone <this repo>
cd promptshield
cp .env.example .env
pip install -r requirements.txt

uvicorn app.main:app --port 8000
curl http://127.0.0.1:8000/health
```

No LLM provider account needed to try it — see
[`demo/DEMO_WALKTHROUGH.md`](demo/DEMO_WALKTHROUGH.md) for a 5-minute
walkthrough using the built-in mock backend, including the CLI demo
chatbot and the detection benchmark.

To point it at a real model:

```bash
export PROMPTSHIELD_BACKEND=openai
export OPENAI_API_KEY=sk-...
# Azure OpenAI / any OpenAI-compatible endpoint:
# export OPENAI_BASE_URL=https://your-resource.openai.azure.com/...
uvicorn app.main:app --port 8000
```

## Policy DSL

```yaml
# policies/default.yaml
rules:
  - id: block-direct-injection
    match: inbound
    detector: injection
    min_confidence: 0.5
    action: block

  - id: redact-inbound-pii
    match: inbound
    detector: pii
    min_confidence: 0.4
    action: redact
```

Rules are evaluated in file order per `(match, detector)` pair — put your
strictest rule first. See [`app/policy.py`](app/policy.py) for the exact
semantics and [`policies/default.yaml`](policies/default.yaml) for the
full default rule set.

## Benchmark results

```
python scripts/run_benchmark.py
```

Measured against [`demo/benchmark_dataset.jsonl`](demo/benchmark_dataset.jsonl)
— 40 hand-built examples across 9 distinct injection/jailbreak techniques,
half of them benign sentences deliberately written to include trigger words
("ignore," "instructions") in ordinary contexts, specifically to measure
the false-positive rate honestly rather than only the catch rate:

| Metric | Result |
|---|---|
| Accuracy | 87.5% |
| Precision | 100.0% (zero false positives on this set) |
| Recall | 75.0% (5 of 20 attacks missed — see script output for which) |
| Avg detector latency | ~0.07 ms/request |

**What this number is and isn't:** this is a real, reproducible measurement
against a small, hand-built, synthetic dataset — not a published benchmark,
and not a claim about performance against real-world adversarial traffic at
scale. Report it as exactly that. The zero-false-positive result is by
design: `default.yaml`'s thresholds are deliberately conservative (a single
weak-signal pattern match alone doesn't cross the 0.5 block threshold),
trading some recall for not blocking legitimate traffic — a defensible
tradeoff to explain in an interview, not a number to inflate past what it
actually measured.

## CI gate

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs the full test
suite and the benchmark script on every push — the benchmark is
informational there (it doesn't fail the build), but wiring a minimum
threshold in is a one-line change once you have a larger eval set to trust.

## Limitations (stated honestly)

- Injection/jailbreak detection is a curated, rule-based pattern library,
  not a trained classifier. It's transparent and auditable (you can read
  every pattern in `app/detectors/injection.py`), but it will miss novel
  phrasing a classifier trained on more examples might catch — see the
  benchmark's 5 false negatives, all of which used a single weak signal
  that stayed under the block threshold by design.
- The rate limiter is in-memory and per-instance — it does not coordinate
  across multiple proxy replicas. A shared-store backend (Redis is the
  obvious choice) is needed before this runs behind a load balancer with
  more than one instance.
- PII detection is regex-based by default; the optional Presidio layer
  requires an extra, heavy dependency this project doesn't require you to
  install.
- System-prompt-leak detection is a fuzzy string-similarity check, not
  semantic — it can miss a paraphrased leak and can, in principle,
  false-positive on a completion that happens to closely restate long
  stretches of a very generic system prompt.

## Roadmap

- [x] Injection/jailbreak pattern detector
- [x] Obfuscated-payload (base64/rot13) detection
- [x] PII detection with Luhn-validated credit-card matching
- [x] Secrets and system-prompt-leak detection (outbound)
- [x] YAML policy DSL with block/redact/flag/allow
- [x] Structured JSONL audit logging + KQL query examples
- [x] In-memory rate limiting
- [x] FastAPI OpenAI-compatible proxy
- [x] Mock backend for dependency-free tests/demo
- [x] Detection benchmark script with honest precision/recall/latency reporting
- [ ] Lightweight ML jailbreak classifier as a second detection layer, evaluated against the same benchmark for an honest before/after comparison
- [ ] Redis-backed rate limiting for multi-instance deployments
- [ ] Live Sentinel dashboard consuming `queries/promptshield_detections.kql`

## Why this exists

RiskWeave correlates vulnerability, exposure, and RBAC context so a
container security team can prioritize what's actually dangerous instead of
drowning in isolated CVE alerts. ModelGuard applies the same idea to model
supply-chain risk. PromptShield is the runtime counterpart to both: once a
risk is understood, something has to actually stop the bad request at the
door. Most teams shipping LLM features today have detection (logging,
after-the-fact review) but not enforcement — this project is what
enforcement looks like, built the same "policy as code, transparent
scoring, honest about its own limits" way as the rest of this author's
security tooling.

## Author

**Lokesh Sivaprakash**

Part of a three-project AI security portfolio alongside
[RiskWeave](https://github.com/LokeshSivaprakash/riskweave) (software
supply-chain risk) and ModelGuard (AI/ML supply-chain risk). Feedback,
issues, and PRs are welcome.

## License

MIT — see [LICENSE](LICENSE).
