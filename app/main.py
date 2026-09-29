"""
PromptShield -- a reverse proxy for LLM chat completion APIs.

Drop-in shape: POST /v1/chat/completions accepts the same body an OpenAI
client sends (`{"model": ..., "messages": [...]}`), so pointing an existing
app at this proxy instead of the real API is a base-URL change, not a code
change. Inbound prompts are gated before they reach the model; outbound
completions are gated before they reach the caller. Every decision is
audit-logged (see app/audit_log.py).

Run with:
    uvicorn app.main:app --port 8000
"""
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.audit_log import get_logger
from app.llm_client import get_backend
from app.pipeline import run_pipeline
from app.policy import load_default_policy
from app.rate_limit import InMemoryRateLimiter

app = FastAPI(title="PromptShield", description="Runtime policy-enforcement proxy for LLM APIs")

_policy = load_default_policy()
_audit = get_logger()
_backend = get_backend()
_rate_limiter = InMemoryRateLimiter(
    max_requests=int(os.environ.get("PROMPTSHIELD_RATE_LIMIT", "60")),
    window_seconds=int(os.environ.get("PROMPTSHIELD_RATE_WINDOW_SECONDS", "60")),
)


@app.get("/health")
def health():
    return {"status": "ok", "backend": type(_backend).__name__, "rules_loaded": len(_policy.rules)}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    client_key = request.client.host if request.client else "unknown"
    if not _rate_limiter.allow(client_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    body = await request.json()
    messages = body.get("messages")
    if not messages:
        raise HTTPException(status_code=400, detail="Request body must include a non-empty 'messages' array")

    result = run_pipeline(messages, _policy, _audit, _backend)

    if result["blocked"]:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": f"Request blocked by PromptShield at {result['stage']} stage: {result['reason']}",
                    "type": "promptshield_policy_violation",
                    "stage": result["stage"],
                },
                "id": result["id"],
            },
        )

    return JSONResponse(status_code=200, content=result)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
