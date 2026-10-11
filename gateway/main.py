"""The API gateway: the single front door to the platform (layers 1 and 2).

Every question follows the same controlled path and each step is recorded
as a "hop" in the answer, so the caller can see exactly what happened:

    1 Client -> 2 API gateway -> 3 Guardrails -> 4 Agent team
      -> 5 Vector store -> 6 Telemetry

The gateway handles hops 1, 2, 3 and 6 itself and asks the agent service
for hops 4 and 5. It also serves the control plane console (a web page)
and a status summary of all five layers.

Start it with:  uvicorn gateway.main:create_app --factory --port 8000
"""

from __future__ import annotations

import logging
import os
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from . import guardrails, telemetry
from .security import AuditLog, KeyRing, RateLimiter, Role, fingerprint, new_request_id
from .telemetry import SPAN_KIND

MAX_QUESTION_CHARS = 1000
STATIC_DIR = Path(__file__).parent / "static"

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("gateway")


# ---------------------------------------------------------------------------
# Settings: every value comes from environment variables (the .env file).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Settings:
    analyst_key: str
    viewer_key: str
    internal_token: str
    agent_url: str = "http://agent-service:8001"
    canary_url: str = ""
    canary_percent: int = 0
    rate_limit_per_minute: int = 20
    agent_timeout_seconds: float = 60.0
    phoenix_endpoint: str = "http://phoenix:6006"
    phoenix_ui_url: str = "http://localhost:6006"
    project_name: str = "governed-secops-assistant"
    version: str = "1.0.0"
    tracing_export: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        def required(name: str) -> str:
            # Refuses missing, placeholder or short secrets (a misconfiguration control).
            value = os.getenv(name, "").strip()
            if not value or value.lower().startswith("change-me") or len(value) < 16:
                raise RuntimeError(f"{name} is missing or too weak. Set a random value of at least 16 "
                                   "characters in .env, for example the output of: openssl rand -hex 24")
            return value

        return cls(
            analyst_key=required("ANALYST_API_KEY"),
            viewer_key=required("VIEWER_API_KEY"),
            internal_token=required("INTERNAL_SERVICE_TOKEN"),
            agent_url=os.getenv("AGENT_SERVICE_URL", cls.agent_url),
            canary_url=os.getenv("AGENT_CANARY_URL", ""),
            canary_percent=max(0, min(100, int(os.getenv("CANARY_PERCENT", "0")))),
            rate_limit_per_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", "20")),
            agent_timeout_seconds=float(os.getenv("AGENT_TIMEOUT_SECONDS", "60")),
            phoenix_endpoint=os.getenv("PHOENIX_COLLECTOR_ENDPOINT", cls.phoenix_endpoint),
            phoenix_ui_url=os.getenv("PHOENIX_UI_URL", cls.phoenix_ui_url),
            project_name=os.getenv("PHOENIX_PROJECT_NAME", cls.project_name),
            version=os.getenv("APP_VERSION", cls.version),
            tracing_export=os.getenv("TRACING_EXPORT", "true").lower() == "true",
        )


# ---------------------------------------------------------------------------
# What the five layers are and which controls they enforce. The console and
# the solution design document (docs/sdd.md, section 6) use the same IDs.
# ---------------------------------------------------------------------------
LAYERS = [
    {"id": "L1", "name": "Experience", "title": "API gateway", "owner": "Platform engineering",
     "evidence": "SDD 6.1", "controls": ["C-01", "C-02", "C-03", "C-04", "C-05", "C-16"]},
    {"id": "L2", "name": "Guardrails", "title": "Policy checks", "owner": "Security engineering",
     "evidence": "SDD 6.2", "controls": ["C-06", "C-07", "C-08", "C-09"]},
    {"id": "L3", "name": "Agentic logic", "title": "Agent team", "owner": "AI engineering",
     "evidence": "SDD 6.3", "controls": ["C-10", "C-11", "C-12", "C-13"]},
    {"id": "L4", "name": "Vector RAG", "title": "Vector store", "owner": "Data platform",
     "evidence": "SDD 6.4", "controls": ["C-14", "C-15"]},
    {"id": "L5", "name": "Telemetry", "title": "Trace and audit", "owner": "Site reliability and operations",
     "evidence": "SDD 6.5", "controls": ["C-17"]},
]

CONTROLS = [
    {"id": "C-01", "name": "Access keys checked in constant time and stored only as fingerprints", "status": "pass"},
    {"id": "C-02", "name": "Documents filtered by role (analyst or viewer)", "status": "pass"},
    {"id": "C-03", "name": "Rate limit per caller", "status": "pass"},
    {"id": "C-04", "name": "Question size limit of 1,000 characters", "status": "pass"},
    {"id": "C-05", "name": "Request ID and trace ID returned with every answer", "status": "pass"},
    {"id": "C-06", "name": "Prompt injection scan on every question", "status": "pass"},
    {"id": "C-07", "name": "Personal data and secrets masked in questions and answers", "status": "pass"},
    {"id": "C-08", "name": "Requests for credentials refused", "status": "pass"},
    {"id": "C-09", "name": "Actions on live systems held for human approval", "status": "pass"},
    {"id": "C-10", "name": "Hard cap of 3 rounds and an emergency stop switch", "status": "pass"},
    {"id": "C-11", "name": "Knowledge search is the only tool the agents may use", "status": "pass"},
    {"id": "C-12", "name": "Grounding review before any answer is released", "status": "pass"},
    {"id": "C-13", "name": "Model calls to one approved address, with timeouts, retries and fallback", "status": "pass"},
    {"id": "C-14", "name": "Unsafe document text held back at loading and at search time", "status": "pass"},
    {"id": "C-15", "name": "Vector store on a network with no internet access", "status": "pass"},
    {"id": "C-16", "name": "Secret service token between gateway and agent service", "status": "pass"},
    {"id": "C-17", "name": "One trace per request across services, plus an audit log without question text", "status": "pass"},
    {"id": "C-18", "name": "Hash-checked packages, non-root images and an image scan on every push", "status": "pass"},
    {"id": "C-19", "name": "Single sign-on with multi-factor authentication for people", "status": "review",
     "note": "Access keys are used for this release; single sign-on is planned before production."},
    {"id": "C-20", "name": "Encryption between containers", "status": "review",
     "note": "Traffic stays on private container networks; TLS at the entry point and between services is planned."},
    {"id": "C-21", "name": "Login for the Phoenix dashboard", "status": "review",
     "note": "The dashboard is reachable only from the host machine; enable its login before shared use."},
]


# ---------------------------------------------------------------------------
# Request and response shapes. FastAPI checks every request against these.
# ---------------------------------------------------------------------------
class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=MAX_QUESTION_CHARS)


HopStatus = Literal["ok", "blocked", "held", "error", "skipped"]


class Hop(BaseModel):
    step: int
    name: str
    layer: str
    status: HopStatus
    ms: float
    detail: str


class Citation(BaseModel):
    number: int
    source: str
    title: str = ""
    section: str = ""
    classification: str = ""
    score: float = 0.0


class AskResponse(BaseModel):
    request_id: str
    trace_id: str
    status: str
    answer: str = ""
    citations: list[Citation] = []
    approval: dict | None = None
    role: str | None = None
    deployment_track: str | None = None
    agent_version: str | None = None
    guardrails: dict = {}
    metrics: dict = {}
    hops: list[Hop] = []


class AgentUnavailable(Exception):
    """The agent service could not be reached or failed."""


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def _skipped(step: int, name: str, layer: str, why: str) -> Hop:
    return Hop(step=step, name=name, layer=layer, status="skipped", ms=0.0, detail=why)


# ---------------------------------------------------------------------------
# The application.
# ---------------------------------------------------------------------------
def create_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None,
               rng: random.Random | None = None) -> FastAPI:
    """Builds the gateway. Tests pass their own settings and a fake transport."""
    settings = settings or Settings.from_env()
    keyring = KeyRing({Role.ANALYST: settings.analyst_key, Role.VIEWER: settings.viewer_key})
    limiter = RateLimiter(settings.rate_limit_per_minute)
    audit = AuditLog()
    rng = rng or random.Random()

    telemetry.setup_tracing("gateway", settings.phoenix_endpoint, settings.project_name,
                            settings.version, export=settings.tracing_export)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # One shared HTTP client for calls to the agent service and Phoenix.
        app.state.http = httpx.AsyncClient(transport=transport, timeout=settings.agent_timeout_seconds)
        yield
        await app.state.http.aclose()
        telemetry.flush()

    app = FastAPI(title="Governed security operations assistant: gateway", version=settings.version,
                  lifespan=lifespan, telemetry=telemetry.web_framework_settings())

    # ----------------------------------------------------------------- pages
    @app.get("/", include_in_schema=False)
    async def console() -> FileResponse:
        return FileResponse(STATIC_DIR / "console.html")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "gateway", "version": settings.version}

    # ----------------------------------------------------------- the path
    def choose_track() -> tuple[str, str]:
        """Sends CANARY_PERCENT of requests to the canary agent service, if one is set."""
        if settings.canary_url and rng.random() * 100 < settings.canary_percent:
            return "canary", settings.canary_url
        return "stable", settings.agent_url

    async def call_agents(url: str, payload: dict) -> dict:
        headers = telemetry.inject_trace_headers({"X-Internal-Token": settings.internal_token})
        try:
            response = await app.state.http.post(f"{url}/v1/run", json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise AgentUnavailable(str(error)) from error

    def telemetry_hop(start: float, trace_id: str) -> Hop:
        return Hop(step=6, name="Telemetry", layer="telemetry", status="ok", ms=_ms(start),
                   detail=f"trace {trace_id[:12]} recorded for Phoenix; audit event written")

    @app.post("/v1/ask", response_model=AskResponse)
    async def ask(body: AskRequest, x_api_key: str | None = Header(default=None)):
        started = time.perf_counter()
        request_id = new_request_id()
        tracer = telemetry.get_tracer()
        hops: list[Hop] = []

        with tracer.start_as_current_span("gateway.request") as root:
            root.set_attribute(SPAN_KIND, "CHAIN")
            root.set_attribute("request.id", request_id)
            trace_id = telemetry.trace_id_of(root)
            hops.append(Hop(step=1, name="Client", layer="client", status="ok", ms=0.0,
                            detail=f"question received ({len(body.question)} characters)"))

            # Hop 2: who is calling and are they within their limit?
            t = time.perf_counter()
            with tracer.start_as_current_span("api_gateway.access_check") as span:
                span.set_attribute(SPAN_KIND, "CHAIN")
                role = keyring.identify(x_api_key)
                if role is None:
                    span.set_attribute("access.allowed", False)
                    audit.record("access_denied", request_id=request_id, trace_id=trace_id,
                                 reason="missing or unknown access key")
                    return JSONResponse(status_code=401, content={
                        "request_id": request_id, "trace_id": trace_id, "status": "denied",
                        "detail": "A valid X-API-Key header is required."})
                allowed, remaining = limiter.check(fingerprint(x_api_key)[:16])
                span.set_attribute("access.role", role.value)
                span.set_attribute("access.allowed", allowed)
                if not allowed:
                    audit.record("rate_limited", request_id=request_id, trace_id=trace_id, role=role.value)
                    return JSONResponse(status_code=429, content={
                        "request_id": request_id, "trace_id": trace_id, "status": "rate_limited",
                        "detail": f"Limit of {settings.rate_limit_per_minute} requests per minute reached."})
            hops.append(Hop(step=2, name="API gateway", layer="experience", status="ok", ms=_ms(t),
                            detail=f"role {role.value}; {remaining} requests left this minute"))

            # Hop 3: guardrails on the question.
            t = time.perf_counter()
            with tracer.start_as_current_span("guardrails.input_check") as span:
                span.set_attribute(SPAN_KIND, "GUARDRAIL")
                decision = guardrails.evaluate_input(body.question)
                span.set_attribute("guardrail.allowed", decision.allowed)
                span.set_attribute("guardrail.rules", decision.rules_triggered)
                span.set_attribute("guardrail.personal_data_masked", sum(decision.personal_data_masked.values()))
            guard_info = {"rules_triggered": decision.rules_triggered, "reasons": decision.reasons,
                          "personal_data_masked": decision.personal_data_masked,
                          "requires_approval": decision.requires_approval}

            if not decision.allowed:
                hops.append(Hop(step=3, name="Guardrails", layer="guardrails", status="blocked",
                                ms=_ms(t), detail="; ".join(decision.reasons)))
                hops.append(_skipped(4, "Agent team", "agentic_logic", "not reached: stopped by the guardrails"))
                hops.append(_skipped(5, "Vector store", "vector_rag", "not reached: stopped by the guardrails"))
                t6 = time.perf_counter()
                audit.record("request_blocked", request_id=request_id, trace_id=trace_id, role=role.value,
                             rules=decision.rules_triggered, question_chars=len(body.question),
                             question_fingerprint=fingerprint(body.question)[:16])
                hops.append(telemetry_hop(t6, trace_id))
                root.set_attribute("output.value", "blocked")
                blocked = AskResponse(
                    request_id=request_id, trace_id=trace_id, status="blocked",
                    answer="This question was blocked by the security policy: " + "; ".join(decision.reasons) + ".",
                    role=role.value, guardrails=guard_info, hops=hops,
                    metrics={"latency_ms": _ms(started), "model_calls": 0, "tool_calls": 0})
                return JSONResponse(status_code=400, content=blocked.model_dump())

            detail = "no injection found"
            masked_total = sum(decision.personal_data_masked.values())
            if masked_total:
                detail += f"; {masked_total} personal data item(s) masked"
            if decision.requires_approval:
                detail += "; action request held for approval (POL-01)"
            hops.append(Hop(step=3, name="Guardrails", layer="guardrails",
                            status="held" if decision.requires_approval else "ok", ms=_ms(t), detail=detail))
            root.set_attribute("input.value", decision.masked_question)

            # Hops 4 and 5: the agent service does the work.
            payload = {"question": decision.masked_question, "role": role.value, "request_id": request_id,
                       "requires_approval": decision.requires_approval,
                       "policy_reasons": decision.reasons}
            track, url = choose_track()
            canary_fallback = False
            try:
                result = await call_agents(url, payload)
            except AgentUnavailable as error:
                if track == "canary":
                    # Resilience: a failing canary must never cost the user an answer.
                    logger.warning("canary failed, retrying on stable: %s", error)
                    canary_fallback, track = True, "stable"
                    try:
                        result = await call_agents(settings.agent_url, payload)
                    except AgentUnavailable as second:
                        error = second
                        result = None
                else:
                    result = None
                if result is None:
                    hops.append(Hop(step=4, name="Agent team", layer="agentic_logic", status="error",
                                    ms=0.0, detail="agent service unavailable"))
                    hops.append(_skipped(5, "Vector store", "vector_rag", "not reached"))
                    t6 = time.perf_counter()
                    audit.record("agent_unavailable", request_id=request_id, trace_id=trace_id, error=str(error))
                    hops.append(telemetry_hop(t6, trace_id))
                    failed = AskResponse(request_id=request_id, trace_id=trace_id, status="unavailable",
                                         answer="The agent service is unavailable. Please try again shortly.",
                                         role=role.value, guardrails=guard_info, hops=hops,
                                         metrics={"latency_ms": _ms(started)})
                    return JSONResponse(status_code=503, content=failed.model_dump())

            # Guardrails on the answer before it leaves.
            with tracer.start_as_current_span("guardrails.output_check") as span:
                span.set_attribute(SPAN_KIND, "GUARDRAIL")
                out = guardrails.filter_output(result.get("answer", ""))
                span.set_attribute("guardrail.personal_data_masked", sum(out.personal_data_masked.values()))
            guard_info["answer_personal_data_masked"] = out.personal_data_masked

            hops.extend(Hop(**hop) for hop in result.get("hops", []))

            # Hop 6: the audit record. The trace itself is exported when this
            # request's spans close, in the background.
            t6 = time.perf_counter()
            metrics = dict(result.get("metrics", {}))
            metrics["latency_ms"] = _ms(started)
            audit.record("request_completed", request_id=request_id, trace_id=trace_id, role=role.value,
                         status=result.get("status"), track=track, canary_fallback=canary_fallback,
                         rounds=metrics.get("rounds_used"), model_calls=metrics.get("model_calls"),
                         grounding_score=metrics.get("grounding_score"), latency_ms=metrics["latency_ms"],
                         question_chars=len(body.question),
                         question_fingerprint=fingerprint(body.question)[:16],
                         personal_data_masked=decision.personal_data_masked)
            hops.append(telemetry_hop(t6, trace_id))
            root.set_attribute("output.value", out.masked_answer)
            root.set_attribute("deployment.track", track)

        return AskResponse(
            request_id=request_id, trace_id=trace_id, status=result.get("status", "answered"),
            answer=out.masked_answer, citations=result.get("citations", []), approval=result.get("approval"),
            role=role.value, deployment_track=track + (" after canary failure" if canary_fallback else ""),
            agent_version=result.get("version"), guardrails=guard_info, metrics=metrics,
            hops=sorted(hops, key=lambda h: h.step))

    # ------------------------------------------------------------ status
    async def _get_json(url: str) -> dict | None:
        try:
            response = await app.state.http.get(url, timeout=5)
            response.raise_for_status()
            return response.json() if "json" in response.headers.get("content-type", "") else {"ok": True}
        except (httpx.HTTPError, ValueError):
            return None

    @app.get("/v1/status")
    async def status(x_api_key: str | None = Header(default=None)):
        role = keyring.identify(x_api_key)
        if role is None:
            return JSONResponse(status_code=401, content={"detail": "A valid X-API-Key header is required."})
        agent = await _get_json(f"{settings.agent_url}/health")
        phoenix_ok = await _get_json(f"{settings.phoenix_endpoint}/healthz") is not None
        guard_ok = guardrails.self_test()
        vector = (agent or {}).get("vector_store", {})

        states = {
            "L1": ("healthy", f"version {settings.version}; rate limit {settings.rate_limit_per_minute} per minute"),
            "L2": ("healthy" if guard_ok else "down", "self-test passed" if guard_ok else "self-test failed"),
            "L3": ("down", "agent service unreachable") if agent is None else (
                "stopped" if agent.get("kill_switch") else "healthy",
                f"model: {agent.get('model_mode')}; round cap {agent.get('max_rounds')}"
                + ("; emergency stop is ON" if agent.get("kill_switch") else "")),
            "L4": ("healthy" if vector.get("ready") else "down",
                   f"{vector.get('passages', 0)} passages from {vector.get('documents', 0)} documents"),
            "L5": ("healthy" if phoenix_ok else "down", f"Phoenix project {settings.project_name}"),
        }
        layers = [dict(layer, state=states[layer["id"]][0], detail=states[layer["id"]][1]) for layer in LAYERS]
        passed = sum(1 for c in CONTROLS if c["status"] == "pass")
        return {
            "service": "gateway", "version": settings.version, "role": role.value,
            "layers": layers, "controls": CONTROLS,
            "summary": {"controls_total": len(CONTROLS), "controls_passed": passed, "hops": 6, "layers": 5},
            "counters": dict(audit.totals),
            "deployment": {"canary_percent": settings.canary_percent if settings.canary_url else 0,
                           "agent_version": (agent or {}).get("version")},
            "phoenix_url": settings.phoenix_ui_url, "project": settings.project_name,
        }

    return app
