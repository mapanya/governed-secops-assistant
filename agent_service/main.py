"""The agent service: layers 3 (agentic logic) and 4 (vector RAG).

It is reachable only inside the container network, never from a browser.
It accepts work only from the gateway: every request must carry the
shared internal service token. It continues the gateway's trace, runs the
question through the agent graph and returns the answer together with
hops 4 (agent team) and 5 (vector store) of the request path.

Start it with:  uvicorn agent_service.main:create_app --factory --port 8001
"""

from __future__ import annotations

import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import telemetry
from .graph import GraphSettings, build_graph, run
from .llm import GeminiWriter, ResilientWriter
from .telemetry import SPAN_KIND
from .vector_store import KnowledgeStore, StoreSettings

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("agent-service")

# The agent service decides clearance itself from the role, rather than
# trusting a list sent by the caller (defence in depth).
ROLE_CLEARANCE = {"analyst": ["public", "internal"], "viewer": ["public"]}


@dataclass(frozen=True)
class AgentSettings:
    internal_token: str
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash"
    llm_timeout_seconds: float = 20.0
    llm_max_attempts: int = 3
    max_rounds: int = 3
    kill_switch: bool = False
    grounding_threshold: float = 0.7
    price_per_1k_input_usd: float = 0.0
    price_per_1k_output_usd: float = 0.0
    version: str = "1.0.0"
    track: str = "stable"
    phoenix_endpoint: str = "http://phoenix:6006"
    project_name: str = "governed-secops-assistant"
    tracing_export: bool = True

    @classmethod
    def from_env(cls) -> "AgentSettings":
        token = os.getenv("INTERNAL_SERVICE_TOKEN", "").strip()
        if not token or token.lower().startswith("change-me") or len(token) < 16:
            raise RuntimeError("INTERNAL_SERVICE_TOKEN is missing or too weak. Set a random value of at least "
                               "16 characters in .env, for example the output of: openssl rand -hex 24")
        flag = lambda name: os.getenv(name, "false").strip().lower() in {"1", "true", "yes", "on"}  # noqa: E731
        return cls(
            internal_token=token,
            gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
            gemini_model=os.getenv("GEMINI_MODEL", cls.gemini_model),
            llm_timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "20")),
            llm_max_attempts=int(os.getenv("LLM_MAX_ATTEMPTS", "3")),
            max_rounds=int(os.getenv("MAX_ROUNDS", "3")),
            kill_switch=flag("AGENTS_KILL_SWITCH"),
            grounding_threshold=float(os.getenv("GROUNDING_THRESHOLD", "0.7")),
            price_per_1k_input_usd=float(os.getenv("PRICE_PER_1K_INPUT_TOKENS_USD", "0")),
            price_per_1k_output_usd=float(os.getenv("PRICE_PER_1K_OUTPUT_TOKENS_USD", "0")),
            version=os.getenv("AGENT_VERSION", cls.version),
            track=os.getenv("DEPLOYMENT_TRACK", cls.track),
            phoenix_endpoint=os.getenv("PHOENIX_COLLECTOR_ENDPOINT", cls.phoenix_endpoint),
            project_name=os.getenv("PHOENIX_PROJECT_NAME", cls.project_name),
            tracing_export=os.getenv("TRACING_EXPORT", "true").lower() == "true",
        )


class RunRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    role: Literal["analyst", "viewer"]
    request_id: str = Field(min_length=8, max_length=64)
    requires_approval: bool = False
    policy_reasons: list[str] = []


def create_app(settings: AgentSettings | None = None, store=None, writer: ResilientWriter | None = None) -> FastAPI:
    """Builds the agent service. Tests pass a stand-in store and writer."""
    settings = settings or AgentSettings.from_env()
    telemetry.setup_tracing(f"agent-service-{settings.track}", settings.phoenix_endpoint, settings.project_name,
                            settings.version, export=settings.tracing_export)
    if writer is None:
        primary = None
        if settings.gemini_api_key:
            primary = GeminiWriter(settings.gemini_api_key, settings.gemini_model,
                                   settings.llm_timeout_seconds, settings.llm_max_attempts)
        writer = ResilientWriter(primary)
    store = store or KnowledgeStore(StoreSettings.from_env())
    graph_settings = GraphSettings(max_rounds=settings.max_rounds, kill_switch=settings.kill_switch,
                                   grounding_threshold=settings.grounding_threshold,
                                   price_per_1k_input_usd=settings.price_per_1k_input_usd,
                                   price_per_1k_output_usd=settings.price_per_1k_output_usd)
    graph = build_graph(store, writer, graph_settings)
    stats_cache: dict = {"at": 0.0, "value": None}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        telemetry.flush()
        if hasattr(store, "close"):
            store.close()

    app = FastAPI(title="Governed security operations assistant: agent service", version=settings.version,
                  lifespan=lifespan, telemetry=telemetry.web_framework_settings())

    def vector_stats() -> dict:
        """Store statistics, cached for 10 seconds so health checks stay light."""
        if time.monotonic() - stats_cache["at"] > 10 or stats_cache["value"] is None:
            try:
                stats_cache["value"] = store.stats()
            except Exception as error:  # store not reachable yet
                stats_cache["value"] = {"ready": False, "passages": 0, "documents": 0, "error": str(error)[:120]}
            stats_cache["at"] = time.monotonic()
        return stats_cache["value"]

    @app.get("/health")
    def health() -> dict:
        vector = vector_stats()
        return {"status": "ok" if vector.get("ready") else "degraded", "service": "agent-service",
                "version": settings.version, "track": settings.track, "kill_switch": settings.kill_switch,
                "max_rounds": settings.max_rounds, "model_mode": writer.mode, "vector_store": vector}

    @app.get("/ready")
    def ready():
        """Ready only once documents are loaded; Kubernetes holds traffic back until then."""
        vector = vector_stats()
        return JSONResponse(status_code=200 if vector.get("ready") else 503, content={"ready": bool(vector.get("ready"))})

    @app.post("/v1/run")
    def run_question(body: RunRequest, request: Request, background: BackgroundTasks,
                     x_internal_token: str | None = Header(default=None)):
        if not x_internal_token or not hmac.compare_digest(x_internal_token, settings.internal_token):
            return JSONResponse(status_code=401, content={"detail": "Only the gateway may call this service."})

        started = time.perf_counter()
        tracer = telemetry.get_tracer()
        context = telemetry.extract_trace_context(request.headers)
        with tracer.start_as_current_span("agent_service.run", context=context) as span:
            span.set_attribute(SPAN_KIND, "AGENT")
            span.set_attribute("request.id", body.request_id)
            span.set_attribute("deployment.track", settings.track)
            span.set_attribute("agent.version", settings.version)
            span.set_attribute("input.value", body.question)
            state = run(graph, graph_settings, question=body.question, clearance=ROLE_CLEARANCE[body.role],
                        request_id=body.request_id, requires_approval=body.requires_approval,
                        policy_reasons=body.policy_reasons)
            final = state.get("final", {})
            span.set_attribute("output.value", final.get("answer", ""))
            span.set_attribute("agent.status", state.get("status", ""))

        total_ms = round((time.perf_counter() - started) * 1000, 1)
        timings, metrics, status = state.get("timings", {}), state.get("metrics", {}), state.get("status", "")
        vector_ms = timings.get("vector_ms", 0.0)

        # Hop 4: the agent team.
        if status == "pending_approval":
            hop4_status, detail = "held", f"Planner sent the request for human approval ({final['approval']['ticket_id']})"
        elif status == "halted":
            hop4_status, detail = "blocked", f"stopped safely: {state.get('halt_reason', '').replace('_', ' ')}"
        else:
            hop4_status = "ok"
            detail = (f"Planner, Executor, Reviewer; {metrics.get('rounds_used', 0)} round(s); "
                      f"{metrics.get('model_calls', 0)} model call(s); grounding {metrics.get('grounding_score')}")
            if metrics.get("fallback_used"):
                detail += "; quoted-passage answer"
        hops = [{"step": 4, "name": "Agent team", "layer": "agentic_logic", "status": hop4_status,
                 "ms": round(total_ms - vector_ms, 1), "detail": detail}]

        # Hop 5: the vector store.
        if "vector_error" in timings:
            hops.append({"step": 5, "name": "Vector store", "layer": "vector_rag", "status": "error",
                         "ms": vector_ms, "detail": "knowledge search failed"})
        elif "vector_ms" in timings:
            hops.append({"step": 5, "name": "Vector store", "layer": "vector_rag", "status": "ok",
                         "ms": vector_ms, "detail": timings.get("vector_detail", "")})
        else:
            why = "not needed: request held for approval" if status == "pending_approval" else "not reached"
            hops.append({"step": 5, "name": "Vector store", "layer": "vector_rag", "status": "skipped",
                         "ms": 0.0, "detail": why})

        # Record the grounding score in Phoenix after the answer has gone back.
        review = state.get("review") or {}
        if settings.tracing_export and state.get("reviewer_span_id") and review:
            background.add_task(telemetry.record_grounding_score, settings.phoenix_endpoint,
                                state["reviewer_span_id"], review.get("score", 0.0), review.get("approved", False),
                                "; ".join(review.get("issues", [])) or "all sentences supported by cited passages")

        logger.info('{"event": "agent_run", "request_id": "%s", "status": "%s", "rounds": %s, "ms": %s}',
                    body.request_id, status, metrics.get("rounds_used"), total_ms)
        return {"status": status, "answer": final.get("answer", ""), "citations": final.get("citations", []),
                "approval": final.get("approval"), "hops": hops, "metrics": metrics,
                "version": settings.version, "track": settings.track}

    return app
