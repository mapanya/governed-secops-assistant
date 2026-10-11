"""Tracing for the agent service (layer 5, telemetry).

This works exactly like gateway/telemetry.py: spans go to Phoenix in the
background. The difference is that the agent service never starts its own
trace for a question. It continues the trace the gateway started, using
the "traceparent" header the gateway sends, so both services appear in one
trace. Each service keeps its own copy of this file because each runs in
its own container with no shared code.

It also records the Reviewer's grounding score in Phoenix as an evaluation,
in the same way the monitored retrieval service recorded its relevance score.
"""

from __future__ import annotations

import logging
import time

import httpx
from opentelemetry import propagate, trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Phoenix reads this span attribute to show what kind of step a span is.
SPAN_KIND = "openinference.span.kind"

logger = logging.getLogger(__name__)
_provider: TracerProvider | None = None


# FastAPI records its own span for every web request. Health checks repeat
# every few seconds and the console asks for status often, so these requests
# are left out to keep Phoenix focused on real questions. FastAPI's internal step spans
# (dependencies, serialization) are left out for the same reason.
QUIET_PATHS = frozenset({"/", "/health", "/ready", "/v1/status"})


def web_framework_settings() -> dict:
    """Settings for FastAPI's built-in tracing (passed as FastAPI(telemetry=...))."""
    return {"operation_spans": False, "exclude": lambda scope: scope.get("path") in QUIET_PATHS}


def setup_tracing(service_name: str, collector_endpoint: str, project_name: str, version: str,
                  export: bool = True) -> None:
    """Creates the tracer once at start-up (see gateway/telemetry.py)."""
    global _provider
    if _provider is not None:
        return
    resource = Resource.create({"service.name": service_name, "service.version": version,
                                "openinference.project.name": project_name})
    _provider = TracerProvider(resource=resource)
    if export:
        exporter = OTLPSpanExporter(endpoint=collector_endpoint.rstrip("/") + "/v1/traces", timeout=30)
        _provider.add_span_processor(BatchSpanProcessor(exporter, schedule_delay_millis=1000))
    trace.set_tracer_provider(_provider)


def get_tracer():
    return trace.get_tracer("agent-service")


def trace_id_of(span) -> str:
    return format(span.get_span_context().trace_id, "032x")


def span_id_of(span) -> str:
    return format(span.get_span_context().span_id, "016x")


def extract_trace_context(headers) -> Context:
    """Continues the gateway's trace from the incoming traceparent header."""
    return propagate.extract(headers)


def flush(timeout_ms: int = 3000) -> None:
    if _provider is not None:
        _provider.force_flush(timeout_ms)


def record_grounding_score(phoenix_endpoint: str, span_id: str, score: float, approved: bool,
                           explanation: str, attempts: int = 4, wait_seconds: float = 2.0) -> bool:
    """Attaches the Reviewer's grounding score to its span in Phoenix.

    Runs after the answer has been sent. The span must reach Phoenix before
    a score can be attached to it, so this flushes the span first and tries
    a few times. A failure here is logged and never affects the answer.
    """
    flush()
    body = {"data": [{
        "span_id": span_id,
        "name": "grounding",
        "annotator_kind": "CODE",
        "result": {"label": "grounded" if approved else "not grounded", "score": round(score, 3),
                   "explanation": explanation[:500]},
    }]}
    url = phoenix_endpoint.rstrip("/") + "/v1/span_annotations"
    for attempt in range(1, attempts + 1):
        try:
            response = httpx.post(url, params={"sync": "true"}, json=body, timeout=5)
            if response.status_code < 300:
                return True
            logger.info("grounding score not stored yet (attempt %s): %s", attempt, response.status_code)
        except httpx.HTTPError as error:
            logger.info("grounding score not stored yet (attempt %s): %s", attempt, error)
        time.sleep(wait_seconds)
    return False
