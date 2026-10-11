"""Tracing for the gateway (layer 5, telemetry).

OpenTelemetry is an open standard for recording what a program does as a
tree of timed steps called spans. The full tree for one request is a trace.
Phoenix receives the spans over HTTP and shows them on its dashboard.

The gateway starts every trace. When it calls the agent service it passes
the trace ID along in a standard request header ("traceparent"), so the
agent service adds its own spans to the same trace. One request therefore
appears in Phoenix as a single trace that crosses both services.
"""

from __future__ import annotations

import logging

from opentelemetry import propagate, trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Phoenix reads this span attribute to show what kind of step a span is,
# for example GUARDRAIL, AGENT, RETRIEVER or LLM.
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


def setup_tracing(
    service_name: str,
    collector_endpoint: str,
    project_name: str,
    version: str,
    export: bool = True,
) -> None:
    """Creates the tracer once at start-up.

    With export=False spans are still created (so trace IDs exist) but
    nothing is sent anywhere. The unit tests use this setting.
    """
    global _provider
    if _provider is not None:
        return
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": version,
            # Phoenix files every span under this project name.
            "openinference.project.name": project_name,
        }
    )
    _provider = TracerProvider(resource=resource)
    if export:
        exporter = OTLPSpanExporter(
            endpoint=collector_endpoint.rstrip("/") + "/v1/traces", timeout=30
        )
        # Spans are sent in small batches in the background, so a slow or
        # missing dashboard never slows down an answer.
        _provider.add_span_processor(BatchSpanProcessor(exporter, schedule_delay_millis=1000))
    trace.set_tracer_provider(_provider)


def get_tracer():
    """Returns the tracer used to open spans in this service."""
    return trace.get_tracer("gateway")


def trace_id_of(span) -> str:
    """Returns the trace ID as the 32-character text Phoenix displays."""
    return format(span.get_span_context().trace_id, "032x")


def inject_trace_headers(headers: dict[str, str]) -> dict[str, str]:
    """Adds the traceparent header so the next service joins this trace."""
    propagate.inject(headers)
    return headers


def extract_trace_context(headers) -> Context:
    """Reads an incoming traceparent header, if there is one."""
    return propagate.extract(headers)


def flush(timeout_ms: int = 3000) -> None:
    """Sends any spans still waiting in the batch. Used at shutdown."""
    if _provider is not None:
        _provider.force_flush(timeout_ms)
