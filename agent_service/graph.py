"""Layer 3: the agent team, wired together with LangGraph.

This follows the pattern of the guardrailed multi-agent system: three
workers (Planner, Executor, Reviewer), a budget gate that counts rounds and
stops after a hard cap of 3, an emergency stop switch and a fixed, safe
fallback answer. It adds a human approval step for requests that would
change a live system.

    START -> planner --(answer)----> budget_gate --(round <= 3)--> executor -> reviewer
               |                          |                                      |
               |--(approval needed)--> human_approval -> END                     |--(approved)--> finalize -> END
               |--(emergency stop)---> fallback -> END   <--(round > 3)--|       |--(rejected)--> budget_gate

The workers are plain Python classes. Only the Executor calls the language
model, at most once per round and only the Executor may use a tool: the
knowledge search (layer 4). Every reply is checked against a strict
Pydantic schema before the next step uses it.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from . import telemetry
from .llm import NOT_IN_DOCUMENTS, ResilientWriter, content_words, split_sentences
from .telemetry import SPAN_KIND
from .vector_store import Passage, injection_reasons

NOT_FOUND_ANSWER = (
    "The approved documents available to your role do not cover this question. "
    "Please ask the security operations shift lead."
)


# ---------------------------------------------------------------------------
# Strict output schemas: every worker's reply must match one of these.
# ---------------------------------------------------------------------------
class PlannerOutput(BaseModel):
    route: Literal["answer", "human_approval"]
    search_query: str
    clearance: list[str]
    steps: list[str]


class Citation(BaseModel):
    number: int
    source: str
    title: str = ""
    section: str = ""
    classification: str = ""
    score: float = 0.0


class ExecutorOutput(BaseModel):
    answer: str
    citations: list[Citation]
    not_found: bool = False
    model: str
    fallback_used: bool = False
    fallback_reason: str = ""


class ReviewerOutput(BaseModel):
    approved: bool
    score: float = Field(ge=0.0, le=1.0)
    issues: list[str]


class ApprovalTicket(BaseModel):
    ticket_id: str
    status: Literal["pending"] = "pending"
    reason: str
    note: str = ("No action has been taken. A shift lead or incident manager must approve this "
                 "request in the case management system before anyone carries it out.")


class AgentState(TypedDict, total=False):
    question: str
    clearance: list[str]
    requires_approval: bool
    policy_reasons: list[str]
    request_id: str
    plan: dict
    passages: list[Passage]
    draft: dict
    review: dict
    execution_count: int
    max_rounds: int
    halt_reason: str
    status: str
    final: dict
    metrics: dict
    timings: dict
    reviewer_span_id: str


@dataclass(frozen=True)
class GraphSettings:
    max_rounds: int = 3
    kill_switch: bool = False
    grounding_threshold: float = 0.7
    price_per_1k_input_usd: float = 0.0
    price_per_1k_output_usd: float = 0.0


# ---------------------------------------------------------------------------
# The three workers.
# ---------------------------------------------------------------------------
class Planner:
    """Decides the route with fixed rules, so its behaviour is predictable and testable."""

    def plan(self, question: str, clearance: list[str], requires_approval: bool) -> PlannerOutput:
        if requires_approval:
            return PlannerOutput(route="human_approval", search_query="", clearance=clearance,
                                 steps=["hold the request for a person to approve", "take no action"])
        return PlannerOutput(route="answer", search_query=question, clearance=clearance,
                             steps=["search the approved documents", "write a cited answer",
                                    "check the answer is grounded"])


class Executor:
    """Runs the knowledge search (its only tool) and writes the draft answer."""

    def __init__(self, store, writer: ResilientWriter):
        self.store = store
        self.writer = writer

    def search(self, plan: PlannerOutput) -> tuple[list[Passage], int]:
        return self.store.search(plan.search_query, plan.clearance)

    def write(self, question: str, passages: list[Passage], attempt: int) -> tuple[ExecutorOutput, Any]:
        citations = [Citation(number=i, source=p.source, title=p.title, section=p.section,
                              classification=p.classification, score=p.score)
                     for i, p in enumerate(passages, start=1)]
        if not passages:
            return ExecutorOutput(answer=NOT_FOUND_ANSWER, citations=[], not_found=True, model="none"), None
        # The first round may use the model; later rounds quote the documents directly.
        result = self.writer.write(question, passages, strict=attempt > 1)
        if result.text.strip() == NOT_IN_DOCUMENTS:
            return ExecutorOutput(answer=NOT_FOUND_ANSWER, citations=[], not_found=True, model=result.model), result
        return ExecutorOutput(answer=result.text, citations=citations, model=result.model,
                              fallback_used=result.fallback_used, fallback_reason=result.fallback_reason), result


class Reviewer:
    """Checks that the draft is supported by the passages before it is released.

    The grounding score is the share of the answer's sentences whose
    meaningful words mostly appear in the passages. A draft also needs at
    least one valid citation and must not contain injected instructions.
    """

    def __init__(self, threshold: float):
        self.threshold = threshold

    def review(self, draft: ExecutorOutput, passages: list[Passage]) -> ReviewerOutput:
        if draft.not_found:
            return ReviewerOutput(approved=True, score=1.0, issues=[])
        issues: list[str] = []
        source_words = set().union(*(content_words(p.text) for p in passages)) if passages else set()
        body = re.sub(r"\[\d+\]", "", draft.answer)
        evaluated = grounded = 0
        for sentence in split_sentences(body.replace("\n", " ")):
            words = content_words(sentence)
            if len(words) < 3:
                continue
            evaluated += 1
            if len(words & source_words) / len(words) >= 0.5:
                grounded += 1
        score = 1.0 if evaluated == 0 else grounded / evaluated
        if score < self.threshold:
            issues.append(f"only {grounded} of {evaluated} sentences are supported by the passages")
        cited = {int(n) for n in re.findall(r"\[(\d+)\]", draft.answer)}
        if not any(1 <= n <= len(passages) for n in cited):
            issues.append("the answer does not cite any of the passages")
        if injection_reasons(draft.answer):
            issues.append("the answer contains instruction-like text")
        return ReviewerOutput(approved=not issues, score=round(score, 3), issues=issues)


# ---------------------------------------------------------------------------
# The graph.
# ---------------------------------------------------------------------------
def build_graph(store, writer: ResilientWriter, settings: GraphSettings):
    """Wires the workers, the budget gate and the fallback together."""
    planner, executor, reviewer = Planner(), Executor(store, writer), Reviewer(settings.grounding_threshold)
    tracer = telemetry.get_tracer()

    def add(metrics: dict, **values) -> dict:
        merged = dict(metrics)
        for key, value in values.items():
            merged[key] = merged.get(key, 0) + value
        return merged

    # ------------------------------------------------------------------ nodes
    def plan_node(state: AgentState) -> dict:
        with tracer.start_as_current_span("agents.planner") as span:
            span.set_attribute(SPAN_KIND, "AGENT")
            if settings.kill_switch:
                span.set_attribute("agent.halted", "emergency_stop")
                return {"halt_reason": "emergency_stop"}
            result = planner.plan(state["question"], state["clearance"], state.get("requires_approval", False))
            span.set_attribute("agent.route", result.route)
            span.set_attribute("output.value", result.model_dump_json())
            return {"plan": result.model_dump()}

    def budget_gate(state: AgentState) -> dict:
        count = state.get("execution_count", 0) + 1
        with tracer.start_as_current_span("agents.budget_gate") as span:
            span.set_attribute(SPAN_KIND, "CHAIN")
            span.set_attribute("agent.round", count)
            span.set_attribute("agent.max_rounds", state["max_rounds"])
            update: dict = {"execution_count": count}
            if settings.kill_switch:
                update["halt_reason"] = "emergency_stop"
            elif count > state["max_rounds"]:
                update["halt_reason"] = "round_limit_reached"
            span.set_attribute("agent.halted", update.get("halt_reason", ""))
            return update

    def execute_node(state: AgentState) -> dict:
        plan = PlannerOutput.model_validate(state["plan"])
        metrics, timings = dict(state.get("metrics", {})), dict(state.get("timings", {}))
        update: dict = {}
        with tracer.start_as_current_span("agents.executor") as span:
            span.set_attribute(SPAN_KIND, "AGENT")
            span.set_attribute("agent.round", state["execution_count"])
            passages = state.get("passages")
            if passages is None:
                # The knowledge search is the only tool and it runs once per question.
                started = time.perf_counter()
                with tracer.start_as_current_span("vector_store.hybrid_search") as search_span:
                    search_span.set_attribute(SPAN_KIND, "RETRIEVER")
                    search_span.set_attribute("input.value", plan.search_query)
                    search_span.set_attribute("retrieval.clearance", plan.clearance)
                    try:
                        passages, dropped = executor.search(plan)
                    except Exception as error:  # store down: stop safely
                        search_span.set_attribute("error.message", str(error)[:200])
                        timings["vector_ms"] = round((time.perf_counter() - started) * 1000, 1)
                        timings["vector_error"] = str(error)[:120]
                        metrics = add(metrics, tool_calls=1, tool_failures=1)
                        return {"halt_reason": "knowledge_search_failed", "metrics": metrics, "timings": timings}
                    for i, p in enumerate(passages):
                        prefix = f"retrieval.documents.{i}.document"
                        search_span.set_attribute(f"{prefix}.id", f"{p.source}#{p.chunk_index}")
                        search_span.set_attribute(f"{prefix}.score", p.score)
                        search_span.set_attribute(f"{prefix}.content", p.text)
                        search_span.set_attribute(f"{prefix}.metadata", json.dumps(
                            {"source": p.source, "section": p.section, "classification": p.classification}))
                timings["vector_ms"] = round((time.perf_counter() - started) * 1000, 1)
                timings["vector_detail"] = (f"hybrid search returned {len(passages)} passage(s) "
                                            f"for clearance {', '.join(plan.clearance)}"
                                            + (f"; {dropped} held back by the safety scan" if dropped else ""))
                metrics = add(metrics, tool_calls=1, quarantined_at_search=dropped)
                update["passages"] = passages

            with tracer.start_as_current_span("writer.generate") as write_span:
                write_span.set_attribute(SPAN_KIND, "LLM")
                draft, result = executor.write(state["question"], passages, state["execution_count"])
                if result is not None:
                    write_span.set_attribute("llm.model_name", result.model)
                    write_span.set_attribute("llm.token_count.prompt", result.prompt_tokens)
                    write_span.set_attribute("llm.token_count.completion", result.completion_tokens)
                    write_span.set_attribute("llm.token_count.total", result.prompt_tokens + result.completion_tokens)
                    metrics = add(metrics, model_calls=result.model_calls, prompt_tokens=result.prompt_tokens,
                                  completion_tokens=result.completion_tokens)
                write_span.set_attribute("output.value", draft.answer)
                write_span.set_attribute("writer.fallback_used", draft.fallback_used)
        update.update({"draft": draft.model_dump(), "metrics": metrics, "timings": timings, "review": None})
        return update

    def review_node(state: AgentState) -> dict:
        draft = ExecutorOutput.model_validate(state["draft"])
        with tracer.start_as_current_span("agents.reviewer") as span:
            span.set_attribute(SPAN_KIND, "EVALUATOR")
            result = reviewer.review(draft, state.get("passages") or [])
            span.set_attribute("eval.grounding_score", result.score)
            span.set_attribute("eval.approved", result.approved)
            span.set_attribute("output.value", result.model_dump_json())
            return {"review": result.model_dump(), "reviewer_span_id": telemetry.span_id_of(span)}

    def approval_node(state: AgentState) -> dict:
        with tracer.start_as_current_span("agents.human_approval") as span:
            span.set_attribute(SPAN_KIND, "CHAIN")
            ticket = ApprovalTicket(ticket_id="APR-" + state["request_id"][:8].upper(),
                                    reason="; ".join(state.get("policy_reasons", [])) or "action request")
            span.set_attribute("approval.ticket_id", ticket.ticket_id)
            answer = (f"This request asks for a change to a live system, so it has been held for human "
                      f"approval (ticket {ticket.ticket_id}). {ticket.note}")
            return {"status": "pending_approval",
                    "final": {"answer": answer, "citations": [], "approval": ticket.model_dump()}}

    def finalize_node(state: AgentState) -> dict:
        draft = ExecutorOutput.model_validate(state["draft"])
        cited = {int(n) for n in re.findall(r"\[(\d+)\]", draft.answer)}
        citations = [c.model_dump() for c in draft.citations if c.number in cited] or \
                    [c.model_dump() for c in draft.citations]
        return {"status": "not_found" if draft.not_found else "answered",
                "final": {"answer": draft.answer, "citations": citations, "approval": None}}

    def fallback_node(state: AgentState) -> dict:
        reason = state.get("halt_reason", "round_limit_reached")
        messages = {
            "emergency_stop": "The assistant is paused by its operators (emergency stop). "
                              "No question was processed.",
            "round_limit_reached": "An answer could not be verified against the approved documents within "
                                   f"{state['max_rounds']} rounds, so none is given. The question has been "
                                   "logged for an analyst to review.",
            "knowledge_search_failed": "The knowledge search is unavailable, so no answer can be given. "
                                       "Please try again shortly.",
        }
        with tracer.start_as_current_span("agents.fallback") as span:
            span.set_attribute(SPAN_KIND, "CHAIN")
            span.set_attribute("agent.halt_reason", reason)
        return {"status": "halted", "final": {"answer": messages.get(reason, messages["round_limit_reached"]),
                                              "citations": [], "approval": None}}

    # ---------------------------------------------------------------- routes
    def after_plan(state: AgentState) -> str:
        if state.get("halt_reason"):
            return "fallback"
        return "human_approval" if state["plan"]["route"] == "human_approval" else "budget_gate"

    def after_gate(state: AgentState) -> str:
        return "fallback" if state.get("halt_reason") else "executor"

    def after_execute(state: AgentState) -> str:
        return "fallback" if state.get("halt_reason") else "reviewer"

    def after_review(state: AgentState) -> str:
        return "finalize" if state["review"]["approved"] else "budget_gate"

    graph = StateGraph(AgentState)
    for name, node in [("planner", plan_node), ("budget_gate", budget_gate), ("executor", execute_node),
                       ("reviewer", review_node), ("human_approval", approval_node),
                       ("finalize", finalize_node), ("fallback", fallback_node)]:
        graph.add_node(name, node)
    graph.add_edge(START, "planner")
    graph.add_conditional_edges("planner", after_plan, ["budget_gate", "human_approval", "fallback"])
    graph.add_conditional_edges("budget_gate", after_gate, ["executor", "fallback"])
    graph.add_conditional_edges("executor", after_execute, ["reviewer", "fallback"])
    graph.add_conditional_edges("reviewer", after_review, ["finalize", "budget_gate"])
    for name in ("human_approval", "finalize", "fallback"):
        graph.add_edge(name, END)
    return graph.compile()


def run(graph, settings: GraphSettings, *, question: str, clearance: list[str], request_id: str,
        requires_approval: bool = False, policy_reasons: list[str] | None = None) -> AgentState:
    """Runs one question through the graph and adds the summary metrics."""
    state: AgentState = graph.invoke(
        {"question": question, "clearance": clearance, "request_id": request_id,
         "requires_approval": requires_approval, "policy_reasons": policy_reasons or [],
         "execution_count": 0, "max_rounds": settings.max_rounds, "metrics": {}, "timings": {}},
        # A second, independent safety net inside LangGraph itself.
        config={"recursion_limit": 25},
    )
    metrics = dict(state.get("metrics", {}))
    tool_calls = metrics.get("tool_calls", 0)
    metrics["rounds_used"] = state.get("execution_count", 0)
    metrics["tool_success_rate"] = round((tool_calls - metrics.get("tool_failures", 0)) / tool_calls, 3) \
        if tool_calls else None
    metrics["cost_usd"] = round(metrics.get("prompt_tokens", 0) / 1000 * settings.price_per_1k_input_usd
                                + metrics.get("completion_tokens", 0) / 1000 * settings.price_per_1k_output_usd, 6)
    review = state.get("review") or {}
    metrics["grounding_score"] = review.get("score")
    draft = state.get("draft") or {}
    metrics["fallback_used"] = draft.get("fallback_used", False)
    metrics["fallback_reason"] = draft.get("fallback_reason", "")
    state["metrics"] = metrics
    return state
