# End-to-end check report

- Run at: 2026-10-11 16:06:07 UTC
- Gateway version: 1.0.0; agent version: 1.0.0
- Answer writer: model: gemini (gemini-3.5-flash); round cap 3
- Controls in place: 18 of 21
- Machine: Darwin x86_64, Python 3.12.14

## Results

| Scenario | Expected | Result | HTTP | Status | Time (ms) | Trace ID |
|---|---|---|---|---|---|---|
| 1. Normal question | answered, six hops ok, cited sources | PASS | 200 | answered | 2870 | `33a2758788cb8885e266139b970b4624` |
| 2. Prompt injection | blocked at hop 3, hops 4 and 5 skipped | PASS | 400 | blocked | 7 | `25d5b257459940db0cf0c22eb6b96fee` |
| 3. Personal data | email and phone number masked before the agents | PASS | 200 | answered | 861 | `7f76c087f7e97ff3128a04b4bd9ddead` |
| 4. Action request | held for human approval, no search, no action | PASS | 200 | pending_approval | 38 | `40513f2beeb951890484792123837e00` |
| 5. Viewer role | only public documents cited | PASS | 200 | answered | 470 | `2e10b51e8182038b77426655bc8542d1` |
| 6. Trace in Phoenix | one trace across both services, grounding score | PASS | 200 | 13 spans | 0 | `33a2758788cb8885e266139b970b4624` |

## Scenario 1: the six hops

| Hop | Name | Status | Time (ms) | Detail |
|---|---|---|---|---|
| 1 | Client | ok | 0.0 | question received (62 characters) |
| 2 | API gateway | ok | 0.2 | role analyst; 19 requests left this minute |
| 3 | Guardrails | ok | 0.2 | no injection found |
| 4 | Agent team | ok | 877.3 | Planner, Executor, Reviewer; 1 round(s); 1 model call(s); grounding 1.0; quoted-passage answer |
| 5 | Vector store | ok | 1969.0 | hybrid search returned 4 passage(s) for clearance public, internal |
| 6 | Telemetry | ok | 0.2 | trace 33a2758788cb recorded for Phoenix; audit event written |

Measured for scenario 1: latency 2858.7 ms; model calls 1; tool success rate 1.0; grounding score 1.0; estimated cost $0.0.

## Scenario 6: the same request in Phoenix

| Span | Kind | Layer |
|---|---|---|
| POST /v1/ask | UNKNOWN | web framework (HTTP request handling) |
| gateway.request | CHAIN | L1 Experience (gateway) |
| api_gateway.access_check | CHAIN | L1 Experience |
| guardrails.input_check | GUARDRAIL | L2 Guardrails |
| POST /v1/run | UNKNOWN | web framework (HTTP request handling) |
| agent_service.run | AGENT | L3 Agentic logic (agent service) |
| agents.planner | AGENT | L3 Agentic logic |
| agents.budget_gate | CHAIN | L3 Agentic logic |
| agents.executor | AGENT | L3 Agentic logic |
| vector_store.hybrid_search | RETRIEVER | L4 Vector RAG |
| writer.generate | LLM | L3 Agentic logic (answer writer) |
| agents.reviewer | EVALUATOR | L3 Agentic logic |
| guardrails.output_check | GUARDRAIL | L2 Guardrails |

Grounding evaluation recorded in Phoenix: label **grounded**, score **1.0** (all sentences supported by cited passages).

## Containers at the time of the check

```
SERVICE         STATUS
agent-service   Up 19 seconds (healthy)
gateway         Up 11 seconds (healthy)
phoenix         Up 2 hours
weaviate        Up 2 hours (healthy)
```
