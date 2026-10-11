# Rollout Rehearsal

Date: 11 October 2026
Versions: stable 1.0.0, canary 1.1.0-canary, stable update 1.1.0

This records a rehearsal of the staged release and rollback plan in docs/sdd.md section 12. Every sample was taken in the control plane console by running the same question 10 times and noting the version in "Served by" and the number of passages in hop 5.

## Part 1: Docker Compose

| Step | What was done | What was seen |
|---|---|---|
| Canary on | CANARY_PERCENT=50 in .env, then `docker compose --profile canary up -d` | Out of 10 requests, 7 were served by stable (version 1.0.0) and 3 by canary (version 1.1.0-canary). The canary read 5 passages per search, stable read 4. |
| Canary failure | `docker compose --profile canary stop agent-service-canary` | Every request was still answered, by "stable after canary failure (version 1.0.0)" when the stopped canary was picked. |
| Rollback | CANARY_PERCENT=0 in .env, then `docker compose up -d gateway` | Every request was served by stable (version 1.0.0). |

## Part 2: Kubernetes on Minikube

| Stage | Commands | Sample of 10 requests |
|---|---|---|
| Before | none | 10 stable 1.0.0 (4 passages) |
| Stage 2: canary at 50% | `kubectl -n secops scale deployment/agent-service-canary --replicas=1` and `kubectl -n secops set env deployment/gateway CANARY_PERCENT=50` | 3 stable 1.0.0 (4 passages), 7 canary 1.1.0-canary (5 passages) |
| Stage 4: rolling update of stable | `kubectl -n secops set env deployment/agent-service AGENT_VERSION=1.1.0 TOP_K=5` | 6 stable 1.1.0 (5 passages), 4 canary 1.1.0-canary (5 passages) |
| Rollback | `kubectl -n secops set env deployment/gateway CANARY_PERCENT=0`, `kubectl -n secops rollout undo deployment/agent-service` and `kubectl -n secops scale deployment/agent-service-canary --replicas=0` | 10 stable 1.0.0 (4 passages) |

During the rolling update and the rollback, the new stable pod became ready before the old one was removed, so the service was never without a working copy. The restored pod carried the same settings fingerprint as the original.

### Rollout history after the rollback

```
deployment.apps/agent-service
REVISION  CHANGE-CAUSE
2         <none>
3         <none>
```

### Pods after the rollback

```
NAME                             READY   STATUS      RESTARTS   AGE
agent-service-5fbf47c76d-pfwrg   1/1     Running     0          15m
gateway-5ddcc94775-7rzqc         1/1     Running     0          17m
ingest-pnnzz                     0/1     Completed   0          103m
phoenix-8c98ff6c8-h2l8v          1/1     Running     0          103m
weaviate-79d4fbb48d-7tvcz        1/1     Running     0          103m
```

### Stable versions kept by Kubernetes after the rollback

```
NAME                       DESIRED   CURRENT   READY   AGE
agent-service-55dc9d8444   0         0         0       26m
agent-service-5fbf47c76d   1         1         1       105m
```

The original recipe (5fbf47c76d, created at the first deployment) runs the restored pod. The 1.1.0 recipe (55dc9d8444) is kept with no pods, so the update could be reapplied.

## Result

Both rollbacks returned every answer to the stable version 1.0.0. The Docker Compose rollback took effect within seconds by setting CANARY_PERCENT to 0. The Kubernetes rollback completed within about a minute with a working stable pod at every moment. Kubernetes restored the original 1.0.0 recipe from the first deployment rather than building a new one. Users were never left without an answer, which shows the rollback steps in section 12 of the design document work as written.