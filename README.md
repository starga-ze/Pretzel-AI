# pretzel-ai

The AI inference service for pretzel. It replaces the old in-tree `inferd` daemon: instead of
riding the C++ IPC fabric as daemon 9, it runs as a standalone gRPC service that `mgmtd` calls.

A chat turn streams back token-by-token (`Chat` is a server-streaming RPC); the final chunk
carries the complete turn document (reply, the AIRS scan verdict, usage) that mgmtd files verbatim.

## CLI

Same shape as pretzel's `./pretzel`:

```bash
sudo ./pretzel-ai install   # venv + deps + generated stubs + /var/log/pretzel-ai
     ./pretzel-ai build     # regenerate the gRPC stubs from proto/
sudo ./pretzel-ai start     # run the daemon under systemd (supervised infinite loop)
sudo ./pretzel-ai stop      # stop + disable
     ./pretzel-ai clean     # remove generated stubs and caches
```

The daemon runs as `pretzel-ai.service` and logs to a rotating file:

```bash
tail -f /var/log/pretzel-ai/pretzel-ai.log
```

## Configuration

There is **no config file.** The whole deployment — which vendors serve turns, which of their
models may be asked for, the guardrail, and how a turn is shaped — is committed in the appliance's
console, versioned in its running-config, and pushed here over `ApplyConfig`. This service reads no
database and holds no file of record; it applies what it is told and caches the last document at
`/etc/pretzel-ai/deployment.json` (root, 0600) so a restart does not leave it mute until the next
push.

Before the first push a fresh install comes up **listening and mute** — no models, so no turn can
be served — and says so in the log. That is the only state it can be in before the appliance has
told it anything, and it is why a configuration that cannot serve is not fatal at startup: the
thing that would fix it reaches this service over the wire.

What arrives, and where it came from:

| pushed | running-config | notes |
|---|---|---|
| providers, models | `pretzel-ai.providers.list` | endpoints are compiled in here, not configured |
| guardrail kind, AIRS endpoint, profile, timeout, fail-open | `pretzel-ai.guardrail` | |
| the four checkpoints | `pretzel-ai.guardrail.inspect_*` | prompt · response · tool_call · tool_result |
| system prompt, token cap, timeout | `pretzel-ai.shape` | |
| vendor keys, the AIRS key | *not* in running-config | sealed in `ai_provider_credential_state`, unsealed by mgmtd for the push |

The guardrail used to live in this service's own `config.json`, deliberately, so that an appliance
changing which models it serves could not change whether the turns were inspected. That bought its
protection by making the guardrail unconfigurable without editing a file on the appliance and
restarting the service. The console owns it now; what protects it is that every change is a
committed, versioned running-config edit rendered in a review diff.

### Running without an appliance

For a developer or a benchmark run with nothing in front of this service, keys come from the
environment — `/etc/pretzel-ai/keys.env` (root, 0600) under systemd, which `./pretzel-ai start`
creates with a commented template on first run and never rewrites:

- `PZ_<SLUG>_API_KEY` — one per provider slug (`openai/gpt-…` → `PZ_OPENAI_API_KEY`)
- `PANW_AI_SEC_API_KEY` — the Prisma AIRS scan key
- `PZ_PRETZEL_AI_STATE` — where the pushed document is cached, if not `/etc/pretzel-ai/deployment.json`

A **pushed key wins over the environment.** It used to be the other way round, because the
environment was how a key avoided being written into the config document; there is no such document
now, and an env var that outranked the console would mean an operator rotating a key in the UI and
watching nothing happen.

## Layout

```
pretzel-ai                       the CLI dispatcher
script/                          build / install / start / stop / clean
src/grpc/pretzel_ai.proto        the mgmtd <-> pretzel-ai contract (source of truth,
                                 mirrored into pretzel/mgmtd/grpc/)
src/main.py                      the entry point: args and log level, then core.serve
src/core.py                      the service: deployment -> engine -> gRPC server -> run
src/factory.py                   which transport and which guardrail this deployment runs
src/guardrail.py                 what an inspection says, with no vendor in the vocabulary
src/airs/                        Prisma AIRS: the scan API client, and both guardrail shapes
src/llm/                         the model call: gateway transport, direct transport, catalog
src/chat/                        the turn: enforcement order, the agent loop, console adapter
src/grpc/server.py               the servicer, composed from src/grpc/handlers/
src/gateway.py                   the AIRS gateway call + scan-verdict extraction
src/config.py                    the built-in defaults, and keys from the environment
src/deployment.py                the pushed document laid over them, and the engine it builds
src/log.py                       rotating file log at /var/log/pretzel-ai
src/crawler/                     the tech-doc crawler (sitemap → fetch → extract → store)
sql/001_techdoc.sql              the pretzel_knowledge schema
```

`src/grpc/` holds everything gRPC — the contract, the stubs `build` generates beside it, and the
server. It is a package inside `src` rather than a directory at the repo root because a top-level
`grpc/` would shadow grpcio's own module for anything that put the root on sys.path.

## The tech-doc corpus

The assistant answers out of `pretzel_knowledge`, crawled from docs.paloaltonetworks.com. Two
schemas: `techdoc` (crawled, expensive to reacquire, back this up) and `corpus` (chunks and
embeddings, derived, rebuilt whenever the chunking rules or the model change).

```bash
python -m src.crawler check                  # what has moved since the last crawl
python -m src.crawler refresh --scope ngfw   # apply it
python -m src.crawler status                 # what the store holds
```

The console drives the same operations from **System Management ▸ Operation ▸ Tech Documentation**.
The CLI is for the first full build, which fetches every page and is a job to leave running in a
terminal rather than to hold a browser window open for.

## Status

Wire + gateway working. Not yet: browser-side token streaming (mgmtd currently files the whole
answer on a poll), and the DB-sealed credential path.
