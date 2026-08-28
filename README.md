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

## The AIRS gateway

All gateway settings live in **`config.json`** at the repo root — host, port, scheme (`tls`), path,
header names, model list, system prompt, and the key in `api_key`. See `src/config.py`.

That file holds a secret, so it is **not** in the repo. Start from the template:

```bash
cp config.example.json config.json
```

then either fill in `api_key` or leave it empty and export `PZ_PORTKEY_API_KEY`.

Overrides:

- `PZ_PORTKEY_API_KEY` — takes precedence over the `api_key` in config.json, so a deploy need not
  edit the file
- `PZ_<SLUG>_API_KEY` — one per direct provider, named after its routing slug
  (`@openai/gpt-4o-…` → `PZ_OPENAI_API_KEY`). Same precedence: the environment wins over the file
- `PANW_AI_SEC_API_KEY` — the Prisma AIRS scan key
- `PZ_PRETZEL_AI_GATEWAY_HOST` — gateway host, if not where config.json points
- `PZ_PRETZEL_AI_CONFIG` — alternate config path

Under systemd those come from **`/etc/pretzel-ai/keys.env`** (root, 0600), which `./pretzel-ai
start` creates with a commented template on first run and never rewrites afterwards. The unit reads
it as an `EnvironmentFile`, so a key never has to be written into `config.json` — which matters
because the configuration document is on its way into the appliance's versioned running-config,
where a secret would be permanent and visible in every review diff.

The gateway itself must be deployed separately; until it is up on the configured host:port, turns
return `UNREACHABLE`.

## Layout

```
pretzel-ai                       the CLI dispatcher
script/                          build / install / start / stop / clean
src/grpc/pretzel_ai.proto        the mgmtd <-> pretzel-ai contract (source of truth,
                                 mirrored into pretzel/mgmtd/grpc/)
src/main.py                      the entry point: args and log level, then core.serve
src/core.py                      the service: config -> engine -> gRPC server -> run
src/factory.py                   which transport and which guardrail this deployment runs
src/guardrail.py                 what an inspection says, with no vendor in the vocabulary
src/airs/                        Prisma AIRS: the scan API client, and both guardrail shapes
src/llm/                         the model call: gateway transport, direct transport, catalog
src/chat/                        the turn: enforcement order, the agent loop, console adapter
src/grpc/server.py               the servicer, composed from src/grpc/handlers/
src/gateway.py                   the AIRS gateway call + scan-verdict extraction
src/config.py                    loads config.json → the appliance config
src/log.py                       rotating file log at /var/log/pretzel-ai
src/crawler/                     the tech-doc crawler (sitemap → fetch → extract → store)
sql/001_techdoc.sql              the pretzel_knowledge schema
config.example.json              template for the config (copy to config.json)
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
