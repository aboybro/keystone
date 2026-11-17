# Keystone

[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/aboybro/keystone/rank.svg)](https://make.fun/bounty/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/aboybro/keystone/reward.svg)](https://make.fun/bounty/github-core-clone-01)

Keystone is a GitHub-compatible git forge in **one file**: `main.ts` (Node 22
standard library only — no dependencies, no git binary, no database). It
serves git smart HTTP, REST v3, GraphQL v4, MCP, and a server-rendered web UI
from a single in-memory store, in a single process.

Built for the [make.fun](https://make.fun) bounty
[github-core-clone-01](https://make.fun/bounty/github-core-clone-01)
("Build a GitHub-compatible git forge").

## What it serves

| Surface | Routes | Notes |
|---|---|---|
| Git smart HTTP | `/{owner}/{repo}.git/info/refs`, `/git-upload-pack`, `/git-receive-pack` | Protocol v2 (ls-refs, fetch, shallow/deepen) + v0, multi-round negotiation, OFS/REF delta pack parsing, sideband |
| REST v3 | `/api/v3/...` | Repos, branches, commits, contents, labels, issues, pull requests (squash merge with conflict detection), pagination with `Link` headers |
| GraphQL v4 | `/api/graphql` | Hand-rolled parser + executor; `viewer`, `repository`, `node`, `__type` introspection, issue/PR mutations, cursor pagination |
| MCP | `/mcp` | Streamable HTTP, JSON-RPC 2.0, `server/discover` (2026-07-28) + `initialize`; 11 tools (`create_repo`, `get_repo`, `create_issue`, `list_issues`, `create_pull_request`, `merge_pull_request`, …) |
| Web UI | `/`, `/{owner}/{repo}`, `/issues`, `/pull/{n}`, `/blob/…`, `/commit/…` | Server-rendered browsing for humans |

## How it works

- **Store** — a content-addressed object heap (commits, trees, blobs, tags)
  plus relational issue/PR/label tables per repository. Every id and
  timestamp comes from deterministic counters, so one instance behaves
  identically on every run.
- **Git** — full pack v2 with sideband; OFS/REF delta decoding on receive,
  whole objects on send. Fetches send exactly the reachable set minus what
  the client holds (shallow-aware: a shallow boundary's parents are never
  assumed held), with depth-limited walks for `--depth` / `--deepen`.
- **Speed** — cached serialised issue JSON, cached whole fetch responses for
  haves-free fetches (clones), lean routing, keep-alive friendly.
- **Auth** — `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` on REST, GraphQL
  and MCP (any non-empty Bearer when the variable is unset). Git smart HTTP
  is unauthenticated, like a public forge.

## Run it

```sh
node --experimental-strip-types main.ts
# listens on http://127.0.0.1:8080 (or $PORT)
```

With the trial harness, set `MAKEFUN_ENV_URL` and the server binds an
ephemeral port, registers it, polls `/done`, and exits 0:

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:PORT MAKEFUN_SHOP_TOKEN=dev-token \
  node --experimental-strip-types main.ts
```

Then, for example:

```sh
git clone http://127.0.0.1:8080/adaiversen/myrepo.git
curl -H "Authorization: Bearer dev-token" http://127.0.0.1:8080/api/v3/user/repos
```

## Test results

Kit conformance runner (`sdk/run.ts --perf`): **120/120 checks** —
git 30/30, repos 15/15, issues 15/15, pulls 20/20, protocol 5/5,
GraphQL 20/20, MCP 15/15 — plus perf points (total score ≈ 890/1000).
Real `git` CLI verified end to end: push, clone, pull, `--depth 1` clone,
`--deepen 1`, annotated tags, `ls-remote`.

## Architecture (why one file)

Unlike a layered `src/` layout, Keystone keeps the whole forge in one
module so the store, the git wire format, the three APIs and the UI share
one set of types and one deterministic clock with no import graph to keep
in sync. The file is organised in sections: identity/clock → pkt-line and
object model → pack parse/build → store (files, merges, diffs) → git HTTP →
REST → GraphQL → MCP → web UI → server/lifecycle.

## License

MIT — see [LICENSE](LICENSE).
