# CLAUDE.local.md — penguind repo-specific overrides

Project-specific additions to `CLAUDE.md` (which is a centrally managed template — never edit it directly).

## Override: Rust Client Daemon May Call hub-api over REST

penguind is an **OUTLIER** to the org service rules. Org `rules/general.md`: all intra-cluster/service-to-service traffic and all Rust *services* use gRPC only, no REST. penguind is a Rust **client** daemon (server/daemonset/desktop run modes) running outside or at the edge of the cluster, so the rule is relaxed as below.

- **Client -> hub-api MAY use REST** — hub-api is the one REST server (REST serves webui + external clients/connections); follow hub-api's published OpenAPI spec
- **JWT on every call**; tokens in platform secure storage only (`client.md` Authentication & Tokens)
- **Internal / daemon-to-daemon / agent-to-agent / server-run-mode comms to cluster services still prefer gRPC** (tonic + rustls, ECC P-256) wherever the peer offers it
- **penguind never exposes its own REST surface for cluster services** — REST is consumed, not served
- **All other `client.md` rules still apply** — PII tokenization (UUIDs only, never PII in API calls), no hardcoded secrets, feature flags, offline/retry behavior
- **Precedence:** this override beats the org `general.md` Rust-no-REST rule for penguind only; it grants no exemption to any other repo or crate outside penguind
