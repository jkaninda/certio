<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="branding/certio-logo-horizontal-dark.svg">
    <img src="branding/certio-logo-horizontal.svg" alt="Certio" width="281" height="100">
  </picture>
</p>

**Self-signed PKI and TLS certificate management, in a single binary.**

Certio replaces the pile of `openssl` commands, `.cnf` files and `.srl` bookkeeping that a
private certificate authority usually turns into. It gives you a web dashboard, a REST API and
a CLI over the same engine — so a certificate issued from your terminal is identical to one
issued from a browser or from CI.

```sh
docker run -p 8080:8080 -v certio:/data jkaninda/certio
```

---

## What it does

- **Certificate authorities** — create roots and intermediates, or **import the CA you already
  have**, certificate and key, without re-issuing anything.
- **Issue certificates** with first-class SAN support: DNS, IP (v4 and v6), email, URI and
  wildcards, with the validation browsers actually apply.
- **Two issuance flows** — managed (Certio generates the key) or BYO-CSR (you keep the key and
  Certio never sees it).
- **Renew** manually, in bulk, or automatically on a threshold. Renewal creates a *new*
  certificate linked to the old one, so history and rollback survive.
- **Revoke** with an RFC 5280 reason code and publish a **CRL** at a URL clients can fetch.
- **Export** in every format a server actually wants: PEM, chain, fullchain, PKCS#12, ZIP,
  Kubernetes `kubernetes.io/tls` Secret, and nginx/Traefik/HAProxy/**Goma Gateway**/compose
  snippets.
- **Distribute trust** — per-platform install instructions for Debian, RHEL, macOS, Windows,
  Java, Node.js, Docker and curl.
- **Inspect** any pasted PEM — certificate, chain, CSR, key or CRL — without storing it.
- **Two-factor authentication** with any TOTP app, plus single-use recovery codes, for the
  accounts that hold the keys to your PKI.
- **ACME (RFC 8555)** — point cert-manager, Traefik, Caddy, certbot or acme.sh at Certio and
  internal certificates renew themselves, with nobody in the loop. `http-01` and `dns-01`,
  wildcards included, gated by administrator-issued credentials.
- **Deploy** a renewed certificate where it is actually used: a Kubernetes `kubernetes.io/tls`
  Secret, a load balancer over SSH with a reload command, or a signed webhook. Renewal that
  nobody deploys has only moved the manual step later.
- **Name-constrain a CA** so it can only ever certify the domains you own. A root in a trust
  store without this can mint a certificate for any name on the internet.
- **OCSP responder** at `/ca/{id}/ocsp`, answered from the revocations table rather than the
  published CRL — so a certificate revoked seconds ago reports revoked immediately.
- **Prometheus metrics** for certificate and CA expiry, issuance, renewal, revocation,
  notification and deployment outcomes. Alert on expiry rather than watching a dashboard.

Private keys are AES-256-GCM encrypted at rest. Every mutation is written to an append-only
audit log. `openssl` stays a *reference*, never a runtime dependency: the engine is Go's
`crypto/x509` end to end.

---

## Quick start

### Docker

```sh
# 1. Generate the secrets. Keep the master key somewhere other than the volume.
docker run --rm jkaninda/certio:latest keygen

# 2. Run it.
docker run -d --name certio -p 8080:8080 \
  -v certio_data:/data \
  -e CERTIO_MASTER_KEY=<the key from step 1> \
  -e CERTIO_JWT_SECRET=<the secret from step 1> \
  -e CERTIO_ADMIN_EMAIL=admin@example.com \
  -e CERTIO_ADMIN_PASSWORD=a-long-enough-password \
  -e CERTIO_BASE_URL=http://localhost:8080 \
  jkaninda/certio:latest
```

Open <http://localhost:8080> and sign in. The API description is at `/docs`.

A complete deployment with file-based secrets is in
[`examples/docker-compose.yml`](examples/docker-compose.yml).

### From source

```sh
git clone https://github.com/jkaninda/certio
cd certio
make deps
make build
./bin/certio serve
```

---

## The CLI

Every command drives the same service layer the API does.

```sh
# One-time setup
certio keygen                       # print a master key and JWT secret
certio migrate                      # create the schema

# Certificate authorities
certio ca create --cn "jkanTech Root CA" --org jkanTech --country CD --days 3650 \
                 --permit-dns jkaninda.dev --permit-ip 10.0.0.0/8
certio ca create --type intermediate --parent jkantech-root-ca \
                 --cn "jkanTech Issuing CA" --days 1825
certio ca import --cert certs/jkantech-ca.crt --key certs/jkantech-ca.key
certio ca list
certio ca export jkantech-root-ca -o ./trust

# Certificates
certio cert issue --ca jkantech-root-ca --cn "*.jkaninda.dev" \
      --san dns:jkaninda.dev --san 'dns:*.jkaninda.dev' --san ip:127.0.0.1 \
      --days 397 -o ./out

certio cert sign  --ca jkantech-root-ca --csr server.csr -o ./out
certio cert list  --expiring-in 30d
certio cert list  --label env=prod --label team=payments
certio cert renew <id> --rekey
certio cert revoke <id> --reason 1
certio cert revoke <id> --reason 6                          # certificateHold — reversible
certio cert release-hold <id>                               # take it back off the CRL
certio cert export <id> --format p12 --password changeit -o ./out
certio cert export <id> --format goma > goma.yml       # Goma Gateway TLS block
certio cert inspect server.crt

# Operations
certio user create --email admin@jkaninda.dev --role admin  # reads CERTIO_USER_PASSWORD
certio user reset-2fa admin@jkaninda.dev                    # lost device and recovery codes
certio scan --crl                                           # one scheduler pass
certio backup --out certio-backup.tar.gz                    # safe against a live instance
certio restore certio-backup.tar.gz --force
```

Secrets are read from the environment rather than argv, so they never land in shell history:
`CERTIO_CA_PASSPHRASE`, `CERTIO_PARENT_PASSPHRASE`, `CERTIO_USER_PASSWORD`.

---

## Configuration

Everything is settable as `CERTIO_*` environment variables or in a YAML file
(`certio serve --config certio.yaml`). The environment always wins. A fully commented file is
in [`examples/certio.yaml`](examples/certio.yaml).

| Variable | Default | Notes |
|---|---|---|
| `CERTIO_MASTER_KEY` / `_FILE` | — | Encrypts every stored private key. **Required in production.** Back it up separately from the database. |
| `CERTIO_JWT_SECRET` / `_FILE` | — | Signs session tokens. Required in production. |
| `CERTIO_PRODUCTION` | `false` | Refuses to boot without the two secrets above. |
| `CERTIO_DB_PATH` | `certio.db` | SQLite file. |
| `CERTIO_DB_DRIVER` | `sqlite` | `sqlite` or `postgres`. Postgres needs `CERTIO_DB_DSN`. |
| `CERTIO_BASE_URL` | `http://localhost:8080` | Baked into the CRL distribution point of issued certificates — must be reachable by clients. |
| `CERTIO_PORT` / `CERTIO_HOST` | `8080` / `0.0.0.0` | Listener. |
| `CERTIO_ADMIN_EMAIL` / `_PASSWORD` | — | Creates the first administrator on an empty database, then never again. |
| `CERTIO_KEY_DOWNLOAD_POLICY` | `always` | `once`, `always` or `never`. |
| `CERTIO_ACCESS_TOKEN_TTL` | `1h` | How long an access token lives. Signing out denies the session immediately, so this is not what bounds a leaked one. |
| `CERTIO_ISSUE_RATE_LIMIT` | `60` | Issuance per window per principal. `0` disables it. |
| `CERTIO_ACME_ENABLED` | `false` | Serve the RFC 8555 endpoints. |
| `CERTIO_ACME_AUTHORITY` | — | The CA that signs ACME orders. Required when ACME is on. |
| `CERTIO_ACME_REQUIRE_EAB` | `true` | Require an administrator-issued credential to register. |
| `CERTIO_ACME_VALIDITY_DAYS` | `90` | Lifetime of an ACME-issued certificate. |
| `CERTIO_ACME_HTTP01_PORT` | `80` | Where `http-01` challenges are fetched. |
| `CERTIO_ACME_RESOLVER` | — | DNS server for `dns-01`, e.g. `10.0.0.53:53`. Empty uses the system resolver. |
| `CERTIO_ENABLE_DOCS` | `true` | Serves the OpenAPI document and the Scalar UI at `/docs`. |
| `CERTIO_SCHEDULER_ENABLED` | `true` | Expiry scanning, auto-renewal and CRL refresh. |
| `CERTIO_EXPIRY_WARN_DAYS` | `30` | When a certificate is marked *expiring*. |
| `CERTIO_LOG_LEVEL` / `_FORMAT` | `info` / `text` | `debug`…`off`; `text` or `json`. |

> **Losing the master key means losing every private key it protects.** The database alone is
> useless without it, which is the point — but so is a backup that contains both.

---

## ACME

Certio speaks RFC 8555, so anything that already renews certificates from Let's Encrypt can renew
them from your private CA instead — no new agent, no new configuration language.

```sh
# 1. Turn it on, pointing at the CA that should sign ACME orders. A
#    name-constrained intermediate is the right choice here.
CERTIO_ACME_ENABLED=true CERTIO_ACME_AUTHORITY=internal-issuing-ca certio serve

# 2. Issue a credential (Settings → ACME, or the API). One per team or per
#    cluster, so a leak can be revoked without affecting anyone else.
curl -X POST https://certio.example.com/api/v1/acme/external-accounts \
     -H "Authorization: Bearer certio_…" \
     -d '{"description":"payments cluster","allowed_domains":["corp.example.com"]}'

# 3. Point a client at it.
certbot certonly --server https://certio.example.com/acme/directory \
        --eab-kid <kid> --eab-hmac-key <hmac> -d api.corp.example.com
```

cert-manager wants the same three values:

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: certio
spec:
  acme:
    server: https://certio.example.com/acme/directory
    privateKeySecretRef: { name: certio-account-key }
    externalAccountBinding:
      keyID: <kid>
      keySecretRef: { name: certio-eab, key: hmac }
    solvers:
      - http01: { ingress: { class: nginx } }
```

**External account binding is on by default and should stay that way.** Let's Encrypt can accept
anyone because it validates against the public DNS; a private CA validating internal names has no
such backstop, so without a credential anything that can reach the directory could obtain a
certificate for any name the CA will sign.

`http-01` and `dns-01` are both supported. Wildcards are `dns-01` only — there is no single host to
serve a file from — and Certio simply does not offer the other challenge for one.

---

## Security

- Private keys are sealed with AES-256-GCM; the content key is derived per value with
  HKDF-SHA256 from the master key. A CA may carry an **extra passphrase**, stretched with
  Argon2id and folded into the same derivation — so that CA cannot be used with the master key
  alone. The passphrase is never stored.
- Passwords are hashed with Argon2id. A login against a non-existent account performs the same
  work as a real one, so the endpoint cannot enumerate addresses.
- **Two-factor authentication** per account: RFC 6238 TOTP, enrolled by scanning a QR code the
  server renders. The shared secret is sealed with the master key like every other secret. A
  code is accepted once and once only — the time step it belongs to is recorded, so an observed
  code cannot be replayed for the rest of its window. Ten single-use recovery codes are issued
  at enrolment and stored as digests. Both steps of the login share one rate limiter.
- JWT access tokens (1 hour) plus refresh tokens (7 days); the access token is mirrored into an
  HttpOnly cookie so the SPA never puts a credential in `localStorage`. A password that still
  owes a second factor yields a five-minute challenge token instead, which cannot authorise
  anything — it can only be exchanged at `/auth/2fa/verify`.
- API tokens are stored as SHA-256 digests and shown exactly once. They are separate
  credentials and are deliberately *not* covered by 2FA; revoke one rather than relying on the
  second factor to contain it.
- **Signing out actually signs out.** A JWT is valid until it expires no matter what has
  happened since, so Certio keeps a session denylist: the access token *and* the refresh token
  that would replace it both stop working immediately. A password change, a demotion or a
  suspension ends every session the account holds — those are exactly the sessions the change
  is meant to end.
- RBAC: **admin** (everything, including users and deleting CAs) · **operator** (issue, renew,
  revoke) · **viewer** (read-only).
- **Token scopes** narrow an API token below its owner's role — `certificates:read` for a
  CI job that only publishes, `certificates:write` for one that issues. A write scope implies
  its read counterpart. Scopes only ever narrow: a viewer's token holding
  `certificates:write` still cannot issue anything.
- **Name constraints** on a CA are enforced by every verifier that matters — Go, OpenSSL, macOS,
  Windows — and Certio additionally refuses out-of-scope names at issuance, so the failure
  appears where someone can fix it rather than in a browser weeks later.
- Every mutation is audited, including *denied* private key downloads. The audit log has no
  update or delete endpoint by construction.
- Rate limiting on `/auth/login`, and separately on issuance — keyed by principal, so one
  runaway CI token is throttled even when it shares an egress address with everyone else.
- A strict `Content-Security-Policy`. `script-src` stays at `'self'` plus SHA-256 hashes of the
  inline bootstrap scripts the dashboard and the docs page carry, computed at startup from the
  bytes actually served — no `'unsafe-inline'`, and no per-request nonce for documents that never
  change. The only external origins allowed are the CDN and webfont the Scalar docs UI loads
  from, and only when `CERTIO_ENABLE_DOCS` is on; with docs off the policy names no outside host
  at all. Scalar's telemetry endpoint is blocked either way — an admin console for a private CA
  has no business calling a third party.
- Serial numbers are 128-bit crypto-random, unique per CA by a database constraint — no `.srl`
  file to lose or corrupt.

---

## Testing

```sh
make test          # includes the openssl cross-checks
make test-short    # skips them
make cover
```

The PKI engine is the load-bearing part and is tested accordingly. Beyond unit tests, the suite
cross-checks against the reference implementation in both directions: `openssl` must be able to
read every certificate, CSR, CRL and PKCS#12 file Certio produces, `openssl verify` must accept
its chains, and Certio must import CAs that `openssl` generated. Those tests skip cleanly when
`openssl` is not installed.

---

## API

The OpenAPI 3.1 description is generated from the route definitions and served at `/docs`,
with the raw document at `/openapi.json`.

```sh
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"…"}' | jq -r .access_token)

curl -X POST localhost:8080/api/v1/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "ca_id": "jkantech-root-ca",
        "subject": { "common_name": "*.jkaninda.dev" },
        "san_list": "jkaninda.dev, *.jkaninda.dev, 127.0.0.1",
        "profile": "server",
        "validity_days": 397,
        "auto_renew": true
      }'
```

For automation, mint an API token under **Settings → API tokens** and use it as the bearer
value instead of a session token.

If the account has two-factor authentication enabled, `/auth/login` replies with
`two_factor_required` and a short-lived `challenge_token` rather than a session. Exchange it
for one:

```sh
curl -X POST localhost:8080/api/v1/auth/2fa/verify \
  -H 'Content-Type: application/json' \
  -d '{"challenge_token": "…", "code": "123456"}'
```

A script that already holds the code can skip the round-trip by sending `totp_code` alongside
the password on `/auth/login`. `GET /api/v1/about` returns the build, runtime and instance
configuration behind the dashboard's **About** page — the line to quote in a bug report.

---

## Profiles

A profile presets key usage, extended key usage and the default lifetime, so the common cases
need no extension knowledge.

| Profile | Key usage | Extended key usage | Default |
|---|---|---|---|
| `server` | DigitalSignature, KeyEncipherment | ServerAuth | 397 days |
| `client` | DigitalSignature | ClientAuth | 397 days |
| `peer` (mTLS) | DigitalSignature, KeyEncipherment | ServerAuth + ClientAuth | 397 days |
| `code-signing` | DigitalSignature | CodeSigning | 3 years |
| `intermediate` | CertSign, CRLSign | — | 5 years |
| `root` | CertSign, CRLSign | — | 10 years |

397 days is the CA/Browser Forum maximum for publicly trusted server certificates. Certio uses
it as the default so habits stay portable; a private CA may exceed it, and the UI says so rather
than blocking it.

---

## Goma Gateway

Two export formats target [Goma Gateway](https://goma.jkaninda.dev), covering both places it
accepts a certificate.

**Global** (`--format goma`) — one `gateway.tls` block; Goma picks a certificate per request by
SNI, matching the hostname against each certificate's common name and SANs:

```yaml
version: 2
gateway:
  tls:
    certificates:
      - cert: /etc/goma/certs/example.com-fullchain.pem
        key: /etc/goma/certs/example.com.key
```

**Per route** (`--format goma-route`) — a route with its own certificate, which takes precedence
over the global list. The `hosts` list is built from the certificate's DNS SANs, so it already
matches what the certificate can actually serve:

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: example.com
      hosts: ["example.com", "*.example.com"]
      backends:
        - endpoint: http://127.0.0.1:8080
      tls:
        certificates:
          - cert: /etc/goma/certs/example.com-fullchain.pem
            key: /etc/goma/certs/example.com.key
```

Both reference the **fullchain**, not the bare leaf: a gateway serving only the leaf breaks any
client that does not already hold the intermediate. Goma also accepts base64 or raw PEM inline
in `cert` and `key`, but file paths are what these snippets emit — a renewal replaces the file
and the gateway reloads, whereas inlined PEM would have to be regenerated every time.

For a directory of certificates, skip the list entirely and point Goma at the folder. Goma pairs
files by base name, which is exactly the layout `--format zip` produces:

```yaml
version: 2
gateway:
  tls:
    certsDir: /etc/goma/certs
```

### Renewing from Certio over ACME

Exports are a push: something re-runs `certio cert export` and reloads the gateway. Goma's own
certificate manager inverts that — it orders and renews on its own, and pointing it at Certio is
one `directoryUrl` away, because Certio serves the same RFC 8555 protocol Let's Encrypt does.

`certManager` is a top-level key, a sibling of `gateway`, not nested inside it. A route selects a
provider by name; routes that leave `tls.provider` empty use `defaultProvider`, and
`tls.provider: none` opts a route out:

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: "[::]:80"      # http-01 is fetched here — Certio has to reach it
    webSecure:
      address: "[::]:443"
  routes:
    - path: /
      name: api
      hosts: ["api.corp.example.com"]
      backends:
        - endpoint: http://127.0.0.1:8080
      tls:
        provider: certio      # or omit it and let defaultProvider apply

certManager:
  defaultProvider: certio
  providers:
    certio:
      type: acme
      acme:
        email: platform@example.com
        directoryUrl: https://certio.example.com/acme/directory
        challengeType: http-01
        storageFile: /etc/goma/acme/certio.json
```

Wildcards need `dns-01`, which Goma solves through a DNS provider of its own
(`dnsProvider: cloudflare` or `route53`, with `credentials.apiToken` — prefer the
`GOMA_CREDENTIALS_API_TOKEN` environment variable over inlining it). Certio resolves the `TXT`
record it just asked for, so set `CERTIO_ACME_RESOLVER` to a server that sees the zone if the
system resolver does not.

Three things differ from pointing Goma at a public CA, and all three are worth knowing before you
try it:

**Goma does not implement external account binding.** It registers with plain
`TermsOfServiceAgreed`, so Certio has to run with `CERTIO_ACME_REQUIRE_EAB=false` for the
registration to succeed — which drops the control the [ACME section](#acme) argues you should
keep. If you turn it off, replace it with something else: make `CERTIO_ACME_AUTHORITY` a
name-constrained intermediate, so the worst an unauthenticated caller can obtain is a certificate
for a name inside the constraint, and keep the directory off any network you would not hand a
certificate to.

**Goma verifies the directory's TLS against the system trust store, and has no key for a custom
root.** Certio's own listener is usually served by a certificate Certio signed, so the Certio root
has to be in the container — mount it into `/usr/local/share/ca-certificates` and run
`update-ca-certificates` in the image, or terminate `certio.example.com` with a publicly trusted
certificate. Setting `GOMA_ENV=development` or `local` skips verification entirely; that is a
testing escape hatch, not a deployment.

**`http-01` is fetched from Certio, not from the internet.** Certio requests
`http://<host>/.well-known/acme-challenge/<token>` on `CERTIO_ACME_HTTP01_PORT` (default `80`), so
the `web` entry point has to be reachable from wherever Certio runs, and the hostname has to
resolve there.

---

## Migrating from openssl

Every recipe in the [parent repository's README](../README.md) has a direct equivalent:

| openssl | Certio |
|---|---|
| `genpkey -algorithm RSA` | Key algorithm selector on any create form |
| `req -x509 -new -nodes … -days 1825` | **Authorities → New root CA** |
| `req -new -key … -subj` | Managed issuance, or `certio cert issue` |
| `req -new -config san.cnf` | **SAN chip input** — no `.cnf` files, ever |
| `x509 -req -CA … -CAcreateserial` | Signing with database-tracked random serials |
| `x509 -in cert.crt -text -noout` | **Inspect** page, or `certio cert inspect` |
| re-running the chain every year | **Renew** button, or auto-renew |
| `jkantech-ca.srl` bookkeeping | The `serial_number` column |

Already have a CA? `certio ca import --cert ca.crt --key ca.key` adopts it as it is — nothing is
re-issued, and every certificate it has already signed keeps verifying.

---

## License

[Apache-2.0](LICENSE) © [Jonas Kaninda](https://github.com/jkaninda)
