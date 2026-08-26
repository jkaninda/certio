# syntax=docker/dockerfile:1

# ─── Stage 1: build the dashboard ────────────────────────────────────────────
FROM node:26-alpine AS ui

WORKDIR /build/web

# Copy the manifests first so the dependency layer is cached across UI edits.
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY web/ ./
RUN npm run build

# ─── Stage 2: build the binary ───────────────────────────────────────────────
FROM golang:1.26-alpine AS build

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# The dashboard is staged where //go:embed expects it.
COPY --from=ui /build/web/.output/public/ ./cmd/certio/dist/

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# CGO stays off even though the runtime stage is Alpine: the SQLite driver is
# pure Go, so the binary depends on no libc at all — musl's or anyone else's.
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /certio ./cmd/certio

# ─── Stage 3: runtime ────────────────────────────────────────────────────────
FROM alpine:3.24

LABEL org.opencontainers.image.title="Certio" \
      org.opencontainers.image.description="Self-signed PKI and TLS certificate manager" \
      org.opencontainers.image.source="https://github.com/jkaninda/certio" \
      org.opencontainers.image.licenses="AGPL-3.0"

# ca-certificates so webhook and SMTP notifications can verify the TLS they
# connect over; tzdata so a schedule configured in a local zone means what it
# says. The distroless base carried the former and not the latter.
RUN apk add --no-cache ca-certificates tzdata

# A named account rather than a bare numeric USER, so `ps` and an exec shell
# show something meaningful. The uid is deliberately 65532: that is what the
# distroless nonroot user was, and an existing /data volume is full of files
# owned by it. Changing the number would leave upgraders with a database they
# can no longer write.
RUN addgroup -g 65532 -S certio \
    && adduser -u 65532 -S -G certio -h /data -s /sbin/nologin certio \
    && mkdir -p /data \
    && chown certio:certio /data

COPY --from=build /certio /usr/local/bin/certio

ENV CERTIO_DB_PATH=/data/certio.db \
    CERTIO_HOST=0.0.0.0 \
    CERTIO_PORT=8080

EXPOSE 8080

USER certio:certio
WORKDIR /data

ENTRYPOINT ["/usr/local/bin/certio"]
CMD ["serve"]
