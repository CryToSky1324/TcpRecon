# ==========================================
# STAGE 1: The Builder (OS & Compilation Environment)
# ==========================================
FROM golang:1.24-alpine AS builder

# 1. Update OS dependencies for cryptographic trust and temporal accuracy
RUN apk update && apk add --no-cache git ca-certificates tzdata && update-ca-certificates

# 2. Provision an unprivileged user space (Namespace Isolation)
# Creating a dedicated user with UID 10001 to pass into the scratch container.
ENV USER=recon
ENV UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR /src

# 3. Layer Caching: Dependency tracking
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# 4. Ingest the refactored project tree
COPY cmd/ cmd/
COPY internal/ internal/

# 5. Compile the deterministic static binary
# - CGO_ENABLED=0: Force static compilation (eliminate libc dependencies)
# - -w -s: Strip DWARF debugging information and symbol table 
# - -extldflags '-static': Force external linker to emit a fully static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -tags netgo -ldflags="-w -s -extldflags '-static'" \
    -o /go/bin/tcprecon cmd/tcprecon/main.go

# ==========================================
# STAGE 2: The Void (Zero-Attack-Surface Execution)
# ==========================================
FROM scratch

# 1. Import the cryptographic trust chain (Resolves X.509/TLS blindness)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# 2. Import timezone data (Mandatory for deterministic JSON log timestamps)
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# 3. Import namespace mapping (Resolves UID 0 violation)
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# 4. Import the compiled binary
COPY --from=builder /go/bin/tcprecon /bin/tcprecon

# 5. Enforce unprivileged execution boundaries
USER recon:recon

# 6. Execute
ENTRYPOINT ["/bin/tcprecon"]
