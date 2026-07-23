# ==========================================
# STAGE 1: Build the statically linked binary
# ==========================================
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install git or build essentials if needed for dependencies
RUN apk add --no-cache git

# Copy dependency tracking files first for optimized caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY TcpRecon.go .

# Compile a 100% static binary (disabling CGO)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o TcpRecon TcpRecon.go

# ==========================================
# STAGE 2: Assemble the minimalist scratch container
# ==========================================
FROM scratch

# Copy the compiled binary from the builder stage
COPY --from=builder /build/TcpRecon /TcpRecon

# Define the default entrypoint executable
ENTRYPOINT ["/TcpRecon"]
