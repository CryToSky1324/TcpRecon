# TcpRecon

This is a custom-engineered, highly concurrent TCP port scanner and network reconnaissance engine written in Go.

## Table of Contents

- [Core Capabilities](#core-capabilities)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage & Command Line Flags](#usage--command-line-flags)
- [Operational Execution Examples](#operational-execution-examples)
- [Understanding Results](#understanding-results)
- [Performance Tuning](#performance-tuning)
- [Limitations & Caveats](#limitations--caveats)
- [Architecture](#architecture)

## Core Capabilities

- **C10k-Capable Concurrency**: Utilizes a strict Goroutine Worker Pool pattern to multiplex millions of socket operations with a minimal memory footprint (starting at ~2KB per worker).

- **Token-Bucket Rate Limiting**: Completely decouples concurrency from throughput. A global token bucket enforces a strict Packets-Per-Second (PPS) ceiling to prevent self-imposed DoS and hardware lock-up.

- **Context-Aware Teardown**: Traps OS signals (e.g., SIGINT via Ctrl+C) to instantly propagate cancellation across all active workers, safely tearing down TCP connections without leaking file descriptors.

- **Application-Layer Injection**: Automatically injects HTTP GET payloads and wraps ports 443/8443 in TLS to force "client-first" protocols to reveal their banners instantly, bypassing standard socket-level silence.

- **Cryptographic X.509 Extraction**: Injects Server Name Indication (SNI) to force edge load balancers to serve actual domain certificates. Extracts Subject Alternative Names (SANs) directly from the TLS handshake.

- **Mass-Scale Target Ingestion**: Ingests targets via an -iL list, mathematically expanding CIDR blocks using bitwise operations and dynamically mapping hostnames to IPs before scanning.

- **Strict UNIX Stream Discipline**: Isolates human-readable diagnostic logs to stderr and outputs structured, machine-readable JSON exclusively to stdout for flawless CI/CD, jq, and SIEM integration.

## Installation

You must have Go 1.16+ installed to enforce strict dependency management. A C compiler (gcc/clang) may be required on some platforms for CGO support.

```bash
# Initialize the module
go mod init custom-scanner

# Fetch the rate-limiting dependency
go get golang.org/x/time/rate

# Sync dependencies and compile the statically linked binary
go mod tidy
go build -o scanner scanner.go
```

## Quick Start

```bash
./scanner google.com                           # Scan top 1000 ports (default)
./scanner -p 80,443 -w 100 192.168.1.0/24     # Scan specific ports on a subnet
./scanner -p 443 -r 50 -d example.com         # Slow, stealth scan with debug logging
```

## Usage & Command Line Flags

The engine enforces strict IPv4 resolution and drops invalid targets before a single socket is opened. You must specify either a single target as a positional argument or a target list via the -iL flag.

```plaintext
Usage: ./scanner [flags] <target>

Flags:
  -w int    Maximum number of concurrent Goroutine workers (default: 500)
  -t int    Timeout per port in milliseconds (default: 1000)
  -p string Ports to scan (e.g., 80,443,1-1024) (default: "1-1000")
  -r int    Global rate limit in packets per second (PPS) (default: 100)
  -iL file  Input file containing list of targets/CIDRs
  -d        Enable debug mode to log Layer 4 socket errors to stderr
  -j        Output results strictly in JSON format (mutes stdout text)
```

## Operational Execution Examples

### 1. The Stealth Probe (Targeted)

Scan the top 10,000 ports of a single host, aggressively throttled to 50 packets per second to evade IPS, while dumping Layer 4 drop-rules to stderr.

```bash
./scanner -w 500 -t 2000 -r 50 -p 1-10000 -d scanme.nmap.org
```

### 2. Wide-Area Mass Scanning

Ingest a mixed text file containing single IPs, hostnames, and full CIDR blocks (e.g., 10.0.0.0/8). The engine will expand the CIDRs mathematically and scan port 443 across all endpoints.

```bash
./scanner -w 1000 -t 1500 -r 250 -p 443 -iL targets.txt
```

### 3. CI/CD & SIEM Ingestion (JSON Mode)

Execute a fast scan against Google's edge infrastructure. Diagnostic updates bypass the pipe via stderr, while the pristine JSON payload flows directly into jq for parsing.

```bash
./scanner -w 500 -t 1000 -r 100 -p 443 -j google.com | jq .
```

## Example Output

```json
{
  "target": "google.com",
  "target_ip": "172.217.27.14",
  "duration_seconds": 0.118,
  "total_open": 1,
  "ports": [
    {
      "port": 443,
      "state": "OPEN",
      "banner": "HTTP/1.1 301 Moved Permanently Location: http://www.google.com/...",
      "tls_subject": "*.google.com",
      "tls_issuer": "WR2",
      "tls_sans": [
        "*.google.com",
        "*.cloud.google.com",
        "*.gemini.cloud.google.com",
        "youtube.com"
      ]
    }
  ]
}
```

## Understanding Results

- **state**: OPEN, CLOSED, or FILTERED based on TCP handshake response.
- **banner**: HTTP/TLS application-layer response (often reveals service version or redirect target).
- **tls_subject**: Primary subject CN from the X.509 certificate.
- **tls_issuer**: Certificate issuer (CA name).
- **tls_sans**: Subject Alternative Names — additional domains/IPs covered by the certificate.

## Performance Tuning

- **-w (workers)**: More workers = higher concurrency. 500–2000 typical. Monitor OS file handle limits with `ulimit -n` to avoid exhaustion.
- **-r (rate)**: Global rate limit in PPS. Balanced between DoS avoidance and detection evasion. Lower = stealthier, slower.
- **-t (timeout)**: Connection timeout per port in milliseconds. Reduce for speed on local networks, increase for high-latency targets.

**Example tuning for a /16 subnet scan:**
```bash
./scanner -w 1000 -t 1500 -r 500 -p 443 10.0.0.0/16
```

## Limitations & Caveats

- **Network Access**: Requires Internet/network access to target addresses. Firewall rules and IPS systems may block or throttle scans.
- **CIDR Limits**: CIDR blocks are practically limited to /0-/30 for sanity. Larger expansions can exhaust memory/time.
- **Platform**: Linux/Unix optimized. Windows is supported via WSL or MinGw.
- **Legal**: Only scan targets you own or have explicit written permission to scan. Unauthorized scanning is illegal in most jurisdictions.
- **Resolution**: IPv6 is not currently supported; only IPv4 targets are processed.

## Architecture

For a deep dive into the engineering decisions, state table exhaustion physics, and the evolution of this project from Python threads to Go multiplexing, read [ARCHITECTURE.md](./ARCHITECTURE.md).
