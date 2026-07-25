# Architecture

Phase 1 & 2: Architectural Foundations, Threading Constraints, and Go Migration

    Objective: Execute full, concurrent TCP 3-way handshakes to validate port states without relying on pre-packaged binaries like Nmap.
    The Problem (Python Threading Constraints & Protocol Deadlocks):
        The GIL & Memory Bloat: The initial Python prototype utilized concurrent.futures.ThreadPoolExecutor. Python's Global Interpreter Lock (GIL) restricted true parallel execution. Furthermore, standard OS-level threads consumed 1–2MB of RAM per stack. Spinning up thousands of concurrent threads to rapidly scan a target consumed gigabytes of memory and induced severe CPU context-switching thrashing.
        Application-Layer Deadlocks: Blindly calling a blocking recv() call immediately after a successful handshake on "client-first" protocols (like HTTP on port 80) caused threads to hang indefinitely while the server waited for a client request. The worker threads absorbed maximum timeout penalties, effectively deadlocking the scanner and stalling throughput.
    The Solution (Go Migration & Concurrency Design):
        Goroutine Multiplexing: The Python architecture was abandoned for Go to capitalize on its C10k-capable runtime scheduler. Go replaces heavy OS-level threads with lightweight Goroutines (starting at a mere 2KB memory footprint) multiplexed onto a small pool of actual OS threads using native, non-blocking event loops (epoll on Linux or kqueue on macOS).
        Worker Pool Pattern: Implemented a strict Worker Pool Pattern utilizing Go channels to feed tasks and collect results. Enforced compile-time memory safety by explicitly typing channels as receive-only (<-chan) and send-only (chan<-), eliminating data-sharing race conditions.
        The Monitor Pattern: Deployed sync.WaitGroup managed by a dedicated background Goroutine. This acts as a synchronization barrier, allowing the main thread to immediately read results without deadlocking when writing tasks.

Phase 3: Application-Layer banner Grabbing & Interface Polymorphism

    Objective: Extract valuable application-layer banner data instantly while avoiding socket hang timeouts.
    The Problem (Static Sockets & DNS Resolution Crashes):
        Silent Servers: Standard L4 TCP connections fail to extract banner data from modern client-first web servers without proactive querying.
        Blocking Defaults: In Go, socket I/O operations block indefinitely by default. If a target host holds a connection open but trickles bytes, a Goroutine will hang forever and slowly exhaust the worker pool.
        Pre-Flight Resolution Failures: Passing unvalidated hostnames directly into C-level socket functions causes fatal gaierror crashes if DNS resolution fails, abruptly killing the binary.
    The Solution (Interface Polymorphism & Strict Deadlines):
        Interface Polymorphism: Leveraged Go's net.Conn interface. Because both standard TCP connections and TLS-wrapped clients satisfy this interface, the engine dynamically wraps port 443/8443 traffic in TLS without duplicating any read/write logic.
        Dynamic Payloads: Engineered workers to inject a standard HTTP GET payload ("GET / HTTP/1.1\r\n\r\n") immediately post-handshake, forcing silent, client-first web servers to return headers instantly.
        Strict I/O Deadlines: Enforced aggressive socket I/O deadlines utilizing SetDeadline(), SetWriteDeadline(), and SetReadDeadline() to prevent slow-responsive servers from hanging active workers.
        Pre-Flight Stub Resolution: Integrated Go's standard flag and net packages to interact with the OS stub resolver. This strictly enforces IPv4 resolution and drops invalid targets before a single socket connection is opened.

Phase 4: State Table Exhaustion & Traffic Shaping

    Objective: Prevent self-imposed Denial of Service (DoS), evade target Intrusion Prevention Systems (IPS), and guarantee clean process termination.
    The Problem (NAT State Saturation & Leakage):
        NAT State Exhaustion: Launching unthrottled, concurrent workers (e.g., 250 threads) to rapidly scan WAN ranges over-allocates local ephemeral ports and fills up consumer/prosumer router translation tables. When NAT tables hit 100% capacity, routers drop subsequent outbound connections, which the host OS bubbles up as a fatal network is unreachable (ENETUNREACH) error. Here, concurrency was incorrectly conflated with throughput.
        Socket Leakage on SIGINT: When the process is aborted (Ctrl+C/SIGINT), standard runtimes instantly kill the binary, abandoning active sockets without sending a TCP FIN packet. This leaves dangling connections on the target and wastes host file descriptors.
        Terminal Output Interleaving: Concurrent workers attempting to print to stdout at the exact same microsecond interleave and corrupt terminal text.
    The Solution (Token Bucket Rate Limiting & Signal Trapping):
        Token Bucket Rate Limiting: Decoupled Goroutine concurrency from wire throughput by integrating the golang.org/x/time/rate package. Enforcing a global rate limiter with a strict burst capacity of 1 forces a mathematically precise pacing of outgoing packets.
        Context-Aware Execution: Upgraded standard net.Dial to DialContext and trapped SIGINT utilizing os/signal and context.Context. This allows the main thread to instantly propagate a cancellation signal across all workers, aborting pending network dials and gracefully sending FIN packets to tear down established sockets cleanly.
        Thread-Safe Telemetry: Implemented a -d debug flag using Go's standard log package, which utilizes internal mutex locking to safely serialize concurrent Layer 4 socket errors directly to os.Stderr.

Phase 5: Cryptographic Extraction & UNIX Stream Discipline

    Objective: Extract hidden infrastructure routing data and deliver structured telemetry cleanly to automated pipelines.
    The Problem (Defensive Certificate Masks & Brittle Logs):
        Defensive Masking: Multi-tenant IP addresses behind edge load balancers (like Google or Cloudflare) return generic, catch-all SSL certificates (such as invalid2.invalid) when probed directly by IP, blinding the scanner.
        Brittle Output: Standard human-readable terminal text is impossible to ingest reliably via SIEMs or UNIX parsing tools without writing brittle regex that breaks on output variations.
    The Solution (SNI Injection & JSONL Stream Separation):
        SNI Injection: Injected the original target hostname into the ServerName directive of the TLS configuration, forcing edge load balancers to serve the actual site certificates.
        Zero-Overhead SAN Extraction: Surgically parsed the PeerCertificates slice in the in-memory ConnectionState immediately following the cryptographic handshake. This extracts the Subject Alternative Names (SANs) to map hidden virtual hosts with zero extra network overhead.
        UNIX Stream Discipline: Enforced strict stream separation. All human-readable diagnostic status updates are aggressively routed to os.Stderr, while the final structured scan telemetry is marshaled into clean, flat Atomic JSON Lines (JSONL/NDJSON) and sent exclusively to os.Stdout. This allows the binary's output to be cleanly piped straight into jq or SIEM indexers without regex parsing.

Phase 6 & 8: Wide-Area Scaling, Ingestion Backpressure, and Stateful Edge Filtering

    Objective: Scale the engine to run mass-scans across vast CIDR blocks statefully while keeping a minimal memory and storage footprint.
    The Problem (OOMKills, Disk Write Saturation, and SIEM Noise):
        The Kubernetes OOMKiller (Exit Code 137): Standard pre-parsing and expanding a massive range (e.g. /16 contains 65,536 IPs) into memory structures (like TargetMap) before scanning allocated millions of string pointers to the heap. Under strict container cgroup resource limits (512Mi), this heap bloat triggered the Linux kernel OOMKiller.
        Queue Flooding: If the target generator parsed IPs faster than the L4 network workers could execute handshakes, millions of unexecuted jobs accumulated in memory.
        Disk Mutex & fsync Bottlenecks: Naively writing scan states directly to an embedded database across 10,000 concurrent Goroutines causes extreme mutex lock contention and saturates the OS disk queue, as bbolt requires an fsync on every update transaction to maintain ACID compliance.
        SIEM Ingestion Noise: Continuously scanning and logging static, unchanged open ports blasts thousands of redundant events into the SIEM daily, overloading rules engines and causing SOC alert fatigue.
    The Solution (Stream Parsing, Channel Backpressure, and Zero-Copy Delta Tracking):
        io.Reader Stream Ingestion: Refactored the target parser to accept an io.Reader and stream line-by-line via bufio.Scanner. This reduced target-tracking memory footprint to a flat O(1) complexity regardless of target size. Bitwise operations in expandCIDR are executed on-the-fly to parse subnet masks dynamically in memory.
        Channel Backpressure: Buffered the worker queue strictly at numWorkers * 2. When the queue saturated, the parser blocked on channel emission, pausing the HTTP target stream until workers freed up.
        bbolt & Zero-Copy mmap: Deployed bbolt as the state store. It maps the DB file using mmap, bypassing the Go GC via zero-copy views and leveraging the Linux kernel page cache for near-instantaneous reads.
        The Fan-In State Manager: Decoupled workers from the DB entirely. Workers simply dial, record state, push to a buffered results channel, and immediately return to the network. A single, dedicated State Manager Goroutine consumes this channel as the sole writer/reader to bbolt, eliminating database lock contention.
        Read-First Fast Path & Hashing: Stored state as keys (IP:Port) and values as high-speed non-cryptographic xxHash bytes of the payload. The State Manager executes a mmap zero-copy read first. It drops the event immediately if hashes match. Only upon a hash mismatch does it invoke an exclusive write (slow-path disk fsync) and emit a JSON delta payload.

Phase 7 & 8 (Deployment): Zero-Attack-Surface Containerization and Automated Kubernetes Orchestration

    Objective: Package the Go environment into an immutable, minimal container and automate execution schedules safely in a cluster environment.
    The Problem (Void Images, Lock Collisions, and Permissions):
        Cryptographic & Temporal Blindness: While deploying to an empty scratch image eliminates the attack surface, it lacks Root CA bundles (ca-certificates.crt), meaning any egress HTTPS request (e.g. pulling target files from S3/Gist) crashes with x509: certificate signed by unknown authority. It also lacks /etc/passwd or timezone bundles (zoneinfo), forcing the container to execute as root (UID 0).
        bbolt exclusive lock collisions: bbolt strictly demands an exclusive POSIX file lock (flock()). If a scan hangs and the K8s scheduler spawns Pod B while Pod A is active, Pod B deadlocks on the Persistent Volume.
        EACCES Perm Denied: Running as unprivileged UID 10001 caused the application to throw permission denied errors when initializing the default ./asm_state.db on the read-only container root / filesystem.
    The Solution (Multi-Stage Builds, Scheduler Policies, and Env Routing):
        The Multi-Stage Bridge: Compiled the static binary in a golang:1.24-alpine builder, setting CGO_ENABLED=0 and flags -tags netgo (for pure Go DNS resolution) and -extldflags '-static' to fully seal it. Updated alpine CA certificates and utilized adduser to provision an unprivileged user (UID 10001). Surgically copied only the binary, /etc/passwd, /etc/ssl/certs/ca-certificates.crt, and /usr/share/zoneinfo into the empty scratch image.
        Kubernetes Scheduler Controls: Set concurrencyPolicy: Forbid in the CronJob manifest, forcing K8s to drop subsequent scans if the previous pod is still active.
        Exclusive PVC: Configured a 1GB PersistentVolumeClaim (PVC) with ReadWriteOnce access mode to enforce exclusive block storage binding.
        Dynamic Paths: Refactored main to dynamically ingest db path variables (DB_PATH), routing the bbolt file descriptor directly to the mounted /data PVC.

SIEM Ingestion & Pipeline Integration (Wazuh)

    Objective: Securely ingest, decode, and alert on raw scanner telemetry inside an enterprise SIEM.
    The Problem (Silent Ingestion Drops, Keyring Permissions, and Template Corruptions):
        The Nested JSON Trap: Wazuh's native JSON decoder flattens or truncates nested object arrays, failing to parse traditional scanner structures.
        Silent Drops: Wazuh is an active engine, not a passive log-forwarder—it drops un-decoded logs that do not match a security rule.
        APT Security Warnings: Keyring files created with raw root permissions (0600) blocked unprivileged _apt signature validation, failing Wazuh Agent installs.
        Missing Schema Template: Filebeat threw errors (could not unmarshal json template: invalid character ':') because dead URLs downloaded HTML 404 pages instead of the actual wazuh-template.json.
    The Solution (Stream Piping, Rule Hierarchies, and Keyring Repair):
        Stream Piping: Used tee to write standard JSON payloads (stdout) directly to /var/log/tcprecon.json while keeping debug telemetry on stderr.
        Custom Decoder and Rules: Authored a local ruleset (ID 100050/100051/100052) that targets the JSON "msg":"open_port_detected" signature, dynamically mapping $(ip) and $(port) variables, escalating exposed SSH/port 22 to a Level 10 Critical Alert.
        Keyring Repair: Re-imported the Wazuh GPG key using --dearmor and explicitly granted read permissions (644) so _apt could verify repositories.
        Version Pinning & Setup: Downloaded the exact version-pinned v4.8.0 template, successfully running filebeat setup to map OpenSearch indices properly.
