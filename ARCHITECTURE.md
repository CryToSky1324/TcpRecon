System Architecture: Evolution of the TCP Reconnaissance Engine
Phase 1: The Python Prototype & Threading Limitations

The Objective: Execute full TCP 3-way handshakes to validate port states without relying on pre-packaged binaries like Nmap.

The Problem: The initial prototype utilized Python's socket library and concurrent.futures.ThreadPoolExecutor, introducing two fatal structural flaws. First, Python's Global Interpreter Lock (GIL) prevented true parallel execution. OS-level threads consumed 1-2MB of RAM per stack, meaning 1,000 threads consumed gigabytes of memory and induced severe CPU context-switching thrashing. Second, blindly calling recv() on "client-first" protocols (like HTTP on port 80) caused threads to hang indefinitely, forcing workers to absorb maximum timeout penalties and effectively deadlocking the scanner.

The Solution: The Python architecture was abandoned entirely in favor of Go, capitalizing on its native C10k-capable scheduler and lightweight concurrency model.
Phase 2: Go Migration & Memory Safety

The Objective: Achieve massive horizontal scalability without exhausting OS file descriptors or system memory.

The Problem: Naive concurrency in systems languages leads to race conditions, deadlocks, and kernel panics if Goroutines are not strictly orchestrated.

The Solution: We replaced heavy OS threads with the Worker Pool Pattern using Go's native event loop (epoll/kqueue) and Goroutines, which start at a mere 2KB memory footprint. Compile-time memory safety was engineered using receive-only (<-chan) and send-only (chan<-) channels to pipe data, eliminating memory-sharing race conditions. Finally, we deployed a sync.WaitGroup via the Monitor Pattern in a dedicated background Goroutine, preventing the main thread from deadlocking while waiting for the workers to drain the queue.
Phase 3: Application-Layer Injection & Polymorphism

The Objective: Extract valuable banner data instantly, bypassing the timeout penalties of client-first protocols.

The Problem: Standard TCP handshakes without application-layer interaction fail to extract data from modern web servers. Additionally, passing unvalidated hostnames directly into C-level sockets causes fatal gaierror crashes if DNS resolution fails.

The Solution: We leveraged Interface Polymorphism via Go's net.Conn interface, which allowed the engine to dynamically wrap ports 443/8443 in TLS without duplicating underlying read/write logic. The workers were engineered to inject a standard HTTP GET payload immediately post-handshake, forcing silent web servers to return their headers instantly. Pre-flight resolution was integrated using the flag and net packages to interact with the OS stub resolver, strictly enforcing IPv4 resolution and dropping invalid targets before a single socket is opened.
Phase 4: State Exhaustion & Traffic Shaping

The Objective: Prevent self-imposed Denial of Service (DoS) and evade target Intrusion Prevention Systems (IPS).

The Problem: Firing 250 unthrottled Goroutines overwhelmed local consumer router hardware. The router's NAT state table hit 100% capacity, resulting in active local packet drops bubbling up as network is unreachable errors. We were incorrectly conflating concurrency (active workers) with throughput (packets per second).

The Solution: Execution was decoupled from transmission using a Token Bucket Rate Limiter (golang.org/x/time/rate). A global token bucket forces Goroutines to block until a token is available, strictly enforcing a Packets-Per-Second (PPS) ceiling and ensuring NAT table survival. Context Cancellation (context.Context and os/signal) was implemented to trap SIGINT (Ctrl+C), allowing the main thread to instantly propagate a cancellation signal across all active workers, safely aborting pending network dials and gracefully tearing down established sockets without leaking file descriptors.
Phase 5: Cryptographic Extraction & UNIX Stream Discipline

The Objective: Extract hidden virtual host infrastructure and prepare the tool for CI/CD or SIEM ingestion.

The Problem: Connecting to edge load balancers via raw IPs returns garbage catch-all certificates (e.g., invalid2.invalid). Furthermore, standard stdout terminal text cannot be parsed by automated pipelines or tools like jq without writing brittle regex.

The Solution: The target hostname was injected into the TLS ServerName directive (SNI Injection), forcing edge servers to reveal their actual domain certificates. Subject Alternative Names (SANs) were extracted directly from the in-memory ConnectionState post-handshake, mapping hidden infrastructure with zero extra network overhead. We also engineered strict stream discipline via a JSON mode (-j). All human-readable diagnostic logs are aggressively routed to os.Stderr. The final, structured ScanReport payload is marshaled into clean JSON and sent exclusively to os.Stdout, allowing flawless pipeline interception.
Phase 6: Wide-Area Scaling & Ingestion Engine

The Objective: Scale the engine from single-target probes to mass-scanning wide-area networks (e.g., /16 CIDR blocks).

The Problem: Scanning a /16 subnet across a standard port list requires millions of socket operations. Storing all expanded IP strings as raw variables would cause massive memory bloat.

The Solution: Mathematical bitwise logic (expandCIDR) was built to parse subnet masks and dynamically generate exact IP slices in memory. The IP mapping was decoupled from the raw target string, and a file parser was engineered to ingest an input list (-iL), resolving hostnames and CIDRs into a TargetMap. Finally, the dispatcher was restructured to pass atomic ScanJob structs (containing IP, TargetName, and Port) into the worker channel, safely managing state across millions of permutations.
