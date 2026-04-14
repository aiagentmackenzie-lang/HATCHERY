# HATCHERY — Malware Sandbox

> "Watch it hatch. Watch it burn."

**Type:** Dynamic malware analysis sandbox  
**Purpose:** Upload binary → detonate in isolated container → observe behavior in real-time → extract IOCs  
**Author:** Raphael Main + Agent Mackenzie  
**Created:** April 14, 2026  
**Status:** SPEC — Awaiting approval to build

---

## Why This Project

**The Problem:** Every malware analyst uses sandboxes — Cuckoo, CAPE, ANY.RUN, Joe Sandbox — but they're either massive enterprise platforms (Cuckoo: 6K⭐, requires full virtualization stack) or expensive SaaS (ANY.RUN: $500/mo). No single developer-built sandbox exists that demonstrates you understand *how* dynamic analysis works at the OS level.

**The Opportunity:** Build something that proves you can:
1. Isolate malicious execution safely (Docker containers, not full VMs)
2. Monitor process behavior at the syscall level (strace/ptrace, not just API hooks)
3. Capture network traffic in real-time (integrate with GHOSTWIRE)
4. Classify malware with YARA + capa (industry-standard tooling)
5. Present findings as a real-time behavioral timeline (not a static PDF report)
6. Auto-extract IOCs for threat intelligence sharing

**Competitive Landscape:**

| Tool | Stars | What It Does | Gap |
|------|-------|--------------|-----|
| Cuckoo Sandbox | 6,000 | Full VM-based malware analysis | Massive, requires KVM/QEMU, Python 2 legacy, unmaintained |
| CAPE Sandbox | 1,500+ | Cuckoo fork with better evasion handling | Still requires full VM infrastructure, complex setup |
| ANY.RUN | SaaS | Interactive cloud sandbox | $500/mo, no self-host, closed source |
| Joe Sandbox | SaaS | Enterprise malware analysis | Closed source, expensive |
| Drakvuf | 1,200 | Hypervisor-based sandbox | Complex C code, requires Xen hypervisor |
| FLARE VM | 6,000 | Windows malware analysis VM image | Not a sandbox — just a pre-built VM with tools |
| speakeasy | 1,400 | Emulation-based sandbox (no real execution) | No real execution = can't catch runtime behavior |
| capa | 5,925 | Static capability extraction | Not a sandbox — needs a sandbox to feed it samples |

**HATCHERY's niche:** A lightweight, Docker-based malware sandbox with real-time behavioral monitoring, YARA/capa classification, and a cyberpunk analyst dashboard. No VM stack required — containers + syscall monitoring. Not enterprise bloat — a focused detonation chamber.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      HATCHERY ENGINE                          │
│                                                                │
│  ┌──────────────┐   ┌───────────────────┐   ┌──────────────┐  │
│  │  Sample      │   │  Container Manager│   │  Behavioral  │  │
│  │  Intake      │──▶│  (Docker API)     │──▶│  Monitor     │  │
│  │  (hash/PE)   │   │  isolate → exec   │   │  (strace/    │  │
│  └──────────────┘   └───────────────────┘   │   inotify)   │  │
│        │                     │               └──────────────┘  │
│        ▼                     ▼                      │          │
│  ┌──────────────┐   ┌───────────────────┐          ▼          │
│  │  Static      │   │  Fake Services    │   ┌──────────────┐  │
│  │  Analysis    │   │  (INetSim-like)    │   │  Network     │  │
│  │  (YARA/capa) │   │  DNS/HTTP/SMTP    │   │  Capture     │  │
│  └──────────────┘   └───────────────────┘   │  (tcpdump)   │  │
│        │                     │              └──────────────┘  │
│        ▼                     ▼                      │          │
│  ┌─────────────────────────────────────────────────┘          │
│  │              Event Stream (SSE / WebSocket)                │
│  └──────────────────────────────────┬────────────────────────┘
│                                     ▼                          │
│  ┌──────────────────────────────────────────────────────┐    │
│  │                  IOC Extractor                         │    │
│  │  IPs • Domains • URLs • File hashes • Mutexes         │    │
│  │  Registry keys • Dropped files • C2 patterns          │    │
│  └──────────────────────────────────────────────────────┘    │
│                                     │                          │
│                                     ▼                          │
│  ┌──────────────────────────────────────────────────────┐    │
│  │               Report Generator                         │    │
│  │  Markdown • STIX 2.1 • MITRE ATT&CK • JSON            │    │
│  └──────────────────────────────────────────────────────┘    │
│                                     │                          │
│  ┌──────────────────────────┐   ┌───┴───────────────────┐    │
│  │  Fastify API Server      │   │  React Dashboard       │    │
│  │  + WebSocket (SSE)       │──▶│  (Real-time behavior)  │    │
│  └──────────────────────────┘   └───────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Container Isolation** | Docker + custom seccomp profile | Lightweight, fast startup, no VM stack needed |
| **Process Monitoring** | strace (syscall tracing) + inotifywait (file events) | Linux-native, zero-hook approach — harder for malware to detect than API hooking |
| **Network Capture** | tcpdump + tc (traffic control for network isolation) | Standard Linux tools, pcap output feeds GHOSTWIRE |
| **Fake Internet** | Custom Python (DNS/HTTP/SMTP/IRC mock servers) | Simulates real environment — malware "phones home" to our sinkhole |
| **Static Analysis** | YARA 4.x + capa (Mandiant/FLARE) | Industry standard classification tools, 5.9K⭐ + 6K⭐ respectively |
| **Backend API** | Python (FastAPI) + Fastify (TypeScript) | Python for analysis logic (YARA/capa/strace integration), TypeScript for API |
| **Dashboard** | React + Vite + Tailwind + D3.js | Real-time behavioral timeline, process tree, network graph |
| **IPC** | Server-Sent Events (SSE) + WebSocket | Stream behavioral events to dashboard in real-time |

**Why Docker over full VM (Cuckoo/CAPE approach):**
1. **Speed** — Container starts in ~1s vs 30-60s for VM boot
2. **Simplicity** — No KVM/QEMU/VirtualBox dependency
3. **Real syscall tracing** — strace works natively in containers (not in VM guests)
4. **Acceptable for portfolio** — We're demonstrating sandbox *concepts*, not replacing ANY.RUN
5. **Honest trade-off** — We document that Docker isolation is weaker than VM isolation for evasive malware (this is a known limitation, and acknowledging it demonstrates expertise)

**Why strace over API hooking (Cuckoo approach):**
1. **Harder to detect** — strace uses ptrace from outside the process; API hooking injects DLLs
2. **No in-guest agent** — Malware can't kill what isn't inside its process
3. **Complete syscall coverage** — Every open/read/write/connect/execve captured
4. **Limitation acknowledged** — Advanced anti-debug malware can detect ptrace (documented)

---

## Core Features

### Phase 1 — Sandbox Core (Week 1)

#### 1.1 Sample Intake & Fingerprinting
- Accept file upload (PE, ELF, Mach-O, scripts, shellcode)
- Compute hashes immediately: MD5, SHA1, SHA256, SSDeep (fuzzy hash)
- PE analysis: import table, sections, compile timestamp, resources, strings
- ELF analysis: symbols, libraries, security properties
- Store sample with metadata in SQLite

#### 1.2 Static Analysis Pipeline
- **YARA scanning** — Run against curated rule sets:
  - MalwareBazaar rules (community-maintained, 1000+ rules)
  - FLARE rules (Mandiant/Google, APT-focused)
  - Custom HATCHERY rules (anti-debug, sandbox evasion, packing detection)
- **capa analysis** — Extract capabilities from PE/ELF:
  - Maps to MITRE ATT&CK techniques
  - Identifies: keylogging, screenshot capture, C2 communication, persistence, etc.
  - JSON output parsed and stored
- **Strings extraction** — URLs, IPs, domains, file paths, registry keys
- **Packer detection** — Common packers: UPX, Themida, VMProtect, MPRESS

#### 1.3 Docker Container Manager
- Custom Docker image based on Alpine/Ubuntu with:
  - Pre-installed: strace, tcpdump, inotify-tools, Python 3
  - Fake services: DNS (port 53), HTTP (port 80), HTTPS (port 443), SMTP (port 25)
  - Fake desktop environment variables and user profiles
  - Anti-evasion: realistic hostname, username, uptime, processes
- Container lifecycle:
  - Create → Execute sample → Monitor (timeout: 120s) → Kill → Capture artifacts
- Resource limits: CPU 50%, memory 512MB, no network access to host
- Seccomp profile: whitelist safe syscalls, log denied syscalls
- Network isolation: container can only reach fake services (iptables rules)

### Phase 2 — Behavioral Monitoring (Week 2)

#### 2.1 Syscall Tracing (strace)
- Attach strace to sample process before execution
- Capture all syscalls with arguments and return values
- Key syscalls to monitor:

| Category | Syscalls | What It Reveals |
|----------|----------|-----------------|
| **File System** | open, openat, read, write, unlink, rename, chmod | File access, creation, deletion, modification |
| **Network** | connect, bind, accept, sendto, recvfrom | C2 connections, data exfiltration, listening ports |
| **Process** | execve, fork, clone, kill, ptrace | Child processes, injection, anti-debug |
| **Registry** | N/A (Linux: read/write /proc, /sys, config files) | Persistence, system modification |
| **Memory** | mmap, mprotect, brk | Self-modification, shellcode injection |

- Parse strace output into structured events in real-time
- Feed events to SSE stream for dashboard

#### 2.2 File System Monitoring (inotifywait)
- Watch all directories in container for:
  - File creation (IN_CREATE)
  - File modification (IN_MODIFY)
  - File deletion (IN_DELETE)
  - File access (IN_ACCESS)
  - Directory creation (IN_CREATE, ISDIR)
- Hash all created/modified files on-the-fly
- Flag suspicious patterns:
  - Writing to /tmp, /dev/shm (dropper behavior)
  - Modifying ~/.bashrc, ~/.ssh (persistence)
  - Creating hidden files (dot-prefix)
  - Writing executables (ELF/PE magic bytes)

#### 2.3 Network Traffic Capture
- tcpdump running inside container (isolated network namespace)
- Capture all traffic to PCAP
- Real-time packet feed to GHOSTWIRE for C2 detection
- Mock services respond to malware:
  - **DNS** — Resolve everything to 127.0.0.1 (sinkhole)
  - **HTTP** — Return 200 OK with generic responses (trick C2 check-in)
  - **HTTPS** — Self-signed cert for any SNI (capture TLS SNI)
  - **SMTP** — Accept and log all mail (capture exfiltrated data)

#### 2.4 Fake Internet Services
- Custom Python servers that simulate a real network environment:
  - **DNS Server** (port 53): Resolves all queries → logs domains, returns fake IPs
  - **HTTP Server** (port 80/443): Returns generic 200s → logs URLs, User-Agents, POST data
  - **SMTP Server** (port 25): Accepts all mail → logs recipients, attachments
  - **IRC Server** (port 6667): Accepts bot connections → logs C2 commands
  - **Time Server** (port 37): Responds normally
- All fake services log to structured JSON for IOC extraction

### Phase 3 — Dashboard (Week 3)

#### 3.1 Real-Time Behavioral Timeline
- Chronological stream of all behavioral events
- Color-coded by type:
  - 🔴 Process events (execve, fork)
  - 🟠 Network events (connect, bind)
  - 🟡 File events (open, write, create)
  - 🔵 Registry/config events
  - 🟢 Memory events (mmap, mprotect)
- Click event → full syscall details with args
- Filter by type, severity, timestamp range

#### 3.2 Process Tree Visualization
- D3.js tree layout showing parent→child process relationships
- Node color = threat level (green → yellow → red)
- Node size = number of syscalls
- Hover → process details, command line, hashes
- Detect: process injection (parent-child mismatch), hollowing (execve without fork)

#### 3.3 Network Activity Panel
- Live connection log: src:port → dst:port, protocol
- Integrates GHOSTWIRE's C2 beacon detection
- GeoIP map of external connections
- DNS query timeline showing DGA patterns

#### 3.4 File System Changes
- Diff view: before/after container state
- New files highlighted, deleted files struck through
- Modified files with diff content
- Auto-hash all artifacts
- One-click download of dropped files for further analysis

#### 3.5 IOC Summary Panel
- Auto-extracted indicators:
  - **Network IOCs**: IPs, domains, URLs, User-Agents
  - **File IOCs**: Dropped file hashes (MD5/SHA256), file paths
  - **String IOCs**: Email addresses, C2 paths, encryption keys
  - **YARA matches**: Rule name + description + matched strings
  - **capa capabilities**: MITRE ATT&CK mapped capabilities
- Copy-all button for each IOC category
- Export as STIX 2.1 bundle (compatible with GHOSTWIRE)

#### 3.6 YARA/capa Results Panel
- YARA rule matches with highlighted matching strings
- capa capability tree grouped by MITRE tactic
- Confidence indicators and rule source attribution

### Phase 4 — Polish & Demo (Week 4)

#### 4.1 Sample Binary Library
- Curated test samples from public sources (safe/detonated):
  - EICAR test file (standard AV test)
  - MalwareBazaar samples (with known classifications)
  - TheZoo repository samples
- Pre-analyzed results for instant demo

#### 4.2 Report Generator
- Full behavioral report (Markdown + PDF)
- IOC summary table
- MITRE ATT&CK technique mapping
- Executive summary (non-technical)
- STIX 2.1 export for threat intel platforms

#### 4.3 CLI Mode
- Full analysis from terminal:
  ```bash
  hatchery submit sample.exe --timeout 120
  hatchery status <task_id>
  hatchery report <task_id> --format markdown
  hatchery iocs <task_id> --format stix
  ```
- JSON output for automation

---

## UI Design Language

**Theme:** Same GHOSTWIRE palette — dark, neon-accented, functional  
**Inspiration:** ANY.RUN's interactive view, but darker and developer-focused  
**Colors:**
- Background: `#0a0a0f`
- Surface: `#13131a`
- Primary accent: `#ff6b35` (orange — malware warning, distinct from GHOSTWIRE's green)
- Danger: `#ff3366`
- Warning: `#ffaa00`
- Info: `#00aaff`
- Success: `#00ff9f`
- Text: `#e0e0e0`

**Key Design Elements:**
- Real-time event stream scrolls like a terminal (monospace, tight spacing)
- Process tree uses animated connectors when new processes spawn
- Network connections pulse when data flows
- File system changes flash briefly when created/modified
- "Live" indicator pulses while sample is executing

---

## File Structure

```
HATCHERY/
├── SPEC.md                        # This file
├── README.md                      # GitHub landing page
├── pyproject.toml                 # Python packaging
├── package.json                   # Dashboard (React)
│
├── engine/                        # Python — Core analysis engine
│   ├── __init__.py
│   ├── intake/                    # Sample intake & fingerprinting
│   │   ├── uploader.py           # File upload handling
│   │   ├── hasher.py             # Multi-hash computation
│   │   ├── pe_analyzer.py        # PE analysis (pefile)
│   │   ├── elf_analyzer.py       # ELF analysis
│   │   └── strings.py            # String extraction & classification
│   ├── static/                    # Static analysis pipeline
│   │   ├── yara_scanner.py       # YARA rule scanning
│   │   ├── capa_scanner.py       # capa capability extraction
│   │   ├── packer_detect.py      # Packer identification
│   │   └── rules/                # YARA rules directory
│   │       ├── flare/            # FLARE/Mandiant rules
│   │       ├── malware_bazaar/   # Community rules
│   │       └── hatchery/         # Custom rules
│   ├── sandbox/                   # Container management
│   │   ├── container.py          # Docker container lifecycle
│   │   ├── seccomp.json          # Seccomp profile
│   │   ├── docker/              # Docker image build files
│   │   │   ├── Dockerfile        # Sandbox container image
│   │   │   └── entrypoint.sh     # Sample execution script
│   │   └── network.py            # Network isolation config
│   ├── monitor/                   # Behavioral monitoring
│   │   ├── strace_parser.py      # strace output parser
│   │   ├── file_watcher.py       # inotify event handler
│   │   ├── network_capture.py    # tcpdump management
│   │   └── event_stream.py       # SSE event aggregator
│   ├── fake_services/             # Simulated internet
│   │   ├── dns_server.py         # Fake DNS (sinkhole)
│   │   ├── http_server.py        # Fake HTTP/HTTPS
│   │   ├── smtp_server.py        # Fake SMTP
│   │   └── service_manager.py    # Orchestrate all fakes
│   ├── ioc/                       # IOC extraction
│   │   ├── extractor.py          # Aggregate IOCs from all sources
│   │   ├── network_iocs.py       # IP/domain/URL extraction
│   │   ├── file_iocs.py          # Dropped file hash extraction
│   │   └── string_iocs.py        # Email/path/key extraction
│   ├── export/                    # Report generation
│   │   ├── report.py             # Markdown/PDF reports
│   │   ├── stix.py               # STIX 2.1 export
│   │   └── mitre_map.py          # MITRE ATT&CK mapping
│   └── cli.py                     # CLI entry point
│
├── server/                        # Fastify API
│   ├── index.ts                   # Entry point + WebSocket
│   ├── routes/
│   │   ├── submit.ts             # Sample submission
│   │   ├── status.ts             # Analysis status
│   │   ├── report.ts            # Report retrieval
│   │   └── iocs.ts              # IOC export
│   └── db/
│       └── schema.sql             # SQLite schema
│
├── dashboard/                     # React — Analyst dashboard
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── Timeline.tsx      # Real-time behavioral event stream
│   │   │   ├── ProcessTree.tsx   # Process tree visualization
│   │   │   ├── NetworkPanel.tsx  # Network activity log
│   │   │   ├── FileSystemView.tsx# File system changes diff
│   │   │   ├── IOCPanel.tsx      # IOC summary & copy
│   │   │   ├── YARAResults.tsx   # YARA/capa results
│   │   │   ├── SampleUpload.tsx  # File upload with drag-drop
│   │   │   └── LiveIndicator.tsx # Pulsing "LIVE" badge
│   │   └── hooks/
│   │       └── useEventStream.ts  # SSE/WebSocket hook
│   └── vite.config.ts
│
├── samples/                       # Test samples (EICAR + known-benign)
│   └── README.md                  # Source attribution
│
└── tests/
    ├── test_strace_parser.py
    ├── test_ioc_extractor.py
    ├── test_yara_scanner.py
    └── fixtures/
        └── eicar.com              # Standard AV test file
```

---

## Dependencies

### Python (engine)
| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | ^0.115 | API framework |
| uvicorn | ^0.34 | ASGI server |
| docker | ^7.0 | Docker SDK (container management) |
| yara-python | ^4.5 | YARA scanning engine |
| flare-capa | ^9.0 | Capability extraction |
| pefile | ^2024.0 | PE binary analysis |
| pyelftools | ^0.32 | ELF binary analysis |
| ssdeep | ^3.4 | Fuzzy hashing |
| aiofiles | ^24.0 | Async file I/O |
| rich | ^13.0 | CLI output |
| click | ^8.0 | CLI framework |
| tcpdump | system | Network capture (apt install) |
| strace | system | Syscall tracing (apt install) |
| inotify-tools | system | File events (apt install) |

### TypeScript (server + dashboard)
| Package | Version | Purpose |
|---------|---------|---------|
| fastify | ^5.0 | API server |
| better-sqlite3 | ^11.0 | SQLite driver |
| react | ^19.0 | Dashboard UI |
| d3 | ^7.0 | Process tree + network graphs |
| tailwindcss | ^4.0 | Styling |

---

## Docker Sandbox Image

```dockerfile
# HATCHERY sandbox container — isolated detonation environment
FROM ubuntu:22.04

# Anti-evasion: Make it look like a real desktop
RUN apt-get update && apt-get install -y \
    strace tcpdump inotify-tools python3 \
    curl wget netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Fake desktop indicators (fool basic sandbox checks)
RUN echo "desktop-user" > /etc/hostname && \
    useradd -m -s /bin/bash user && \
    echo "user:Password123" | chpasswd && \
    mkdir -p /home/user/Desktop /home/user/Documents /home/user/Downloads

# Fake services will be injected at runtime
COPY entrypoint.sh /hatchery/entrypoint.sh
RUN chmod +x /hatchery/entrypoint.sh

# Default: run sample with strace attached
ENTRYPOINT ["/hatchery/entrypoint.sh"]
```

### Seccomp Profile (Key Restrictions)
- **Blocked:** mount, umount2, ptrace (prevent escape), reboot, mount, keyctl, add_key, request_key
- **Logged:** clone, fork, execve, connect, bind, openat, unlink, rename, chmod, mknod
- **Allowed:** All standard process/file/network syscalls

### Network Isolation
- Container uses custom Docker network with no internet access
- iptables rules redirect all traffic to fake services running on gateway
- Only fake DNS (port 53), HTTP (80/443), SMTP (25) reachable
- All other traffic dropped + logged

---

## Demo Scenario (For Portfolio)

**The Pitch:** "Give me any suspicious binary and I'll show you exactly what it does — in real time."

1. Upload a known-malware sample (e.g., a dropper)
2. HATCHERY hashes it, runs YARA/capa static analysis instantly
3. Capa identifies: "keylogger capability detected", "HTTP C2 communication"
4. Sample submitted to sandbox container
5. Dashboard goes **LIVE** — events stream in:
   - Process spawns child (dropper extracting payload)
   - File written to /tmp/payload (inotify catches it, hashes it)
   - DNS query to c2.evil-domain.com (fake DNS logs it)
   - HTTP POST to 185.x.x.x/upload (fake HTTP captures exfil data)
   - Persistence: .bashrc modified
6. IOC panel populates automatically
7. GHOSTWIRE integration: PCAP shows C2 beacon with 0.02 jitter
8. Export STIX report with all IOCs + MITRE ATT&CK mapping

**Why this closes interviews:** You're not *describing* malware analysis. You're *running a live detonation* and explaining the behavior in real-time. That's "start Monday" energy.

---

## What This Proves to Hiring Managers

| Skill | How HATCHERY Demonstrates It |
|-------|-------------------------------|
| **Malware analysis** | Built a sandbox — understands detonation, behavioral monitoring, IOC extraction |
| **Container security** | Docker isolation + seccomp + network sandboxing |
| **Linux internals** | strace syscall tracing, inotify, process trees |
| **Static analysis** | YARA rule writing + capa capability extraction |
| **Fake environment design** | INetSim-style services — understands evasion techniques |
| **Threat intelligence** | STIX 2.1 export, MITRE ATT&CK mapping |
| **Real-time systems** | SSE event streaming, WebSocket dashboard |
| **Full-stack engineering** | Python engine + TypeScript API + React dashboard |

---

## Known Limitations (Honest — Documented in README)

1. **Docker ≠ VM isolation** — Containers share the host kernel. Evasive malware using VM detection will not be fooled. This is documented, not hidden.
2. **ptrace detection** — Advanced anti-debug malware can detect strace. For portfolio purposes, we demonstrate the concept; production sandboxes use hypervisor-level monitoring.
3. **Windows malware** — HATCHERY runs Linux containers. PE samples can be analyzed statically (YARA/capa/pefile) but dynamic execution requires a Windows container (future enhancement).
4. **No VM snapshot/restore** — Unlike Cuckoo, we don't snapshot/restore clean state between runs. Each analysis spins a fresh container (slightly slower but cleaner).

These limitations are *features of the spec* — they show you understand the trade-offs, which is more impressive than pretending your tool is perfect.

---

## Integration with GHOSTWIRE

| Feature | Integration |
|---------|------------|
| PCAP analysis | HATCHERY captures network PCAP → feeds to GHOSTWIRE engine |
| C2 beacon detection | GHOSTWIRE's beacon detector runs on sandbox traffic |
| JA4+ fingerprinting | TLS fingerprints from sandbox HTTPS traffic |
| DNS threat detection | GHOSTWIRE analyzes DGA patterns in sandbox DNS queries |
| STIX export | Both tools export compatible STIX 2.1 bundles |

---

## Timeline

| Week | Deliverable | Status |
|------|------------|--------|
| 1 | Sample intake + static analysis (YARA/capa/pefile) + Docker container manager | 🔲 |
| 2 | Behavioral monitoring (strace/inotify/tcpdump) + fake services + event streaming | 🔲 |
| 3 | Dashboard (timeline, process tree, network panel, file system diff, IOC panel) | 🔲 |
| 4 | CLI mode + reports + sample library + GHOSTWIRE integration | 🔲 |

---

## Success Criteria

- [ ] Accepts file upload and computes all hashes in <2s
- [ ] YARA + capa static analysis completes in <10s
- [ ] Docker container starts and executes sample in <5s
- [ ] strace events stream to dashboard in real-time (<100ms latency)
- [ ] Fake services respond to malware network calls correctly
- [ ] IOCs auto-extracted from all monitoring sources
- [ ] Process tree renders correctly for multi-process malware
- [ ] GHOSTWIRE integration: PCAP from sandbox → C2 detection
- [ ] Report generated with MITRE ATT&CK mapping
- [ ] README has demo GIF + honest limitations section

---

## Differentiators vs Existing Tools

| Feature | Cuckoo | CAPE | ANY.RUN | HATCHERY |
|---------|--------|------|---------|----------|
| Self-hosted | ✅ | ✅ | ❌ | ✅ |
| Single developer built | ❌ | ❌ | ❌ | ✅ |
| Docker-based (no VM) | ❌ | ❌ | ❌ | ✅ |
| Real-time dashboard | ❌ | ❌ | ✅ | ✅ |
| YARA + capa built-in | ❌ | ❌ | ❌ | ✅ |
| Syscall-level monitoring | ❌ | ✅ (hooks) | ✅ | ✅ (strace) |
| Fake internet services | ❌ | ❌ | ✅ | ✅ |
| GHOSTWIRE integration | ❌ | ❌ | ❌ | ✅ |
| Setup complexity | High | High | None (SaaS) | **Medium** |
| Cost | Free | Free | $500/mo | **Free** |

---

*"Watch it hatch. Watch it burn. Either way, you'll know exactly what it did."*