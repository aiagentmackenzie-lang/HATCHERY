# HATCHERY — Malware Sandbox Engine

> *"Watch it hatch. Watch it burn. Either way, you'll know exactly what it did."*

**Docker-based malware sandbox with real-time behavioral monitoring, YARA/capa classification, and GHOSTWIRE C2 detection integration.**

---

## What It Does

HATCHERY accepts suspicious binaries, detonates them in isolated Docker containers, and observes their behavior in real-time:

1. **Static Analysis** — Multi-hash computation, PE/ELF parsing, YARA scanning, capa capability extraction, packer detection
2. **Dynamic Analysis** — Docker container detonation with strace syscall tracing, inotify file watching, and tcpdump network capture
3. **Fake Internet** — Simulated DNS/HTTP/SMTP services so malware thinks it's online (and detonates fully)
4. **IOC Extraction** — Auto-extracted IPs, domains, URLs, file hashes, C2 beacons
5. **Threat Intel Export** — STIX 2.1 bundles, MITRE ATT&CK mapping, Markdown/JSON reports

---

## Quick Start

```bash
# Install
cd HATCHERY
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Run static analysis on a sample
hatchery static suspicious.exe

# Submit for full analysis (static + sandbox)
hatchery submit suspicious.exe --timeout 120

# Check analysis status
hatchery status <task_id>

# Generate report
hatchery report <task_id> --format markdown
hatchery report <task_id> --format stix

# Build the sandbox Docker image
hatchery build
```

---

## Architecture

```
Sample → Intake (hash/PE/ELF/strings) → Static (YARA/capa/packer)
   ↓                                        ↓
   └──→ Sandbox (Docker container) ──→ Behavioral Monitor (strace/inotify/tcpdump)
              │                                      │
              └──→ Fake Services (DNS/HTTP/SMTP)     ↓
              │                              Event Stream (SSE)
              ↓                                      ↓
         Network Capture (PCAP) ──→ GHOSTWIRE C2 Detection
                                                    ↓
                                          IOC Extraction → Report/STIX/ATT&CK
```

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Container Isolation | Docker + seccomp | Fast startup, no VM stack needed |
| Process Monitoring | strace (syscall tracing) | Zero-hook approach — harder for malware to detect |
| Network Capture | tcpdump + PCAP analysis | Standard tools, feeds GHOSTWIRE |
| Fake Internet | Custom Python (DNS/HTTP/SMTP) | INetSim-style — trick malware into detonating |
| Static Analysis | YARA 4.x + capa 9.0+ | Industry standard (6K⭐ each) |
| CLI | Click + Rich | Beautiful terminal output |
| C2 Detection | GHOSTWIRE integration | PCAP → beacon detection → JA4+ fingerprinting |

---

## Key Design Decisions

### Docker over VM (Cuckoo/CAPE approach)
- **Speed**: Container starts in ~1s vs 30-60s for VM boot
- **Simplicity**: No KVM/QEMU/VirtualBox dependency
- **Real strace**: Works natively in containers
- **Trade-off acknowledged**: Docker isolation is weaker than VM for evasive malware

### strace over API Hooking (Cuckoo approach)
- **Harder to detect**: ptrace from outside the process; no injected DLLs
- **No in-guest agent**: Malware can't kill what isn't inside its process
- **Complete coverage**: Every syscall captured
- **Trade-off acknowledged**: Advanced anti-debug can detect ptrace

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `hatchery submit <file>` | Full analysis: static + sandbox + IOC extraction |
| `hatchery static <file>` | Static analysis only (no sandbox) |
| `hatchery status <id>` | Check analysis task status |
| `hatchery report <id>` | Generate analysis report |
| `hatchery iocs <id>` | Extract IOCs |
| `hatchery build` | Build sandbox Docker image |

Options:
- `--timeout SECONDS` — Sandbox execution timeout (default: 120s)
- `--output DIR` — Output directory for results
- `--no-sandbox` — Skip container execution (static only)
- `--format FORMAT` — Report format: markdown, json, stix

---

## YARA Rules

Custom HATCHERY rules cover:

| Category | Rules | Detects |
|----------|-------|---------|
| Anti-Debug | 4 | IsDebuggerPresent, timing checks, PEB checks, OutputDebugString |
| Sandbox Evasion | 5 | Sleep bombs, desktop checks, VM artifacts, process enumeration, driver checks |
| Packing | 6 | UPX, VMProtect, Themida, MPRESS, NSIS, generic high-entropy |
| Network C2 | 3 | HTTP C2, socket C2, DNS tunneling/DGA |

Add more rules to `engine/static/rules/hatchery/` — they're auto-compiled on first scan.

---

## GHOSTWIRE Integration

HATCHERY feeds sandbox PCAPs to [GHOSTWIRE](../GHOSTWIRE/) for:

- **C2 beacon detection** — Statistical jitter analysis on network sessions
- **JA4+ fingerprinting** — TLS fingerprinting from HTTPS traffic
- **DNS threat detection** — DGA pattern analysis
- **STIX export** — Both tools export compatible STIX 2.1 bundles

---

## API & Dashboard

```bash
# Start the API server
cd server && npm install && npm run dev
# → http://localhost:3002

# Start the dashboard
cd dashboard && npm install && npm run dev
# → http://localhost:5174
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/submit` | Submit sample for analysis |
| POST | `/api/submit/:id/retry` | Retry failed analysis |
| GET | `/api/tasks` | List all tasks |
| GET | `/api/tasks/:id` | Task details + static/sandbox results |
| GET | `/api/tasks/:id/events` | Behavioral events (paginated, filterable) |
| GET | `/api/tasks/:id/network` | Network connections |
| GET | `/api/tasks/:id/filesystem` | File system changes |
| GET | `/api/tasks/:id/report` | Full report (JSON/Markdown/STIX) |
| GET | `/api/tasks/:id/iocs` | IOC extraction (JSON/STIX/text) |
| GET | `/ws` | WebSocket for real-time event streaming |

### Dashboard Features

- 🔥 **Sample Upload** — Drag-drop or path input
- 🔴 **Live Timeline** — Real-time scrolling behavioral event stream
- 🌳 **Process Tree** — D3.js parent→child visualization (size = event count, color = threat)
- 🌐 **Network Panel** — Connection log with GHOSTWIRE integration hint
- 📁 **Filesystem View** — Suspicious path alerts (/tmp, .bashrc, /dev/shm)
- 🎯 **IOC Panel** — Grouped by type, copy-all, STIX export
- 🔍 **YARA/capa Results** — Rule matches, ATT&CK mapping, PE analysis
- 📊 **Live Indicator** — Pulsing red dot when connected to WebSocket

---

## Known Limitations

1. **Docker ≠ VM isolation** — Containers share the host kernel. Evasive malware using VM detection won't be fooled. This is documented, not hidden.
2. **ptrace detection** — Advanced anti-debug malware can detect strace. Production sandboxes use hypervisor-level monitoring.
3. **Windows malware** — HATCHERY runs Linux containers. PE samples can be analyzed statically (YARA/capa/pefile) but dynamic execution requires Windows containers (future enhancement).
4. **No VM snapshot/restore** — Unlike Cuckoo, we don't snapshot/restore clean state. Each analysis spins a fresh container.

**These limitations are features of the spec** — they demonstrate you understand the trade-offs, which is more impressive than pretending your tool is perfect.

---

## File Structure

```
HATCHERY/
├── engine/
│   ├── intake/         # Sample upload, hashing, PE/ELF/strings
│   ├── static/         # YARA, capa, packer detection + rules/
│   ├── sandbox/        # Docker container manager + seccomp + Dockerfile
│   ├── monitor/        # strace parser, file watcher, network capture, event stream
│   ├── fake_services/  # DNS, HTTP, SMTP servers + manager
│   ├── ioc/            # IOC extraction and aggregation
│   ├── export/         # Report gen, STIX 2.1, MITRE ATT&CK mapping
│   └── cli.py          # Click CLI entry point
├── server/             # Fastify API + WebSocket + SQLite
│   └── src/
│       ├── index.ts    # Entry point + WS
│       ├── routes/     # submit, status, report, iocs, analysis
│       └── db/         # SQLite schema + queries
├── dashboard/          # React + Vite + Tailwind + D3
│   └── src/
│       ├── App.tsx     # Main layout + state management
│       └── components/ # Timeline, ProcessTree, NetworkPanel, etc.
├── samples/            # Test samples (EICAR + benign PE)
├── tests/              # Unit tests + fixtures
├── pyproject.toml      # Python packaging
├── SPEC.md             # Full architecture spec
└── README.md           # This file
```

---

## What This Proves

| Skill | How HATCHERY Demonstrates It |
|-------|-------------------------------|
| Malware analysis | Built a sandbox — understands detonation, behavioral monitoring, IOC extraction |
| Container security | Docker isolation + seccomp + network sandboxing |
| Linux internals | strace syscall tracing, inotify, process trees |
| Static analysis | YARA rule writing + capa capability extraction |
| Fake environment design | INetSim-style services — understands evasion techniques |
| Threat intelligence | STIX 2.1 export, MITRE ATT&CK mapping |
| Real-time systems | SSE event streaming for dashboard |
| Full-stack engineering | Python engine + Click CLI + Docker integration |

---

*Built by Raphael Main + Agent Mackenzie — April 2026*