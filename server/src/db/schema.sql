-- SQLite schema for HATCHERY analysis tasks and results

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    md5 TEXT,
    sha1 TEXT,
    sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, running, completed, failed
    static_done INTEGER NOT NULL DEFAULT 0,
    sandbox_done INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    error_message TEXT,
    queue_job_id TEXT,         -- the durable job this task was queued as (D27)
    sample_store_ref TEXT      -- the store address of a stream-supplied sample (D42);
                               -- a path-supplied task keeps NULL and a real file_path
);

CREATE TABLE IF NOT EXISTS static_results (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    hashes_json TEXT,          -- { md5, sha1, sha256, ssdeep, file_size }
    strings_json TEXT,         -- { urls, ips, domains, emails, registry_keys, all_strings_count }
    pe_json TEXT,              -- PE analysis results
    elf_json TEXT,             -- ELF analysis results
    yara_json TEXT,            -- YARA match results
    capa_json TEXT,            -- capa capability results
    packer_json TEXT,          -- packer detection results
    delivery_json TEXT,        -- delivery-format intake: container, children, unsupported
    emulation_json TEXT,       -- Windows PE emulation: config, snapshots, capa_dynamic
    triage_json TEXT,          -- advisory local-LLM triage: verdict, grounded findings
    ioc_json TEXT,             -- extracted IOCs
    mitre_json TEXT,           -- MITRE ATT&CK mapping
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sandbox_results (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    container_id TEXT,
    status TEXT,               -- completed, timeout, error, crashed
    exit_code INTEGER,
    duration_seconds REAL,
    strace_log_path TEXT,
    tcpdump_pcap_path TEXT,
    inotify_log_path TEXT,
    container_logs TEXT,
    artifacts_path TEXT,
    error_message TEXT,
    evasion_json TEXT,         -- scored evasion assessment from the engine
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS behavioral_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    timestamp TEXT NOT NULL,
    pid INTEGER,
    syscall_name TEXT,
    category TEXT,             -- file, network, process, memory, system
    severity TEXT,             -- info, low, medium, high, critical
    args TEXT,                 -- JSON-encoded syscall arguments
    return_value TEXT,
    raw_line TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_task ON behavioral_events(task_id);
CREATE INDEX IF NOT EXISTS idx_events_category ON behavioral_events(task_id, category);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    ioc_type TEXT NOT NULL,    -- ip, domain, url, email, hash, registry_key, file_path, mutex
    value TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    context TEXT,              -- where was this IOC found
    source TEXT,               -- strings, yara, capa, sandbox_network, sandbox_file, etc.
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_iocs_task ON iocs(task_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);

-- Access audit log (D25). Every API request the server answers is recorded here:
-- who (actor + role), what (method + path), and the outcome (status). No token, no
-- sample bytes and no request body is ever stored.
--
-- D30 adds an append-only hash chain: `prev_hash` is the previous row's
-- `entry_hash` (or the documented genesis constant for the first chained row) and
-- `entry_hash` is SHA-256 over a canonical encoding of the row's stored fields.
-- D31 adds `key_id`/`entry_mac`: an HMAC-SHA-256 over the same canonical form,
-- keyed by the local audit key ring, so recomputing the digests is not enough to
-- forge the log. All four are nullable because rows written before their migration
-- are left untouched: they were not tamper-evident then and are not claimed to be
-- now (verification reports their coverage honestly).
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL DEFAULT 'anonymous',
    role TEXT NOT NULL DEFAULT 'anonymous',
    authenticated INTEGER NOT NULL DEFAULT 0,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER,
    action TEXT,               -- auth.denied | request.forbidden | request.allowed
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    prev_hash TEXT,            -- previous entry_hash, or the genesis constant (D30)
    entry_hash TEXT,           -- sha256 of this row's canonical encoding (D30)
    key_id TEXT,               -- audit key id that produced entry_mac (D31)
    entry_mac TEXT             -- hmac-sha256 of the same canonical encoding (D31)
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

-- Audit-chain bookkeeping (D30). One row per key. `legacy_*` is written once, at
-- the migration that adds the chain, and records how many pre-chain rows existed
-- so their later deletion is visible; `head_*`/`chained_row_count` track the live
-- head so truncation of the tail is detectable too.
CREATE TABLE IF NOT EXISTS audit_chain_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- API tokens (D30). A credential's lifecycle: an id, a role, a non-secret prefix,
-- a one-way hash of the secret, creation/expiry times and a revocation stamp.
-- There is deliberately no column that can hold the raw token: `secret_hash` is
-- sha256(domain || token) and the token itself is shown once, by the CLI, at
-- creation. A row's id or prefix is never sufficient to authenticate.
CREATE TABLE IF NOT EXISTS api_tokens (
    id TEXT PRIMARY KEY,               -- htk_<16 hex>; the token's first segment
    name TEXT,                          -- operator label, never a secret
    role TEXT NOT NULL,                 -- admin | viewer
    prefix TEXT NOT NULL,              -- non-secret identifying prefix for listings
    secret_hash TEXT NOT NULL UNIQUE,  -- sha256(domain || token), hex
    created_at TEXT NOT NULL,
    expires_at TEXT,                   -- ISO-8601 UTC; NULL means no expiry
    revoked_at TEXT,                   -- ISO-8601 UTC; NULL means live
    retired_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_role ON api_tokens(role);