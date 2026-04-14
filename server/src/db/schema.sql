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
    error_message TEXT
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