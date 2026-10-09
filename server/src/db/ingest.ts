/**
 * Ingest an analysis bundle into SQLite.
 *
 * This module is the bridge that did not exist. The Python engine wrote
 * `analysis.json` and `events.jsonl` to disk; the API read four SQLite tables
 * that nothing ever wrote to. The result was a working analysis behind a
 * permanently empty dashboard.
 *
 * Contract: the Python engine is the only producer of analysis data. The API
 * is the only producer of rows. Every table has exactly one writer.
 */

import type Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

export interface IngestResult {
  ok: boolean;
  events: number;
  iocs: number;
  error?: string;
}

interface BundleEvent {
  timestamp?: string;
  pid?: number;
  syscall_name?: string;
  category?: string;
  severity?: string;
  args?: string;
  return_value?: string;
  raw_line?: string;
  source?: string;
}

interface AnalysisBundle {
  task_id?: string;
  sample?: Record<string, unknown>;
  isolation?: Record<string, unknown> | null;
  static?: Record<string, unknown>;
  sandbox?: Record<string, unknown> | null;
  iocs?: Array<Record<string, unknown>>;
  mitre?: Record<string, unknown>;
  evasion?: Record<string, unknown> | null;
  limitations?: string[];
  errors?: string[];
  summary?: Record<string, unknown>;
}

/** Read events.jsonl, skipping any malformed line rather than failing the ingest. */
export function readEvents(eventsPath: string): BundleEvent[] {
  if (!fs.existsSync(eventsPath)) return [];
  const rows: BundleEvent[] = [];
  for (const line of fs.readFileSync(eventsPath, 'utf-8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed) as BundleEvent);
    } catch {
      // A partial trailing line is expected if the writer was interrupted.
    }
  }
  return rows;
}

/**
 * Ingest `results/<taskId>/bundle/{analysis.json,events.jsonl}`.
 *
 * Idempotent: re-ingesting the same task replaces that task's rows instead of
 * duplicating them, so a retry cannot double-count events.
 */
export function ingestBundle(db: Database.Database, taskId: string, resultsDir: string): IngestResult {
  const bundleDir = path.join(resultsDir, 'bundle');
  const analysisPath = path.join(bundleDir, 'analysis.json');

  if (!fs.existsSync(analysisPath)) {
    return {
      ok: false,
      events: 0,
      iocs: 0,
      error: `No analysis bundle at ${analysisPath}`,
    };
  }

  let bundle: AnalysisBundle;
  try {
    bundle = JSON.parse(fs.readFileSync(analysisPath, 'utf-8')) as AnalysisBundle;
  } catch (e) {
    return { ok: false, events: 0, iocs: 0, error: `Malformed analysis.json: ${String(e)}` };
  }

  const events = readEvents(path.join(bundleDir, 'events.jsonl'));
  const sample = (bundle.sample ?? {}) as Record<string, unknown>;
  const sandbox = (bundle.sandbox ?? null) as Record<string, unknown> | null;
  const isolation = (bundle.isolation ?? null) as Record<string, unknown> | null;
  const iocs = (bundle.iocs ?? []) as Array<Record<string, unknown>>;
  const evasion = (bundle.evasion ?? null) as Record<string, unknown> | null;

  const str = (v: unknown): string | null => (v === undefined || v === null ? null : String(v));
  const num = (v: unknown): number => (typeof v === 'number' ? v : 0);

  const transact = db.transaction(() => {
    // --- task row: hashes and completion state come from the bundle now ----
    db.prepare(
      `UPDATE tasks SET
         md5 = COALESCE(?, md5),
         sha1 = COALESCE(?, sha1),
         sha256 = COALESCE(?, sha256),
         static_done = 1,
         sandbox_done = ?,
         status = 'completed',
         completed_at = datetime('now'),
         updated_at = datetime('now')
       WHERE task_id = ?`,
    ).run(
      str(sample.md5),
      str(sample.sha1),
      str(sample.sha256),
      sandbox ? 1 : 0,
      taskId,
    );

    // --- static results -----------------------------------------------------
    const staticData = (bundle.static ?? {}) as Record<string, unknown>;
    const mitre = (bundle.mitre ?? {}) as Record<string, unknown>;
    db.prepare('DELETE FROM static_results WHERE task_id = ?').run(taskId);
    db.prepare(
      `INSERT INTO static_results
         (task_id, hashes_json, strings_json, pe_json, elf_json, yara_json,
          capa_json, packer_json, delivery_json, ioc_json, mitre_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      taskId,
      JSON.stringify({
        md5: str(sample.md5),
        sha1: str(sample.sha1),
        sha256: str(sample.sha256),
        file_size: num(sample.file_size),
      }),
      JSON.stringify(staticData.strings ?? null),
      staticData.pe ? JSON.stringify(staticData.pe) : null,
      staticData.elf ? JSON.stringify(staticData.elf) : null,
      JSON.stringify(staticData.yara ?? null),
      JSON.stringify(staticData.capa ?? null),
      JSON.stringify(staticData.packer ?? null),
      staticData.delivery ? JSON.stringify(staticData.delivery) : null,
      JSON.stringify(iocs),
      JSON.stringify(mitre),
    );

    // --- sandbox results, including the honest limitations block -----------
    db.prepare('DELETE FROM sandbox_results WHERE task_id = ?').run(taskId);
    if (sandbox) {
      const artifacts = (sandbox.artifacts ?? {}) as Record<string, unknown>;
      const found = (artifacts.found ?? {}) as Record<string, string>;
      db.prepare(
        `INSERT INTO sandbox_results
           (task_id, container_id, status, exit_code, duration_seconds,
            strace_log_path, tcpdump_pcap_path, inotify_log_path,
            container_logs, artifacts_path, error_message, evasion_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        taskId,
        str(sandbox.container_id),
        str(sandbox.status),
        typeof sandbox.exit_code === 'number' ? sandbox.exit_code : null,
        num(sandbox.duration_seconds),
        str(found.strace_log ?? sandbox.strace_log),
        str(found.pcap ?? sandbox.tcpdump_pcap),
        str(found.inotify_log ?? sandbox.inotify_log),
        str(sandbox.container_logs),
        str(artifacts.root),
        str(sandbox.error),
        evasion ? JSON.stringify(evasion) : null,
      );
    }

    // --- IOCs --------------------------------------------------------------
    db.prepare('DELETE FROM iocs WHERE task_id = ?').run(taskId);
    const insertIoc = db.prepare(
      `INSERT INTO iocs (task_id, ioc_type, value, severity, context, source)
       VALUES (?, ?, ?, ?, ?, ?)`,
    );
    let iocCount = 0;
    for (const ioc of iocs) {
      const value = str(ioc.value);
      const iocType = str(ioc.type ?? ioc.ioc_type);
      if (!value || !iocType) continue;
      insertIoc.run(
        taskId,
        iocType,
        value,
        str(ioc.severity) ?? 'info',
        str(ioc.context),
        str(ioc.source),
      );
      iocCount += 1;
    }

    // --- behavioural events -------------------------------------------------
    db.prepare('DELETE FROM behavioral_events WHERE task_id = ?').run(taskId);
    const insertEvent = db.prepare(
      `INSERT INTO behavioral_events
         (task_id, timestamp, pid, syscall_name, category, severity,
          args, return_value, raw_line)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    let eventCount = 0;
    for (const event of events) {
      insertEvent.run(
        taskId,
        str(event.timestamp) ?? '',
        typeof event.pid === 'number' ? event.pid : 0,
        str(event.syscall_name) ?? '',
        str(event.category) ?? 'unknown',
        str(event.severity) ?? 'info',
        str(event.args) ?? '{}',
        str(event.return_value) ?? '',
        str(event.raw_line) ?? '',
      );
      eventCount += 1;
    }

    // Store the limitations alongside the run so the operator can always see
    // what the run did not establish, without re-reading the bundle.
    const limitations = bundle.limitations ?? [];
    if (limitations.length > 0 && sandbox) {
      const note = `Limitations: ${limitations.length} item(s). ${limitations[0]}`;
      db.prepare(
        'UPDATE sandbox_results SET error_message = COALESCE(error_message, ?) WHERE task_id = ?',
      ).run(note, taskId);
    }

    if (isolation && isolation.is_security_boundary === false) {
      db.prepare(
        'UPDATE sandbox_results SET status = ? WHERE task_id = ?',
      ).run(`${str(sandbox?.status) ?? 'completed'} (no isolation boundary)`, taskId);
    }
  });

  try {
    transact();
  } catch (e) {
    return { ok: false, events: 0, iocs: 0, error: `Ingest failed: ${String(e)}` };
  }

  return { ok: true, events: events.length, iocs: iocs.length };
}
