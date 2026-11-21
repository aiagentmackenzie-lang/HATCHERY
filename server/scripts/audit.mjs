#!/usr/bin/env node
/**
 * Audit chain operator CLI (D31, extended by D32).
 *
 *   npm run audit -- head [--json]                 # the current head, to record elsewhere
 *   npm run audit -- status [policy] [--json]      # rows, sizes, growth, what a run would move
 *   npm run audit -- compact [policy] [--apply]    # archive a segment and hand the chain off
 *   npm run audit -- archives [--json]             # every recorded archive segment
 *   npm run audit -- verify [--limit N] [--after ID] [--expect-head <id>:<hash>]
 *                           [--no-archive] [--json]
 *   npm run audit -- verify --archive PATH [--keyring PATH | --key-file PATH] [--json]
 *   npm run audit -- key status [--json]
 *   npm run audit -- key rotate [--json]
 *
 * Policy (only `compact --apply` ever removes a row; the server never does):
 *   --older-than 30d     archive rows older than the duration (s/m/h/d/w or seconds)
 *   --max-rows N         archive everything beyond the newest N chained rows
 *   --keep-rows N        always keep the newest N live (default 1 — the anchor)
 *   --max-segment-rows N at most N rows per run (default 50000)
 *   --gzip               compress the archive (Node's zlib)
 *   --out DIR            where to write the archive (default: <db dir>/audit-archives)
 *
 * Exit codes: 0 success and verification passed; 1 verification failed or the
 * operation failed; 2 usage error. No key material is ever printed.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');

function usage() {
  process.stdout.write(
    [
      'Usage: npm run audit -- <command> [options]',
      '',
      'Commands:',
      '  head [--json]                       Print the current chain head (id:hash) to record elsewhere',
      '  status [policy] [--json]            Rows, ids, dates, database size, growth warning, what a run would move',
      '  compact [policy] [--apply] [--gzip] [--out DIR] [--json]',
      '                                      Archive a segment and hand the chain off (dry run without --apply)',
      '  archives [--json]                   List the recorded archive segments',
      '  verify [--limit N] [--after ID] [--expect-head <id>:<hash>] [--no-archive] [--json]',
      '  verify --archive PATH [--keyring PATH | --key-file PATH] [--json]',
      '                                      Verify an archive offline (no database needed)',
      '  key status [--json]',
      '  key rotate [--json]',
      '',
      'Policy (retention is OFF by default; only `compact --apply` removes rows):',
      '  --older-than 30d        archive rows older than the duration (s/m/h/d/w or seconds)',
      '  --max-rows N            archive everything beyond the newest N chained rows',
      '  --keep-rows N           always keep the newest N chained rows live (default 1)',
      '  --max-segment-rows N    at most N rows per run (default 50000)',
      '',
      'Growth warning thresholds (read-only; they never delete anything):',
      '  HATCHERY_AUDIT_WARN_ROWS (default 500000) · HATCHERY_AUDIT_WARN_BYTES (default 256 MiB)',
      '',
      'Every command accepts --db PATH (default: $HATCHERY_DB_PATH or data/hatchery.db).',
      'Exit codes: 0 ok, 1 verification or operation failed, 2 usage error.',
      'Key material is never printed; only key ids. Archives are 0600 and contain exactly',
      'what audit_log stores — never a token, header, body or sample byte.',
      '',
    ].join('\n'),
  );
}

function fail(message, code = 2) {
  process.stderr.write(`audit: ${message}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--json') args.json = true;
    else if (item === '--apply') args.apply = true;
    else if (item === '--gzip') args.gzip = true;
    else if (item === '--no-archive') args['no-archive'] = true;
    else if (item === '--help' || item === '-h') args.help = true;
    else if (item.startsWith('--')) {
      const key = item.slice(2);
      const value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) fail(`--${key} needs a value`);
      args[key] = value;
      i += 1;
    } else {
      args._.push(item);
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (args.help || args._.length === 0) {
  usage();
  process.exit(args.help ? 0 : 2);
}
if (args.db) process.env.HATCHERY_DB_PATH = path.resolve(String(args.db));

let auditMod;
let keyMod;
let archiveMod;
let compactionMod;
try {
  auditMod = await import(pathToFileURL(path.join(serverRoot, 'dist', 'security', 'audit.js')).href);
  keyMod = await import(pathToFileURL(path.join(serverRoot, 'dist', 'security', 'auditKey.js')).href);
  archiveMod = await import(
    pathToFileURL(path.join(serverRoot, 'dist', 'security', 'auditArchive.js')).href
  );
  compactionMod = await import(
    pathToFileURL(path.join(serverRoot, 'dist', 'security', 'auditCompaction.js')).href
  );
} catch (error) {
  fail(`cannot load the built server (run npm run build): ${error?.message ?? error}`, 2);
}

function emitJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

const command = args._[0];
const sub = args._[1];

// ---------------------------------------------------------------------------
// Offline archive verification: no database, and no key material in the output.
// ---------------------------------------------------------------------------
if (command === 'verify' && args.archive) {
  const archivePath = path.resolve(String(args.archive));
  let ring = null;
  try {
    if (args.keyfile || args['key-file']) {
      const material = keyMod.readKeyFile(path.resolve(String(args.keyfile ?? args['key-file'])));
      ring = {
        version: 1,
        active: keyMod.keyIdOf(material),
        keys: [{ id: keyMod.keyIdOf(material), material, created_at: '' }],
        source: 'file',
        path: path.resolve(String(args.keyfile ?? args['key-file'])),
        env_ignored: false,
      };
    } else if (args.keyring) {
      ring = keyMod.readRingFile(path.resolve(String(args.keyring)));
      if (!ring) fail(`no key ring at ${args.keyring}`, 2);
    } else {
      // `HATCHERY_AUDIT_KEY`/`_FILE`, or a ring beside the archive — then one directory
      // up, which is where a default installation keeps it (`<db dir>/.audit-keyring`,
      // with archives in `<db dir>/audit-archives/`). Never generate one offline.
      const directory = path.dirname(archivePath);
      for (const candidate of [directory, path.dirname(directory), process.cwd()]) {
        ring = keyMod.resolveAuditKeyring(path.join(candidate, 'offline'), process.env, {
          generate: false,
        });
        if (ring) break;
      }
    }
  } catch (error) {
    fail(`cannot resolve the audit key: ${error instanceof Error ? error.message : error}`, 1);
  }

  const manifestFile = archiveMod.manifestPathFor(archivePath);
  const result = archiveMod.verifyArchive({
    archiveFile: archivePath,
    manifestFile,
    keyring: ring,
  });
  if (args.json) {
    emitJson({ ...result, archive: archivePath, manifest: manifestFile });
  } else {
    process.stdout.write(
      [
        `ok:         ${result.ok}`,
        `archive:    ${archivePath}`,
        `manifest:   ${manifestFile}`,
        `manifest#:  ${result.manifest_sha256 ?? 'none'}`,
        `archive#:   ${result.archive_sha256 ?? 'none'}`,
        `rows:       ${result.rows}`,
        `tail:       ${result.tail ? `${result.tail.id}:${result.tail.entry_hash}` : 'none'}`,
        `first prev: ${result.first_prev_hash ?? 'none'}`,
        `keys:       ${ring ? ring.active : 'none configured'}`,
        result.first_broken
          ? `BREAK:      row ${result.first_broken.id ?? '?'} ${result.first_broken.classification}: ${result.first_broken.detail}`
          : 'BREAK:      none',
        result.ok
          ? '\nThe archive is internally consistent. Its tail is\n' +
            `  ${result.tail ? `${result.tail.id}:${result.tail.entry_hash}` : 'none'}\n` +
            'and a live chain whose first prev_hash equals that value continues it.\n' +
            `Its first row links to ${result.first_prev_hash ?? 'none'} — the genesis value for\n` +
            'the first segment, or the previous segment\'s tail when splicing archives.'
          : '',
        '',
      ]
        .filter(Boolean)
        .join('\n'),
    );
  }
  process.exit(result.ok && result.checked ? 0 : 1);
}

let mod;
try {
  mod = await import(pathToFileURL(path.join(serverRoot, 'dist', 'db', 'index.js')).href);
} catch (error) {
  fail(`cannot load the built server (run npm run build): ${error?.message ?? error}`, 2);
}

let db;
try {
  db = mod.getDb();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error), 1);
}

const dbPath = mod.databasePath();

function audit(action, detail) {
  auditMod.recordAudit(db, {
    actor: 'operator:cli',
    role: 'admin',
    authenticated: false,
    method: 'CLI',
    path: `audit.${action}`,
    statusCode: null,
    action,
    detail,
  });
}

function ringOrFail() {
  const ring = auditMod.auditKeyring();
  if (!ring) fail('no audit key ring is configured for this database', 1);
  return ring;
}

function describeKey(ring) {
  return {
    active: ring.active,
    source: ring.source,
    path: ring.path,
    env_ignored: Boolean(ring.env_ignored),
    keys: ring.keys.map((key) => ({
      id: key.id,
      created_at: key.created_at,
      active: key.id === ring.active,
    })),
  };
}

function policyFromArgs() {
  try {
    return compactionMod.resolveRetentionPolicy({
      olderThan: args['older-than'],
      maxRows: args['max-rows'],
      keepRows: args['keep-rows'],
      maxSegmentRows: args['max-segment-rows'],
    });
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error), 2);
  }
}

try {
  if (command === 'head') {
    const meta = auditMod.auditChainMeta(db);
    const id = meta.head_id ? Number(meta.head_id) : null;
    const hash = meta.head_hash ?? null;
    const ring = auditMod.auditKeyring();
    const payload = {
      head: id !== null && hash ? { id, hash } : null,
      anchor: id !== null && hash ? `${id}:${hash}` : null,
      chained_rows: Number(meta.chained_row_count ?? '0'),
      chained_rows_total: Number(meta.chained_rows_total ?? meta.chained_row_count ?? '0'),
      archived_rows: Number(meta.archived_row_total ?? '0'),
      archive_segments: meta.archive_segments ? JSON.parse(meta.archive_segments).length : 0,
      key_id: ring ? ring.active : null,
      note: 'record this outside the database; verify --expect-head enforces it',
    };
    if (args.json) emitJson(payload);
    else if (!payload.anchor) process.stdout.write('The chain is empty (no chained rows yet).\n');
    else {
      process.stdout.write(
        `${payload.anchor}\n` +
          `rows: ${payload.chained_rows} live, ${payload.archived_rows} archived in ` +
          `${payload.archive_segments} segment(s)  key: ${payload.key_id ?? 'none (unkeyed)'}\n` +
          'Record this somewhere the database writer cannot rewrite (a log collector, a ticket).\n',
      );
    }
  } else if (command === 'status') {
    const policy = policyFromArgs();
    const report = compactionMod.auditStatus(db, dbPath, policy, {
      appendFailures: auditMod.auditAppendFailureTotals(),
    });
    if (args.json) emitJson(report);
    else {
      const line = (label, value) => `${label.padEnd(14)}${value}`;
      process.stdout.write(
        [
          line('database:', `${report.database.path} (${report.database.bytes} bytes` +
            `${report.database.wal_bytes ? `, of which ${report.database.wal_bytes} WAL` : ''})`),
          line('rows:', `${report.rows.total} total, ${report.rows.chained} chained, ` +
            `${report.rows.legacy} pre-chain`),
          line('oldest:', report.oldest ? `${report.oldest.id} at ${report.oldest.created_at}` : 'none'),
          line('newest:', report.newest ? `${report.newest.id} at ${report.newest.created_at}` : 'none'),
          line('archived:', `${report.archived.rows} row(s) in ${report.archived.segments} segment(s)` +
            (report.archived.last_manifest ? ` · last ${report.archived.last_manifest}` : '') +
            (report.archived.error ? ` · ERROR ${report.archived.error}` : '')),
          line('policy:', report.policy_off
            ? 'OFF — pass --older-than and/or --max-rows; nothing is ever removed by the API'
            : JSON.stringify(report.policy)),
          line('would move:', report.policy_off
            ? 'nothing (policy off)'
            : `${report.would_archive.rows} of ${report.would_archive.eligible_rows} eligible ` +
              `row(s)${report.would_archive.first_id !== null
                ? `, ids ${report.would_archive.first_id}-${report.would_archive.last_id}`
                : ''}` +
              (report.would_archive.remaining_after
                ? `; ${report.would_archive.remaining_after} more after this run`
                : '')),
          line('anchor row:', report.would_archive.anchor_row
            ? `${report.would_archive.anchor_row.id} (stays live; the next row links through it)`
            : 'none'),
          line('growth:', `${report.growth.over ? 'OVER THRESHOLD' : 'ok'} — ` +
            `${report.growth.rows} rows, ${report.growth.bytes} bytes; warn at ` +
            `${report.growth.warn_rows} rows / ${report.growth.warn_bytes} bytes`),
          line('append fails:', `${report.append_failures.since_start} since start, ` +
            `${report.append_failures.total} total` +
            (report.append_failures.persisted ? '' : ' (NOT PERSISTED — see the server log)')),
          report.would_archive.clamp !== 'none' ? line('note:', report.would_archive.clamp) : '',
          '',
          'Retention is off by default and is applied only by `npm run audit -- compact --apply`.',
          'The API never deletes an audit row: no timer, no background task, no request path.',
          '',
        ]
          .filter((entry) => entry !== '')
          .join('\n'),
      );
    }
  } else if (command === 'compact') {
    const policy = policyFromArgs();
    if (compactionMod.policyIsOff(policy)) {
      fail(
        'retention is off by default: pass --older-than <duration> and/or --max-rows N ' +
          '(add --apply to actually archive and delete; without it this is a dry run)',
        2,
      );
    }
    let report;
    try {
      report = compactionMod.compactAudit(db, {
        dbPath,
        policy,
        apply: Boolean(args.apply),
        gzip: Boolean(args.gzip),
        outDir: args.out ? path.resolve(String(args.out)) : undefined,
      });
    } catch (error) {
      fail(error instanceof Error ? error.message : String(error), 1);
    }
    if (args.json) emitJson(report);
    else if (!report.applied && report.reason !== 'dry-run') {
      process.stdout.write(`Nothing to archive: ${report.reason}.\n`);
    } else if (!report.applied) {
      process.stdout.write(
        [
          'DRY RUN — nothing was written and no row was deleted.',
          `would archive: ${report.window.rows} row(s), ids ${report.window.first_id}-${report.window.last_id} ` +
            `(${report.window.from} .. ${report.window.to})`,
          `archive:       ${path.join(report.archive_dir, `<window>.jsonl${args.gzip ? '.gz' : ''}`)}`,
          `tail:          ${report.tail.id}:${report.tail.entry_hash}`,
          `join:          the live row ${report.join.anchor_id} links to that tail (proven)`,
          report.remaining_eligible
            ? `remaining:     ${report.remaining_eligible} row(s) still eligible after this run`
            : 'remaining:     none',
          '',
          'Re-run with --apply to archive the segment and delete exactly these rows.',
          '',
        ].join('\n'),
      );
    } else {
      process.stdout.write(
        [
          `Archived ${report.window.rows} row(s), ids ${report.window.first_id}-${report.window.last_id}.`,
          `archive:   ${report.archive.path} (${report.archive.size} bytes, sha256 ${report.archive.sha256})`,
          `manifest:  ${report.manifest.path} (last written, sha256 ${report.manifest.sha256})`,
          `tail:      ${report.tail.id}:${report.tail.entry_hash}`,
          `join:      proven — the live chain resumes from that hash`,
          report.resumed ? 'resumed:   an interrupted run was completed; nothing was archived twice' : '',
          report.remaining_eligible
            ? `remaining: ${report.remaining_eligible} row(s) still eligible; run compact again`
            : 'remaining: none',
          '',
          'Verify with `npm run audit -- verify` (reads the archive) or offline with',
          '`npm run audit -- verify --archive ' + report.archive.path + '`.',
          '',
        ]
          .filter(Boolean)
          .join('\n'),
      );
    }
    process.exit(0);
  } else if (command === 'archives') {
    const read = archiveMod.readArchiveSegments(db);
    if (args.json) emitJson(read);
    else if (read.error) fail(read.error, 1);
    else if (read.segments.length === 0) process.stdout.write('No archived segments.\n');
    else {
      process.stdout.write(
        read.segments
          .map(
            (segment) =>
              `${String(segment.sequence).padStart(3)}  ids ${segment.window.first_id}-` +
              `${segment.window.last_id}  ${String(segment.window.rows).padStart(7)} rows  ` +
              `${segment.archive.path}\n     manifest ${segment.manifest.path} ` +
              `sha256:${segment.manifest.sha256}  tail ${segment.tail.id}:${segment.tail.entry_hash}`,
          )
          .join('\n') + '\n',
      );
    }
  } else if (command === 'verify') {
    const limit = args.limit === undefined ? 50000 : Number.parseInt(String(args.limit), 10);
    if (!Number.isFinite(limit) || limit < 1) fail('--limit must be a positive integer');
    const after = args.after === undefined ? 0 : Number.parseInt(String(args.after), 10);
    if (!Number.isFinite(after) || after < 0) fail('--after must be a non-negative integer');

    let expectHead = null;
    if (args['expect-head'] !== undefined) {
      const match = /^(\d+):([0-9a-f]{64})$/.exec(String(args['expect-head']));
      if (!match) fail('--expect-head must be "<id>:<64 hex chars>" (see: npm run audit -- head)');
      expectHead = { id: Number(match[1]), hash: match[2] };
    }

    const result = auditMod.verifyAuditChain(db, {
      limitRows: limit,
      afterId: after,
      expectHead,
      dbPath,
      archiveMode: args['no-archive'] ? 'presence' : 'full',
    });
    const anchorUnconfirmed = Boolean(expectHead) && result.anchor.matches !== true;
    if (args.json) emitJson(result);
    else {
      process.stdout.write(
        [
          `ok:         ${result.ok}`,
          `assurance:  ${result.assurance} (mac rows: ${result.coverage.mac_rows}, ` +
            `unkeyed: ${result.coverage.unkeyed_rows}, pre-chain: ${result.coverage.legacy_rows})`,
          `rows:       ${result.rows_checked} live` +
            `${result.archive.rows ? `, ${result.archive.rows} archived` : ''}` +
            `${result.complete ? '' : ` (more after ${result.next_after_id})`}`,
          `head:       ${result.head.id ?? 'none'}:${result.head.hash ?? 'none'}` +
            ` (matches stored head: ${result.head.matches_meta})`,
          `archive:    ${result.archive.recorded
            ? `${result.archive.segments} segment(s) ` +
              `${result.archive.checked ? 'verified' : `PRESENT BUT NOT READ (${result.archive.reason ?? 'presence mode'})`}` +
              ` · manifest ${result.archive.manifest_sha256 ?? 'none'}` +
              ` · join ${result.archive.join}`
            : 'none'}`,
          `anchor:     ${result.anchor.expected
            ? `${result.anchor.expected.id}:${result.anchor.expected.hash} -> ` +
              `${result.anchor.matches === null ? 'UNCONFIRMED' : result.anchor.matches}` +
              `${result.anchor.found_in
                ? ` (in ${result.anchor.found_in}` +
                  `${result.anchor.head_at_anchor === false ? '; not the current head' : ''})`
                : ''}`
            : 'not supplied'}`,
          `growth:     ${result.growth ? (result.growth.over ? 'OVER THRESHOLD' : 'ok') : 'not measured'}` +
            `${result.growth ? ` — ${result.growth.rows} rows, ${result.growth.bytes} bytes` : ''}`,
          result.first_broken
            ? `BREAK:      row ${result.first_broken.id ?? '?'} ${result.first_broken.classification}: ${result.first_broken.detail}`
            : 'BREAK:      none',
          result.append_failures_since_start || !result.append_failures_persisted
            ? `WARNING:    ${result.append_failures_since_start} audit append(s) failed in this ` +
              `process, ${result.append_failures_total} total` +
              `${result.append_failures_persisted ? '' : ' (NOT PERSISTED — see the server log)'}`
            : 'WARNING:    no failed appends recorded',
          anchorUnconfirmed ? 'ANCHOR:     the supplied head could not be confirmed — this is not a pass' : '',
          '',
        ]
          .filter(Boolean)
          .join('\n'),
      );
    }
    process.exit(result.ok && !anchorUnconfirmed ? 0 : 1);
  } else if (command === 'key' && sub === 'status') {
    const ring = ringOrFail();
    const payload = { ...describeKey(ring), keys_in_use: [] };
    const used = db
      .prepare('SELECT key_id, COUNT(*) AS n FROM audit_log WHERE key_id IS NOT NULL GROUP BY key_id')
      .all();
    payload.keys_in_use = used;
    if (args.json) emitJson(payload);
    else {
      process.stdout.write(
        [
          `active key: ${ring.active} (${ring.source})`,
          `ring:       ${ring.path}`,
          `known keys: ${ring.keys.map((key) => key.id).join(', ')}`,
          `rows by key: ${used.map((row) => `${row.key_id}=${row.n}`).join(', ') || 'none'}`,
          ring.env_ignored
            ? 'HATCHERY_AUDIT_KEY is IGNORED: the key ring already exists and is authoritative.'
            : '',
          '',
        ]
          .filter(Boolean)
          .join('\n'),
      );
    }
  } else if (command === 'key' && sub === 'rotate') {
    const ring = ringOrFail();
    const next = keyMod.rotateAuditKey(ring);
    auditMod.configureAuditKeyring(next);
    audit('key-rotated', `audit key rotated: active ${next.active} (previous ${ring.active})`);
    const payload = describeKey(next);
    if (args.json) emitJson(payload);
    else {
      process.stdout.write(
        `Rotated. Active key ${next.active}; previous keys stay in the ring so history ` +
          `still verifies. New rows are MAC'd with the new key.\n`,
      );
    }
  } else {
    usage();
    process.exit(2);
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error), 1);
}
