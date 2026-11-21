#!/usr/bin/env node
/**
 * Audit chain operator CLI (D31).
 *
 *   npm run audit -- head [--json]                 # the current head, to record elsewhere
 *   npm run audit -- verify [--limit N] [--expect-head <id>:<hash>] [--json]
 *   npm run audit -- key status [--json]
 *   npm run audit -- key rotate [--json]
 *
 * Why a head anchor matters: the keyed chain stops anyone without the key from
 * rewriting rows, but a deliberate truncation that also rewrites the stored head is
 * internally consistent — only a head recorded **outside** the database detects it.
 * `head` prints exactly that, and `verify --expect-head` enforces it.
 *
 * Exit codes: 0 success and verification passed; 1 verification failed or the
 * operation failed; 2 usage error. No key material is ever printed.
 */

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
      '  verify [--limit N] [--after ID] [--expect-head <id>:<hash>] [--json]',
      '  key status [--json]',
      '  key rotate [--json]',
      '',
      'Every command accepts --db PATH (default: $HATCHERY_DB_PATH or data/hatchery.db).',
      'Exit codes: 0 ok, 1 verification or operation failed, 2 usage error.',
      'Key material is never printed; only key ids.',
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

let mod;
let auditMod;
let keyMod;
try {
  mod = await import(pathToFileURL(path.join(serverRoot, 'dist', 'db', 'index.js')).href);
  auditMod = await import(pathToFileURL(path.join(serverRoot, 'dist', 'security', 'audit.js')).href);
  keyMod = await import(pathToFileURL(path.join(serverRoot, 'dist', 'security', 'auditKey.js')).href);
} catch (error) {
  fail(`cannot load the built server (run npm run build): ${error?.message ?? error}`, 2);
}

let db;
try {
  db = mod.getDb();
} catch (error) {
  fail(error instanceof Error ? error.message : String(error), 1);
}

function emitJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

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

const command = args._[0];
const sub = args._[1];

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
      key_id: ring ? ring.active : null,
      note: 'record this outside the database; verify --expect-head enforces it',
    };
    if (args.json) emitJson(payload);
    else if (!payload.anchor) process.stdout.write('The chain is empty (no chained rows yet).\n');
    else {
      process.stdout.write(
        `${payload.anchor}\n` +
          `rows: ${payload.chained_rows}  key: ${payload.key_id ?? 'none (unkeyed)'}\n` +
          'Record this somewhere the database writer cannot rewrite (a log collector, a ticket).\n',
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

    const result = auditMod.verifyAuditChain(db, { limitRows: limit, afterId: after, expectHead });
    if (args.json) emitJson(result);
    else {
      process.stdout.write(
        [
          `ok:         ${result.ok}`,
          `assurance:  ${result.assurance} (mac rows: ${result.coverage.mac_rows}, ` +
            `unkeyed: ${result.coverage.unkeyed_rows}, pre-chain: ${result.coverage.legacy_rows})`,
          `rows:       ${result.rows_checked}${result.complete ? '' : ` (more after ${result.next_after_id})`}`,
          `head:       ${result.head.id ?? 'none'}:${result.head.hash ?? 'none'}` +
            ` (matches stored head: ${result.head.matches_meta})`,
          `anchor:     ${result.anchor.expected ? `${result.anchor.expected.id}:${result.anchor.expected.hash} -> ${result.anchor.matches}` : 'not supplied'}`,
          result.first_broken
            ? `BREAK:      row ${result.first_broken.id ?? '?'} ${result.first_broken.classification}: ${result.first_broken.detail}`
            : 'BREAK:      none',
          result.append_failures_since_start
            ? `WARNING:    ${result.append_failures_since_start} audit append(s) failed in this process (see the server log)`
            : 'WARNING:    no failed appends in this process',
          '',
        ].join('\n'),
      );
    }
    process.exit(result.ok ? 0 : 1);
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
