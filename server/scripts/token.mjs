#!/usr/bin/env node
/**
 * Token lifecycle CLI (D30).
 *
 *   npm run token -- create --role viewer [--name "ci"] [--expires-in 30d] [--json]
 *   npm run token -- list [--json]
 *   npm run token -- retire TOKEN_ID [--reason "..."] [--json]
 *   npm run token -- expire TOKEN_ID [--in 0] [--at ISO8601] [--json]
 *
 * Why a local CLI rather than an HTTP endpoint for creation: the secret must never
 * cross the network, appear in a response, or be reachable by an admin who is
 * compromised over the wire. The CLI generates it here, prints it **once** to
 * stdout, and stores only `sha256(domain || token)` plus the non-secret id/prefix.
 * The server never sees the raw value, so it can never log or return it.
 *
 * Exit codes (stable, documented for scripts):
 *   0  success
 *   1  the operation failed (unknown token id, database error)
 *   2  usage error (bad flag, bad role, unparseable duration)
 *
 * It writes to the same SQLite database the API uses (`HATCHERY_DB_PATH`, or
 * `<repo>/data/hatchery.db`). WAL + a busy timeout mean the API can be running; a
 * change takes effect on the next request with no restart.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const distEntry = path.join(serverRoot, 'dist', 'db', 'index.js');

function usage() {
  process.stdout.write(
    [
      'Usage: npm run token -- <command> [options]',
      '',
      'Commands:',
      '  create --role admin|viewer [--name LABEL] [--expires-in 30d] [--expires-at ISO] [--json]',
      '  list [--json]',
      '  retire TOKEN_ID [--reason TEXT] [--json]',
      '  expire TOKEN_ID [--in 30d] [--at ISO] [--json]',
      '',
      'Every command accepts --db PATH (default: $HATCHERY_DB_PATH or data/hatchery.db).',
      'Exit codes: 0 success, 1 operation failed, 2 usage error.',
      'The raw token is printed once, by `create`, on stdout. It is never stored.',
      '',
    ].join('\n'),
  );
}

function fail(message, code = 2) {
  process.stderr.write(`token: ${message}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--json') args.json = true;
    else if (item === '--help' || item === '-h') args.help = true;
    else if (item === '--dry-run') args.dryRun = true;
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

/** `30d`, `12h`, `45m`, `90s`, `2w`, or a bare number of seconds. */
function parseDuration(raw) {
  const match = /^(\d+(?:\.\d+)?)([smhdw]?)$/.exec(String(raw).trim().toLowerCase());
  if (!match) return null;
  const amount = Number(match[1]);
  if (!Number.isFinite(amount) || amount < 0) return null;
  const unit = match[2] || 's';
  const ms = { s: 1000, m: 60000, h: 3600000, d: 86400000, w: 604800000 }[unit];
  return Math.round(amount * ms);
}

function parseExpiryValue(value) {
  if (value === undefined) return null;
  const duration = parseDuration(value);
  if (duration !== null) return new Date(Date.now() + duration).toISOString();
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) fail(`cannot parse --expires-at/--in value: ${value}`, 2);
  return new Date(parsed).toISOString();
}

function table(rows, columns) {
  const widths = columns.map((column) =>
    Math.max(column.header.length, ...rows.map((row) => String(row[column.key] ?? '').length)),
  );
  const line = (cells) => cells.map((cell, i) => String(cell).padEnd(widths[i])).join('  ');
  const out = [line(columns.map((column) => column.header))];
  for (const row of rows) out.push(line(columns.map((column) => row[column.key] ?? '')));
  return out.join('\n');
}

const args = parseArgs(process.argv.slice(2));
if (args.help || args._.length === 0) {
  usage();
  process.exit(args.help ? 0 : 2);
}

const command = args._[0];
if (!['create', 'list', 'retire', 'expire', 'help'].includes(command)) {
  fail(`unknown command: ${command}`);
}
if (command === 'help') {
  usage();
  process.exit(0);
}

if (args.db) process.env.HATCHERY_DB_PATH = path.resolve(String(args.db));

if (!fs.existsSync(distEntry)) {
  fail('the server is not built; run `npm run build` in server/ first', 2);
}

let mod;
let tokensMod;
let auditMod;
try {
  mod = await import(pathToFileURL(distEntry).href);
  tokensMod = await import(
    pathToFileURL(path.join(serverRoot, 'dist', 'security', 'tokens.js')).href,
  );
  auditMod = await import(
    pathToFileURL(path.join(serverRoot, 'dist', 'security', 'audit.js')).href,
  );
} catch (error) {
  fail(`cannot load the built server: ${error instanceof Error ? error.message : error}`, 2);
}

const { getDb } = mod;
const db = getDb();

/** Every lifecycle action is audited, with the token id and never the secret. */
function audit(action, detail) {
  auditMod.recordAudit(db, {
    actor: 'operator:cli',
    role: 'admin',
    authenticated: false,
    method: 'CLI',
    path: `token.${action}`,
    statusCode: null,
    action,
    detail,
  });
}

function emitJson(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

try {
  if (command === 'create') {
    const role = args.role;
    if (role !== 'admin' && role !== 'viewer') {
      fail('--role must be "admin" or "viewer" (required)', 2);
    }
    const expiresAt = parseExpiryValue(args['expires-in'] ?? args['expires-at']);
    const created = tokensMod.createToken(db, {
      role,
      name: args.name ? String(args.name).slice(0, 120) : null,
      expiresAt,
    });
    audit(
      'token.created',
      `created token ${created.id} role=${created.role} ` +
        `expires=${created.expires_at ?? 'never'} name=${created.name ?? '-'}`,
    );

    if (args.json) {
      emitJson({
        id: created.id,
        role: created.role,
        prefix: created.prefix,
        name: created.name,
        created_at: created.created_at,
        expires_at: created.expires_at,
        state: 'live',
        token: created.token,
        notice: 'the token is shown once; only its SHA-256 is stored',
      });
    } else {
      process.stdout.write(
        [
          `Created token ${created.id}`,
          `  role:     ${created.role}`,
          `  name:     ${created.name ?? '-'}`,
          `  created:  ${created.created_at}`,
          `  expires:  ${created.expires_at ?? 'never'}`,
          '',
          `  ${created.token}`,
          '',
          'This value is shown ONCE. HATCHERY stores only its SHA-256, so it cannot',
          'be recovered: if it is lost, retire it and create another.',
          '',
        ].join('\n'),
      );
    }
  } else if (command === 'list') {
    const tokens = tokensMod.listTokens(db);
    if (args.json) {
      emitJson({ count: tokens.length, tokens });
    } else if (tokens.length === 0) {
      process.stdout.write('No stored tokens. (Bootstrap env tokens are not listed here.)\n');
    } else {
      process.stdout.write(
        `${table(tokens, [
          { key: 'id', header: 'ID' },
          { key: 'role', header: 'ROLE' },
          { key: 'state', header: 'STATE' },
          { key: 'name', header: 'NAME' },
          { key: 'created_at', header: 'CREATED' },
          { key: 'expires_at', header: 'EXPIRES' },
          { key: 'revoked_at', header: 'REVOKED' },
        ])}\n`,
      );
    }
  } else if (command === 'retire') {
    const id = args._[1];
    if (!id) fail('retire needs a TOKEN_ID (see `list`)', 2);
    if (args.dryRun) {
      emitJson({ dry_run: true, id, would_retire: true });
    } else {
      const result = tokensMod.retireToken(
        db,
        id,
        args.reason ? String(args.reason).slice(0, 200) : 'retired by operator (CLI)',
      );
      if (!result.token) fail(`no token with id ${id}`, 1);
      audit('token.retired', `retired token ${id} (changed=${result.changed})`);
      if (args.json) emitJson(result);
      else {
        process.stdout.write(
          result.changed
            ? `Retired ${id}. It is refused on the next request; no restart needed.\n`
            : `${id} was already retired (${result.token.revoked_at}). Nothing changed.\n`,
        );
      }
    }
  } else if (command === 'expire') {
    const id = args._[1];
    if (!id) fail('expire needs a TOKEN_ID (see `list`)', 2);
    let at;
    if (args.at) {
      at = parseExpiryValue(args.at);
    } else {
      const duration = parseDuration(args.in ?? '0');
      if (duration === null) fail(`cannot parse --in value: ${args.in}`, 2);
      at = new Date(Date.now() + duration).toISOString();
    }
    const updated = tokensMod.expireToken(db, id, at);
    if (!updated) fail(`no token with id ${id}`, 1);
    audit('token.expired', `set expiry of token ${id} to ${at}`);
    if (args.json) emitJson(updated);
    else {
      process.stdout.write(
        `Token ${id} now expires at ${at} (state: ${updated.state}). Refused from that instant.\n`,
      );
    }
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error), 1);
}
