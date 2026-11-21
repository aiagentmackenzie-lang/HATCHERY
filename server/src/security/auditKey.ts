/**
 * The audit chain's key ring (D31).
 *
 * D30's chain is a SHA-256 linked list. That detects a careless edit, but anyone
 * who can write the database can recompute every digest from their edit onwards and
 * produce a chain that verifies — the log *looks* tamper-evident and is not. D31
 * adds a keyed MAC per row, so forging the chain requires the key as well as write
 * access to the database.
 *
 * The posture mirrors D28/D29 on purpose, because an operator should not have to
 * learn a second security model for the same machine:
 *
 * - The key ring is `<db dir>/.audit-keyring`, versioned JSON, `0600`, at most 64
 *   KiB and 32 keys, read with the same rules as the sample-store key file (regular,
 *   non-symlink, no group/other bits).
 * - Resolution order: `HATCHERY_AUDIT_KEY` (64 hex), then `HATCHERY_AUDIT_KEY_FILE`,
 *   then the ring. **The ring is authoritative once it exists** — a configured env key
 *   that the ring does not hold is ignored (and reported), because history can only
 *   be verified with the keys it names.
 * - With nothing configured, the first start generates a ring and announces it. There
 *   is no silent unkeyed fallback in the server path; the file sits beside the
 *   database, which protects against database-only tampering (a `sqlite3` edit, a
 *   copied `.db`, a backup that includes the database but not the key) and **not**
 *   against an attacker who can read that directory. Point
 *   `HATCHERY_AUDIT_KEY_FILE` outside it when that distinction matters.
 * - Rotation is additive: the new key becomes active and the old ones stay in the
 *   ring, so every historical row still verifies by the key id it names. Nothing is
 *   re-MAC'd — re-writing evidence to make it verify under a new key would be exactly
 *   the rewrite the chain exists to detect.
 *
 * The key material is never logged, returned by the API, printed by `list`, or
 * written into the database or a row. Only the derived key id is.
 */

import { createHash, createHmac, randomBytes } from 'crypto';
import fs from 'fs';
import path from 'path';

export const KEYRING_FILENAME = '.audit-keyring';
const KEYRING_MAX_BYTES = 64 * 1024;
const MAX_KEYS = 32;
const MATERIAL_PATTERN = /^[0-9a-f]{64}$/;

export interface AuditKey {
  id: string;
  /** 64 hex characters (32 bytes). Never returned by an API or a listing. */
  material: string;
  created_at: string;
}

export type KeySource = 'env' | 'file' | 'ring' | 'generated';

export interface AuditKeyring {
  version: 1;
  active: string;
  keys: AuditKey[];
  source: KeySource;
  path: string;
  /** A configured env key that the ring overrides. Reported, never silently used. */
  env_ignored: boolean;
}

/** The non-secret key id: sha256 over a domain string and the material, first 8 bytes. */
export function keyIdOf(material: string): string {
  return createHash('sha256')
    .update(`hatchery.audit.key-id.v1\u0000${material}`, 'utf8')
    .digest('hex')
    .slice(0, 16);
}

function newKey(): AuditKey {
  const material = randomBytes(32).toString('hex');
  return { id: keyIdOf(material), material, created_at: new Date().toISOString() };
}

/**
 * Read a key file with the sample-store rules: regular, not a symlink, no group or
 * other bits, small, and 64 hex characters. A looser file is refused, not repaired.
 */
export function readKeyFile(file: string): string {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink()) throw new Error(`${file}: refusing a symlink key file`);
  if (!stat.isFile()) throw new Error(`${file}: refusing a non-regular key file`);
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `${file}: key file must not be group/other accessible (mode ${(stat.mode & 0o777).toString(8)})`,
    );
  }
  if (stat.size > 4096) throw new Error(`${file}: key file is larger than 4096 bytes`);
  const material = fs.readFileSync(file, 'utf8').trim();
  if (!MATERIAL_PATTERN.test(material)) {
    throw new Error(`${file}: expected 64 hex characters (32 bytes) of key material`);
  }
  return material;
}

export function readRingFile(file: string): AuditKeyring | null {
  if (!fs.existsSync(file)) return null;
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink()) throw new Error(`${file}: refusing a symlink key ring`);
  if (!stat.isFile()) throw new Error(`${file}: refusing a non-regular key ring`);
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `${file}: key ring must be 0600 (mode ${(stat.mode & 0o777).toString(8)})`,
    );
  }
  if (stat.size > KEYRING_MAX_BYTES) throw new Error(`${file}: key ring is larger than 64 KiB`);

  let parsed: any;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`${file}: not valid JSON (${error instanceof Error ? error.message : error})`);
  }
  if (parsed?.version !== 1) {
    throw new Error(`${file}: unsupported key-ring version ${String(parsed?.version)}`);
  }
  if (!Array.isArray(parsed.keys) || parsed.keys.length === 0) {
    throw new Error(`${file}: key ring has no keys`);
  }
  if (parsed.keys.length > MAX_KEYS) {
    throw new Error(`${file}: key ring has more than ${MAX_KEYS} keys`);
  }
  const keys: AuditKey[] = parsed.keys.map((key: any) => {
    if (typeof key?.material !== 'string' || !MATERIAL_PATTERN.test(key.material)) {
      throw new Error(`${file}: a key has malformed material`);
    }
    const id = keyIdOf(key.material);
    if (key.id !== id) throw new Error(`${file}: a key id does not match its material`);
    return {
      id,
      material: key.material,
      created_at: typeof key.created_at === 'string' ? key.created_at : '',
    };
  });
  const ids = new Set(keys.map((key) => key.id));
  if (ids.size !== keys.length) throw new Error(`${file}: duplicate key ids`);
  if (typeof parsed.active !== 'string' || !ids.has(parsed.active)) {
    throw new Error(`${file}: active key ${String(parsed.active)} is not in the ring`);
  }
  return { version: 1, active: parsed.active, keys, source: 'ring', path: file, env_ignored: false };
}

/**
 * Create the ring **exclusively**. Two processes starting against a fresh database
 * must not each generate a key and have the second overwrite the first: rows written
 * under the loser's key would then be unverifiable. `O_EXCL` makes exactly one
 * process the creator; the other reads what it wrote.
 */
export function createKeyringExclusive(ring: AuditKeyring): AuditKeyring {
  const document = JSON.stringify(
    { version: 1, active: ring.active, keys: ring.keys.map((key) => ({ ...key })) },
    null,
    2,
  );
  try {
    const fd = fs.openSync(ring.path, 'wx', 0o600);
    try {
      fs.writeFileSync(fd, document);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return ring;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    const existing = readRingFile(ring.path);
    if (!existing) throw new Error(`${ring.path}: exists but is not a readable key ring`);
    return existing;
  }
}

/** Write the ring atomically and `0600`: temp in the same directory, fsync, rename. */
export function writeKeyring(ring: AuditKeyring): void {
  const file = ring.path;
  const dir = path.dirname(file);
  const temp = path.join(dir, `.tmp-audit-keyring-${process.pid}-${randomBytes(4).toString('hex')}`);
  const document = JSON.stringify(
    {
      version: 1,
      active: ring.active,
      keys: ring.keys.map((key) => ({
        id: key.id,
        material: key.material,
        created_at: key.created_at,
      })),
    },
    null,
    2,
  );
  const fd = fs.openSync(temp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, document);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, file);
  try {
    const dirFd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  } catch {
    // directory fsync is best effort on platforms that refuse it
  }
}

/**
 * Resolve the chain's keys.
 *
 * Never returns "no key" for a server start: with nothing configured it generates a
 * ring and says so. A caller that must not touch the filesystem (a unit test) can
 * pass `{ generate: false }` and get `null`, in which case rows are written unkeyed —
 * only reachable from tests, and verification reports the reduced assurance rather
 * than pretending otherwise.
 */
export function resolveAuditKeyring(
  dbPath: string,
  env: NodeJS.ProcessEnv = process.env,
  options: { generate?: boolean } = {},
): AuditKeyring | null {
  const ringPath = path.join(path.dirname(dbPath), KEYRING_FILENAME);
  const configured = (env.HATCHERY_AUDIT_KEY ?? '').trim();
  const configuredFile = (env.HATCHERY_AUDIT_KEY_FILE ?? '').trim();

  let envMaterial: string | null = null;
  let envSource: KeySource = 'env';
  if (configured) {
    if (!MATERIAL_PATTERN.test(configured)) {
      throw new Error('HATCHERY_AUDIT_KEY must be 64 hex characters (32 bytes)');
    }
    envMaterial = configured;
  } else if (configuredFile) {
    envMaterial = readKeyFile(configuredFile);
    envSource = 'file';
  }

  const existing = readRingFile(ringPath);
  if (existing) {
    const envId = envMaterial ? keyIdOf(envMaterial) : null;
    const known = envId !== null && existing.keys.some((key) => key.id === envId);
    return { ...existing, source: 'ring', env_ignored: envId !== null && !known };
  }

  if (envMaterial) {
    const key: AuditKey = {
      id: keyIdOf(envMaterial),
      material: envMaterial,
      created_at: new Date().toISOString(),
    };
    // Not written to disk until an explicit rotation materialises it — the operator
    // already has the key somewhere, and copying it beside the database silently
    // would be a downgrade of their posture.
    return { version: 1, active: key.id, keys: [key], source: envSource, path: ringPath, env_ignored: false };
  }

  if (options.generate === false) return null;

  const key = newKey();
  const ring: AuditKeyring = {
    version: 1,
    active: key.id,
    keys: [key],
    source: 'generated',
    path: ringPath,
    env_ignored: false,
  };
  return createKeyringExclusive(ring);
}

/**
 * Rotate: the new key becomes active and every old key stays in the ring, so all
 * historical rows keep verifying by the key id they name. Refuses to rotate a ring
 * that has not been materialised from an env/file key yet without first writing it —
 * otherwise the previous key would be lost and with it every row's verifiability.
 */
export function rotateAuditKey(ring: AuditKeyring): AuditKeyring {
  if (!fs.existsSync(ring.path)) {
    // Materialise the current key first, then add the new one.
    writeKeyring({ ...ring, source: 'ring' });
  }
  const fresh = newKey();
  const next: AuditKeyring = {
    ...ring,
    source: 'ring',
    env_ignored: false,
    active: fresh.id,
    keys: [...ring.keys, fresh],
  };
  writeKeyring(next);
  return next;
}

/** The row MAC: HMAC-SHA256 over a domain string, the key id and the row's canonical form. */
export function auditMac(material: string, keyId: string, canonical: string): string {
  return createHmac('sha256', Buffer.from(material, 'hex'))
    .update(`hatchery.audit.mac.v1\u0000${keyId}\u0000${canonical}`, 'utf8')
    .digest('hex');
}

export function findKey(ring: AuditKeyring | null, keyId: string | null): AuditKey | null {
  if (!ring || !keyId) return null;
  return ring.keys.find((key) => key.id === keyId) ?? null;
}

export function activeKey(ring: AuditKeyring): AuditKey {
  const key = ring.keys.find((candidate) => candidate.id === ring.active);
  if (!key) throw new Error(`active key ${ring.active} is missing from the ring`);
  return key;
}
