/**
 * Segmented-chain archives (D32).
 *
 * D31 made the audit chain unforgeable without the key, but not finite: `audit_log`
 * grows for the life of the deployment. The obvious fix — `DELETE` old rows — is the
 * one thing a hash chain cannot survive, because the next row's `prev_hash` points
 * into the deleted region. So a compaction **archives** the segment and hands the
 * chain off:
 *
 * - The archive is a self-contained JSONL file (optionally gzipped) of exactly the
 *   fields `audit_log` stores — no token, header, body or sample byte, and nothing
 *   the table did not already hold.
 * - A manifest is written **last** (temp + fsync + rename + dir fsync). It records
 *   the counts, the first/last id, the tail `entry_hash`/`entry_mac`, the key ids
 *   present, the SHA-256 of the archive file and the compaction window. It contains
 *   no secret — key ids only.
 * - The row that follows the archived tail (`prev_hash` = the archived tail's
 *   `entry_hash`) is the handoff. Whether that row is a surviving live row or the
 *   `audit.compacted` record the compaction appends, the invariant is the same and
 *   an offline verifier can prove it by splicing the two chains.
 *
 * This module owns the **file formats** and the **archive verifier**. Policy,
 * deletion and crash-resume live in `auditCompaction.ts`.
 */

import { createHash, timingSafeEqual } from 'crypto';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import type Database from 'better-sqlite3';

import {
  CHAIN_ALGORITHM,
  GENESIS_HASH,
  canonical,
  entryHash,
  type ChainBreak,
} from './auditChain.js';
import { auditMac, findKey, type AuditKeyring } from './auditKey.js';

export const ARCHIVE_FORMAT = 'hatchery.audit-archive';
export const MANIFEST_VERSION = 1;
export const ARCHIVE_DIRNAME = 'audit-archives';

/**
 * One compaction run archives at most this many rows. It bounds the archive file, the
 * time the write lock is held and the cost of a full verification; the operator can
 * raise it with `--max-segment-rows` and run `compact` again for the rest.
 */
export const DEFAULT_MAX_SEGMENT_ROWS = 50_000;

/** A single archive file larger than this is refused rather than read into memory. */
export const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;

/** A manifest is small by construction; anything larger is not one of ours. */
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;

/** At most this many segments are recorded before the metadata itself is suspect. */
export const MAX_SEGMENTS = 512;

/** Exactly the columns `audit_log` stores. Nothing is added to an archive row. */
export interface ArchiveRow {
  id: number;
  actor: string;
  role: string;
  authenticated: number;
  method: string;
  path: string;
  status_code: number | null;
  action: string | null;
  detail: string | null;
  created_at: string;
  prev_hash: string | null;
  entry_hash: string;
  key_id: string | null;
  entry_mac: string | null;
}

export interface ArchiveTail {
  id: number;
  entry_hash: string;
  entry_mac: string | null;
  key_id: string | null;
  created_at: string;
}

/** The `audit_chain_meta.archive_segments` entry for one compaction. */
export interface ArchiveSegment {
  sequence: number;
  created_at: string;
  window: {
    first_id: number;
    last_id: number;
    rows: number;
    from: string | null;
    to: string | null;
    policy: Record<string, unknown>;
  };
  archive: {
    /** Path relative to the database directory (or absolute if it is elsewhere). */
    path: string;
    sha256: string;
    size: number;
    compression: 'none' | 'gzip';
  };
  manifest: { path: string; sha256: string };
  first: { prev_hash: string; entry_hash: string };
  tail: ArchiveTail;
  key_ids: string[];
  algorithm: string;
  genesis: string;
}

export interface ArchiveSegmentRead {
  segments: ArchiveSegment[];
  error: string | null;
}

export function sha256(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256Buffer(data: Buffer): string {
  return sha256(data);
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== right.length || left.length === 0) return false;
  return timingSafeEqual(left, right);
}

function fsyncDir(dir: string): void {
  try {
    const fd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // directory fsync is best effort on platforms that refuse it
  }
}

/** The archive directory: `<db dir>/audit-archives` unless the operator chose one. */
export function defaultArchiveDir(dbPath: string): string {
  return path.join(path.dirname(dbPath), ARCHIVE_DIRNAME);
}

export function ensureArchiveDir(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/** Record a path the way the manifest and the audit row should name it. */
export function describeArchivePath(dbPath: string, file: string): string {
  const base = path.dirname(dbPath);
  const relative = path.relative(base, file);
  if (!relative.startsWith('..') && !path.isAbsolute(relative)) return relative;
  return file;
}

export function resolveArchivePath(dbPath: string, recorded: string): string {
  return path.isAbsolute(recorded) ? recorded : path.resolve(path.dirname(dbPath), recorded);
}

export function archiveFileName(firstId: number, lastId: number, gzip: boolean): string {
  const pad = (value: number) => String(value).padStart(6, '0');
  return `audit-${pad(firstId)}-${pad(lastId)}.jsonl${gzip ? '.gz' : ''}`;
}

export function manifestFileName(firstId: number, lastId: number): string {
  const pad = (value: number) => String(value).padStart(6, '0');
  return `audit-${pad(firstId)}-${pad(lastId)}.manifest.json`;
}

/** One JSONL line, with a fixed key order so the bytes are reproducible. */
export function archiveLine(row: ArchiveRow): string {
  return JSON.stringify({
    id: row.id,
    actor: row.actor,
    role: row.role,
    authenticated: row.authenticated,
    method: row.method,
    path: row.path,
    status_code: row.status_code,
    action: row.action,
    detail: row.detail,
    created_at: row.created_at,
    prev_hash: row.prev_hash,
    entry_hash: row.entry_hash,
    key_id: row.key_id,
    entry_mac: row.entry_mac,
  });
}

/** The archive body. Deterministic: the same rows always produce the same bytes. */
export function serialiseArchive(rows: ArchiveRow[]): Buffer {
  if (rows.length === 0) return Buffer.alloc(0);
  return Buffer.from(`${rows.map(archiveLine).join('\n')}\n`, 'utf8');
}

export interface WrittenArchive {
  file: string;
  bytes: Buffer;
  written: boolean;
}

/**
 * Write an archive atomically, or adopt an identical one left by an interrupted run.
 *
 * The content is deterministic, so a re-run after a crash produces the same bytes and
 * the existing file is reused rather than duplicated. A file with the same name but
 * different content is refused: that is not a resumable state, it is a conflict.
 */
export function writeArchive(
  dir: string,
  firstId: number,
  lastId: number,
  rows: ArchiveRow[],
  gzip: boolean,
): WrittenArchive {
  ensureArchiveDir(dir);
  const file = path.join(dir, archiveFileName(firstId, lastId, gzip));
  const plain = serialiseArchive(rows);
  const payload = gzip ? zlib.gzipSync(plain, { level: 9 }) : plain;

  if (fs.existsSync(file)) {
    const existing = fs.readFileSync(file);
    const decoded = gzip ? zlib.gunzipSync(existing) : existing;
    if (!decoded.equals(plain)) {
      throw new Error(
        `${file}: an archive with this window already exists with different content ` +
          '— refusing to overwrite evidence',
      );
    }
    return { file, bytes: existing, written: false };
  }

  const temp = path.join(
    dir,
    `.tmp-${path.basename(file)}-${process.pid}-${createHash('sha256')
      .update(String(Date.now() + Math.random()))
      .digest('hex')
      .slice(0, 8)}`,
  );
  const fd = fs.openSync(temp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, payload);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, file);
  // `openSync` above already created it 0600; an operator umask cannot widen it.
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // best effort; the file was created 0600
  }
  fsyncDir(dir);
  return { file, bytes: payload, written: true };
}

export interface ManifestInput {
  dbPath: string;
  dir: string;
  firstId: number;
  lastId: number;
  rows: ArchiveRow[];
  archiveFile: string;
  archiveSha256: string;
  archiveSize: number;
  compression: 'none' | 'gzip';
  policy: Record<string, unknown>;
  headId: number | null;
  headHash: string | null;
  now: string;
}

export interface WrittenManifest {
  file: string;
  document: Record<string, unknown>;
  sha256: string;
  written: boolean;
}

function manifestDocument(input: ManifestInput): Record<string, unknown> {
  const first = input.rows[0];
  const last = input.rows[input.rows.length - 1];
  const keyIds = Array.from(
    new Set(input.rows.map((row) => row.key_id).filter((id): id is string => Boolean(id))),
  ).sort();
  return {
    format: ARCHIVE_FORMAT,
    manifest_version: MANIFEST_VERSION,
    created_at: input.now,
    // What this archive is, and what it is not: it can be checked on a machine that
    // never had the database, and it contains no credential or sample byte.
    contains: 'exactly the audit_log fields for the window below; no token, header, body or sample byte',
    algorithm: CHAIN_ALGORITHM,
    genesis: GENESIS_HASH,
    archive: {
      path: describeArchivePath(input.dbPath, input.archiveFile),
      file: path.basename(input.archiveFile),
      sha256: input.archiveSha256,
      size: input.archiveSize,
      compression: input.compression,
      rows: input.rows.length,
    },
    window: {
      first_id: input.firstId,
      last_id: input.lastId,
      rows: input.rows.length,
      from: first?.created_at ?? null,
      to: last?.created_at ?? null,
      policy: input.policy,
    },
    first: {
      id: first?.id ?? null,
      prev_hash: first?.prev_hash ?? null,
      entry_hash: first?.entry_hash ?? null,
      entry_mac: first?.entry_mac ?? null,
      key_id: first?.key_id ?? null,
    },
    tail: {
      id: last?.id ?? null,
      entry_hash: last?.entry_hash ?? null,
      entry_mac: last?.entry_mac ?? null,
      key_id: last?.key_id ?? null,
      created_at: last?.created_at ?? null,
    },
    key_ids: keyIds,
    database: { head_id: input.headId, head_hash: input.headHash },
  };
}

/**
 * Write the manifest **last**, and adopt an existing one when it describes the same
 * archive. That is what makes a crash between "manifest written" and "rows deleted"
 * resumable to the same manifest hash instead of a second, different record.
 */
export function writeManifest(input: ManifestInput): WrittenManifest {
  ensureArchiveDir(input.dir);
  const file = path.join(input.dir, manifestFileName(input.firstId, input.lastId));
  const document = manifestDocument(input);
  const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`, 'utf8');

  if (fs.existsSync(file)) {
    const existing = fs.readFileSync(file);
    let parsed: any;
    try {
      parsed = JSON.parse(existing.toString('utf8'));
    } catch (error) {
      throw new Error(
        `${file}: an existing manifest is not valid JSON and cannot be adopted ` +
          `(${error instanceof Error ? error.message : String(error)})`,
      );
    }
    const same =
      parsed?.format === ARCHIVE_FORMAT &&
      parsed?.manifest_version === MANIFEST_VERSION &&
      parsed?.archive?.sha256 === input.archiveSha256 &&
      Number(parsed?.window?.first_id) === input.firstId &&
      Number(parsed?.window?.last_id) === input.lastId &&
      Number(parsed?.window?.rows) === input.rows.length &&
      parsed?.tail?.entry_hash === (input.rows[input.rows.length - 1]?.entry_hash ?? null);
    if (!same) {
      throw new Error(
        `${file}: an existing manifest for this window does not describe this archive ` +
          '— refusing to overwrite evidence',
      );
    }
    return { file, document: parsed, sha256: sha256(existing), written: false };
  }

  const temp = path.join(
    input.dir,
    `.tmp-${path.basename(file)}-${process.pid}-${createHash('sha256')
      .update(String(Date.now() + Math.random()))
      .digest('hex')
      .slice(0, 8)}`,
  );
  const fd = fs.openSync(temp, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, file);
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // best effort
  }
  fsyncDir(input.dir);
  return { file, document, sha256: sha256(bytes), written: true };
}

/** Parse `audit_chain_meta.archive_segments`. Garbage is a reported error, not a pass. */
export function readArchiveSegments(db: Database.Database): ArchiveSegmentRead {
  let raw: string | null = null;
  try {
    const row = db
      .prepare("SELECT value FROM audit_chain_meta WHERE key = 'archive_segments'")
      .get() as { value: string } | undefined;
    raw = row?.value ?? null;
  } catch {
    return { segments: [], error: 'audit_chain_meta is unreadable' };
  }
  if (!raw) return { segments: [], error: null };
  if (raw.length > 1024 * 1024) {
    return { segments: [], error: 'archive metadata is larger than 1 MiB — refusing to trust it' };
  }
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    return {
      segments: [],
      error: `archive metadata is not valid JSON (${error instanceof Error ? error.message : String(error)})`,
    };
  }
  if (!Array.isArray(parsed)) {
    return { segments: [], error: 'archive metadata is not an array of segments' };
  }
  if (parsed.length > MAX_SEGMENTS) {
    return { segments: [], error: `archive metadata records more than ${MAX_SEGMENTS} segments` };
  }
  const segments: ArchiveSegment[] = [];
  for (const item of parsed) {
    if (
      !item ||
      typeof item !== 'object' ||
      !Number.isInteger(item.window?.first_id) ||
      !Number.isInteger(item.window?.last_id) ||
      typeof item.tail?.entry_hash !== 'string' ||
      typeof item.manifest?.path !== 'string' ||
      typeof item.manifest?.sha256 !== 'string'
    ) {
      return { segments: [], error: 'an archive segment entry is malformed' };
    }
    segments.push(item as ArchiveSegment);
  }
  segments.sort((a, b) => Number(a.sequence) - Number(b.sequence));
  return { segments, error: null };
}

export interface ArchiveVerification {
  ok: boolean;
  checked: boolean;
  rows: number;
  first_broken: ChainBreak | null;
  manifest_sha256: string | null;
  archive_sha256: string | null;
  tail: ArchiveTail | null;
  first_prev_hash: string | null;
  error: string | null;
  /** Whether a caller-supplied row (an anchored head) is present in this archive. */
  contains: { id: number; found: boolean; mismatched: boolean } | null;
}

function readArchiveBytes(file: string): Buffer {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink()) throw new Error(`${file}: refusing a symlink archive`);
  if (!stat.isFile()) throw new Error(`${file}: archive is not a regular file`);
  if (stat.size > MAX_ARCHIVE_BYTES) {
    throw new Error(
      `${file}: archive is ${stat.size} bytes, larger than the ${MAX_ARCHIVE_BYTES}-byte ` +
        'verification limit — split the segment or verify it on the host that wrote it',
    );
  }
  return fs.readFileSync(file);
}

function decodeArchive(file: string, gzip: boolean): Buffer {
  const bytes = readArchiveBytes(file);
  if (!gzip) return bytes;
  const decoded = zlib.gunzipSync(bytes);
  if (decoded.length > MAX_ARCHIVE_BYTES) {
    throw new Error(
      `${file}: decompressed archive is larger than the ${MAX_ARCHIVE_BYTES}-byte limit`,
    );
  }
  return decoded;
}

export interface VerifyArchiveOptions {
  archiveFile: string;
  manifestFile: string;
  keyring: AuditKeyring | null;
  /** The hash the first archived row must link to (genesis, or the previous tail). */
  expectedFirstPrev?: string;
  /** When set, the live chain's first `prev_hash` must equal the archive's tail. */
  expectJoin?: string | null;
  /**
   * An anchored head that must be located: an anchor recorded before a compaction is
   * no longer the live head, but it is still evidence that the archived rows existed.
   */
  expectContains?: { id: number; hash: string };
}

/**
 * Verify one archive segment offline: the manifest hash, the file hash, the chain,
 * every MAC, the counts and the tail.
 *
 * "Offline" means "no database": an operator can hand this file and the manifest to a
 * machine that never held HATCHERY, check every row, and splice the result onto the
 * live chain with two hashes. It needs the key ring (or the env key) to check MACs —
 * without it the answer is `unknown-key`, never a pass.
 */
export function verifyArchive(options: VerifyArchiveOptions): ArchiveVerification {
  const result: ArchiveVerification = {
    ok: true,
    checked: false,
    rows: 0,
    first_broken: null,
    manifest_sha256: null,
    archive_sha256: null,
    tail: null,
    first_prev_hash: null,
    error: null,
    contains: options.expectContains
      ? { id: options.expectContains.id, found: false, mismatched: false }
      : null,
  };

  let hashNote = '';
  const fail = (classification: ChainBreak['classification'], detail: string, id: number | null = null) => {
    result.ok = false;
    result.first_broken = { id, classification, detail: `${detail}${hashNote}` };
    return result;
  };

  if (!fs.existsSync(options.manifestFile)) {
    return fail('archive-missing', `the archive manifest ${options.manifestFile} is missing`);
  }
  let manifestBytes: Buffer;
  try {
    const stat = fs.lstatSync(options.manifestFile);
    if (stat.isSymbolicLink()) return fail('archive-invalid', 'the manifest is a symlink');
    if (!stat.isFile()) return fail('archive-invalid', 'the manifest is not a regular file');
    if (stat.size > MAX_MANIFEST_BYTES) return fail('archive-invalid', 'the manifest is implausibly large');
    manifestBytes = fs.readFileSync(options.manifestFile);
  } catch (error) {
    return fail('archive-invalid', `the manifest cannot be read: ${String(error)}`);
  }
  result.manifest_sha256 = sha256(manifestBytes);

  let manifest: any;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    return fail(
      'archive-invalid',
      `the manifest is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (manifest?.format !== ARCHIVE_FORMAT || manifest?.manifest_version !== MANIFEST_VERSION) {
    return fail(
      'archive-invalid',
      `the manifest is not a version-${MANIFEST_VERSION} ${ARCHIVE_FORMAT} document`,
    );
  }
  if (!fs.existsSync(options.archiveFile)) {
    return fail(
      'archive-missing',
      `the archive file ${options.archiveFile} named by the manifest is missing`,
    );
  }

  // A file-hash mismatch is recorded, not returned immediately: an edited row should be
  // reported **at its row** with the right classification, and the manifest-hash
  // mismatch named alongside it. Only a change that leaves every row self-consistent
  // (re-serialised whitespace, a swapped-in but validly MAC'd row set) is reported as
  // a bare `archive-mismatch`.
  const declaredHash = typeof manifest.archive?.sha256 === 'string' ? manifest.archive.sha256 : null;
  let hashMatches = true;

  let rows: ArchiveRow[];
  try {
    const declared = manifest.archive?.compression === 'gzip' ? 'gzip' : 'none';
    const bytes = decodeArchive(options.archiveFile, declared === 'gzip');
    result.archive_sha256 = sha256(readArchiveBytes(options.archiveFile));
    if (declaredHash) hashMatches = constantTimeEqual(result.archive_sha256, declaredHash);
    const text = bytes.toString('utf8');
    rows = text
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line) as ArchiveRow);
  } catch (error) {
    return fail(
      'archive-invalid',
      `the archive cannot be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  hashNote = hashMatches
    ? ''
    : ` (the manifest records archive sha256 ${declaredHash}, the file hashes to ` +
      `${result.archive_sha256} — the file is not the one that was recorded)`;

  result.checked = true;
  result.rows = rows.length;
  if (rows.length === 0) return fail('archive-truncated', 'the archive contains no rows');

  // Bound the archive by the window the manifest recorded **before** walking it, so a
  // removed tail is reported at the first id that is missing rather than as a bare
  // count mismatch.
  const expectedRows = Number(manifest.window?.rows ?? -1);
  if (rows[0].id !== Number(manifest.window?.first_id)) {
    return fail(
      'archive-truncated',
      `the archive starts at row ${rows[0].id}, but the manifest records the window ` +
        `starting at row ${String(manifest.window?.first_id)}`,
      rows[0].id,
    );
  }
  if (rows[rows.length - 1].id !== Number(manifest.window?.last_id)) {
    return fail(
      'archive-truncated',
      `the archive ends at row ${rows[rows.length - 1].id}, but the manifest records ` +
        `${String(manifest.window?.last_id)} — the tail is missing`,
      rows[rows.length - 1].id + 1,
    );
  }

  let expectedPrev = options.expectedFirstPrev ?? rows[0].prev_hash ?? GENESIS_HASH;
  let previousId: number | null = null;
  let sawMac = false;
  for (const row of rows) {
    if (previousId !== null && row.id !== previousId + 1) {
      return fail(
        'archive-truncated',
        `the archive jumps from row ${previousId} to row ${row.id} — a row is missing from the archive`,
        previousId + 1,
      );
    }
    if (row.prev_hash !== expectedPrev) {
      return fail(
        'archive-modified',
        `row ${row.id} links to ${String(row.prev_hash)}, but the previous row's hash is ` +
          `${expectedPrev} — the archive was edited`,
        row.id,
      );
    }
    if (row.entry_hash !== entryHash(row)) {
      return fail(
        'archive-modified',
        `row ${row.id} no longer hashes to its stored entry_hash`,
        row.id,
      );
    }
    if (row.entry_mac) {
      const key = findKey(options.keyring, row.key_id);
      if (!key) {
        return fail(
          'unknown-key',
          `row ${row.id} is MAC'd with key ${String(row.key_id)}, which the key ring does not ` +
            'hold — supply the ring that authenticated this archive',
          row.id,
        );
      }
      const expected = auditMac(key.material, key.id, canonical(row));
      if (!constantTimeEqual(expected, row.entry_mac)) {
        return fail(
          'archive-modified',
          `row ${row.id} is internally consistent but its MAC does not verify — it was ` +
            'rewritten without the audit key',
          row.id,
        );
      }
      sawMac = true;
    } else if (sawMac) {
      return fail(
        'unkeyed',
        `row ${row.id} has no MAC after keyed rows — the archive was downgraded`,
        row.id,
      );
    }
    expectedPrev = row.entry_hash;
    previousId = row.id;
    result.first_prev_hash ??= row.prev_hash;
    if (options.expectContains && result.contains && row.id === options.expectContains.id) {
      if (row.entry_hash === options.expectContains.hash) result.contains.found = true;
      else result.contains.mismatched = true;
    }
  }

  if (expectedRows !== rows.length) {
    return fail(
      'archive-truncated',
      `the archive holds ${rows.length} row(s) but the manifest records ${expectedRows}`,
      rows[0].id,
    );
  }

  const tail = rows[rows.length - 1];
  result.tail = {
    id: tail.id,
    entry_hash: tail.entry_hash,
    entry_mac: tail.entry_mac,
    key_id: tail.key_id,
    created_at: tail.created_at,
  };
  if (manifest.tail?.entry_hash && manifest.tail.entry_hash !== tail.entry_hash) {
    return fail(
      'archive-truncated',
      `the archive ends at ${tail.id}:${tail.entry_hash}, but the manifest records ` +
        `${String(manifest.tail.id)}:${manifest.tail.entry_hash}`,
      tail.id,
    );
  }
  if (manifest.tail?.entry_mac && manifest.tail.entry_mac !== tail.entry_mac) {
    return fail(
      'archive-modified',
      `the archive's tail MAC does not match the manifest — the last row was replaced`,
      tail.id,
    );
  }
  if (options.expectJoin && options.expectJoin !== tail.entry_hash) {
    return fail(
      'join-mismatch',
      `the live chain starts after ${String(options.expectJoin)}, but the archive ends at ` +
        `${tail.id}:${tail.entry_hash} — the two chains do not splice`,
      tail.id,
    );
  }

  // Every row is self-consistent and MAC'd, yet the bytes are not the recorded bytes.
  if (!hashMatches) {
    return fail(
      'archive-mismatch',
      'every row verifies, but the archive file is not the one the manifest recorded' +
        hashNote,
      rows[0].id,
    );
  }

  return result;
}

/** Resolve the manifest that belongs to an archive file (or accept the manifest path). */
export function manifestPathFor(archivePath: string): string {
  if (archivePath.endsWith('.manifest.json')) return archivePath;
  const dir = path.dirname(archivePath);
  const base = path.basename(archivePath).replace(/\.jsonl(\.gz)?$/, '');
  const match = /^audit-(\d{6})-(\d{6})$/.exec(base);
  if (match) return path.join(dir, `audit-${match[1]}-${match[2]}.manifest.json`);
  return path.join(dir, `${base}.manifest.json`);
}

/** Build the `ArchiveSegment` record for the metadata table from a written manifest. */
export function segmentFromManifest(
  dbPath: string,
  sequence: number,
  manifest: any,
  manifestSha256: string,
  archiveSha256: string,
  created_at: string,
): ArchiveSegment {
  const rows = Number(manifest.window.rows);
  return {
    sequence,
    created_at,
    window: {
      first_id: Number(manifest.window.first_id),
      last_id: Number(manifest.window.last_id),
      rows,
      from: manifest.window.from ?? null,
      to: manifest.window.to ?? null,
      policy: manifest.window.policy ?? {},
    },
    archive: {
      path: manifest.archive.path,
      sha256: archiveSha256,
      size: Number(manifest.archive.size ?? 0),
      compression: manifest.archive.compression === 'gzip' ? 'gzip' : 'none',
    },
    manifest: { path: describeArchivePath(dbPath, manifestPathFor(manifest.archive.path)), sha256: manifestSha256 },
    first: {
      prev_hash: String(manifest.first?.prev_hash ?? ''),
      entry_hash: String(manifest.first?.entry_hash ?? ''),
    },
    tail: {
      id: Number(manifest.tail.id),
      entry_hash: String(manifest.tail.entry_hash),
      entry_mac: manifest.tail.entry_mac ?? null,
      key_id: manifest.tail.key_id ?? null,
      created_at: manifest.tail.created_at ?? '',
    },
    key_ids: Array.isArray(manifest.key_ids) ? manifest.key_ids.map(String) : [],
    algorithm: CHAIN_ALGORITHM,
    genesis: GENESIS_HASH,
  };
}
