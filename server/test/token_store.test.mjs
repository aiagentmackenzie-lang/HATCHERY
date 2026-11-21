/**
 * Token store and resolution units (D30).
 *
 * The end-to-end file proves the operator-visible behaviour; this one pins the
 * pieces that are easy to get subtly wrong and hard to see from outside: the token
 * format, the domain-separated hash, every fail-closed refusal reason, and the
 * documented precedence between bootstrap env tokens and stored tokens.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import {
  checkStoredToken,
  createToken,
  expireToken,
  generateToken,
  hasStoredTokens,
  hashToken,
  listTokens,
  retireToken,
  tokenIdOf,
  tokenState,
} from '../dist/security/tokens.js';
import { isOpen, readTokens, requiredRole, resolveActor, resolveRequest } from '../dist/security/auth.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(here, '..', 'src', 'db', 'schema.sql');

function freshDb() {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  return db;
}

/** Insert a row with a known secret, bypassing createToken (for failure paths). */
function insertRow(db, { id, role = 'viewer', expiresAt = null, revokedAt = null, secret }) {
  db.prepare(
    `INSERT INTO api_tokens (id, name, role, prefix, secret_hash, created_at, expires_at, revoked_at, retired_reason)
     VALUES (?, NULL, ?, ?, ?, ?, ?, ?, NULL)`,
  ).run(id, role, id, hashToken(secret), new Date().toISOString(), expiresAt, revokedAt);
}

test('a generated token has a strict, fixed-length format', () => {
  const generated = generateToken();
  assert.match(generated.token, /^htk_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/);
  assert.equal(generated.token.length, 64);
  assert.equal(generated.id, generated.prefix);
  assert.equal(generated.tokenIdOf ?? tokenIdOf(generated.token), generated.id);
  assert.equal(generated.token.slice(0, 20), generated.id);

  // Uniqueness: two calls never collide (they are 256-bit secrets).
  const other = generateToken();
  assert.notEqual(other.token, generated.token);
  assert.notEqual(other.id, generated.id);
});

test('the stored hash is domain-separated, one-way and stable', () => {
  const { token } = generateToken();
  const stored = hashToken(token);
  assert.match(stored, /^[0-9a-f]{64}$/);
  assert.equal(hashToken(token), stored, 'the same token always hashes the same');
  assert.notEqual(
    stored,
    createHash('sha256').update(token).digest('hex'),
    'a plain SHA-256 of the token is not the stored value (domain separation)',
  );
  assert.notEqual(hashToken(token), hashToken(`${token}x`));
  assert.ok(!stored.includes(token));
});

test('tokenIdOf rejects anything that is not exactly our format', () => {
  const { id, token } = generateToken();
  const bad = [
    '',
    id,
    token.slice(0, -1),
    `${token}x`,
    token.replace('htk_', 'tok_'),
    token.replace(/[0-9a-f]{16}/, 'ABCDEF0123456789'),
    `${id}_`,
    `${id}__${token.split('_')[2]}`,
    'htk_123',
  ];
  for (const candidate of bad) {
    assert.equal(tokenIdOf(candidate), null, `must reject: ${candidate}`);
  }
  assert.equal(tokenIdOf(token), id);
});

test('createToken never returns or stores anything but a hash and a prefix', () => {
  const db = freshDb();
  const created = createToken(db, { role: 'admin', name: 'ops' });
  const rows = db.prepare('SELECT * FROM api_tokens').all();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].secret_hash, hashToken(created.token));
  assert.notEqual(rows[0].secret_hash, created.token);
  assert.equal(rows[0].prefix, created.id);
  assert.equal(created.expires_at, null);

  const listing = listTokens(db);
  assert.equal(listing.length, 1);
  assert.equal(listing[0].state, 'live');
  const serialized = JSON.stringify(listing);
  assert.ok(!serialized.includes(created.token));
  assert.ok(!serialized.includes(rows[0].secret_hash), 'the hash is not listed either');

  assert.throws(() => createToken(db, { role: 'root' }), /invalid role/);
  const expiring = createToken(db, { role: 'viewer', expiresAt: '2030-01-01T00:00:00Z' });
  assert.equal(expiring.expires_at, '2030-01-01T00:00:00.000Z');
});

test('every ambiguous token is refused with a precise reason', () => {
  const db = freshDb();
  const live = createToken(db, { role: 'viewer' });
  const admin = createToken(db, { role: 'admin' });
  const revoked = createToken(db, { role: 'viewer' });
  const expired = createToken(db, { role: 'viewer' });
  retireToken(db, revoked.id);
  expireToken(db, expired.id, new Date(Date.now() - 1000).toISOString());

  assert.deepEqual(checkStoredToken(db, live.token), {
    ok: true,
    reason: 'token-valid',
    tokenId: live.id,
    role: 'viewer',
  });
  assert.equal(checkStoredToken(db, admin.token).role, 'admin');

  const cases = [
    ['token-malformed', 'htk_not-a-real-token'],
    ['token-malformed', live.id], // the id alone is not a credential
    ['token-malformed', `${live.id}_`],
    ['token-unknown', `htk_ffffffffffffffff_${'A'.repeat(43)}`],
    ['token-hash-mismatch', `${live.id}_${'A'.repeat(43)}`],
    ['token-revoked', revoked.token],
    ['token-expired', expired.token],
  ];
  for (const [reason, presented] of cases) {
    const result = checkStoredToken(db, presented);
    assert.equal(result.ok, false, `${reason} should not authenticate`);
    assert.equal(result.reason, reason);
    assert.equal(result.role, null);
  }

  // A malformed expiry is never treated as "no expiry".
  insertRow(db, {
    id: 'htk_00000000000000aa',
    secret: 'htk_00000000000000aa_' + 'B'.repeat(43),
    expiresAt: 'not-a-date',
  });
  assert.equal(checkStoredToken(db, 'htk_00000000000000aa_' + 'B'.repeat(43)).reason, 'token-malformed');

  // A role this build does not understand fails closed, even with the right secret.
  insertRow(db, {
    id: 'htk_00000000000000bb',
    role: 'superuser',
    secret: 'htk_00000000000000bb_' + 'C'.repeat(43),
  });
  const unknownRole = checkStoredToken(db, 'htk_00000000000000bb_' + 'C'.repeat(43));
  assert.equal(unknownRole.ok, false);
  assert.equal(unknownRole.reason, 'token-invalid-role');

  // A hash that is not a hash cannot match.
  db.prepare('UPDATE api_tokens SET secret_hash = ? WHERE id = ?').run('short', live.id);
  assert.equal(checkStoredToken(db, live.token).reason, 'token-hash-mismatch');

  // An unreadable store is refused, not treated as open.
  db.exec('DROP TABLE api_tokens');
  assert.equal(checkStoredToken(db, live.token).reason, 'token-store-unreadable');
});

test('bootstrap tokens take precedence over stored tokens', () => {
  const db = freshDb();
  const tokens = readTokens({ HATCHERY_ADMIN_TOKEN: 'env-admin', HATCHERY_READ_TOKEN: 'env-viewer' });

  // A stored row that claims the bootstrap secret must not become the actor: the
  // env pair is checked first and is not looked up in the store at all.
  db.prepare(
    `INSERT INTO api_tokens (id, name, role, prefix, secret_hash, created_at)
     VALUES ('htk_00000000000000cc', 'shadow', 'viewer', 'htk_00000000000000cc', ?, ?)`,
  ).run(hashToken('env-admin'), new Date().toISOString());

  const boot = resolveRequest({ authorization: 'Bearer env-admin' }, tokens, db);
  assert.equal(boot.actor.role, 'admin');
  assert.equal(boot.actor.name, 'admin');
  assert.equal(boot.source, 'bootstrap');
  assert.equal(boot.tokenId, null);

  const stored = createToken(db, { role: 'viewer' });
  const storedResolution = resolveRequest({ authorization: `Bearer ${stored.token}` }, tokens, db);
  assert.equal(storedResolution.source, 'store');
  assert.equal(storedResolution.actor.name, `token:${stored.id}`);
  assert.equal(storedResolution.actor.role, 'viewer');
  assert.equal(storedResolution.actor.authenticated, true);
});

test('open mode requires no bootstrap token and no stored token at all', () => {
  const empty = freshDb();
  const tokens = readTokens({});

  assert.equal(isOpen(tokens, empty), true);
  assert.deepEqual(resolveActor({}, tokens, empty), {
    name: 'anonymous',
    role: 'admin',
    authenticated: false,
  });

  // Creating a token closes it immediately; retiring it must NOT re-open it.
  const created = createToken(empty, { role: 'viewer' });
  assert.equal(hasStoredTokens(empty), true);
  assert.equal(isOpen(tokens, empty), false);
  assert.equal(resolveActor({}, tokens, empty), null);
  retireToken(empty, created.id);
  assert.equal(isOpen(tokens, empty), false, 'retiring the last token must not re-open the API');
  assert.equal(resolveActor({ authorization: `Bearer ${created.token}` }, tokens, empty), null);

  // An unreadable store fails closed.
  const broken = freshDb();
  broken.exec('DROP TABLE api_tokens');
  assert.equal(isOpen(tokens, broken), false);
  assert.equal(resolveRequest({}, tokens, broken).reason, 'token-store-unreadable');
});

test('token states and retirement are idempotent', () => {
  const db = freshDb();
  const created = createToken(db, { role: 'viewer' });
  assert.equal(tokenState({ ...created, revoked_at: null, retired_reason: null }), 'live');

  const first = retireToken(db, created.id, 'done');
  assert.equal(first.changed, true);
  const second = retireToken(db, created.id, 'done again');
  assert.equal(second.changed, false);
  assert.equal(second.token.revoked_at, first.token.revoked_at);
  assert.equal(second.token.state, 'revoked');

  assert.equal(retireToken(db, 'htk_ffffffffffffffff').token, null);
  assert.equal(expireToken(db, 'htk_ffffffffffffffff', new Date().toISOString()), null);

  // Revocation wins over expiry: a revoked token stays revoked even if its expiry
  // is later moved, so a state transition is never ambiguous.
  const reopened = expireToken(db, created.id, new Date(Date.now() - 5).toISOString());
  assert.equal(reopened.state, 'revoked');

  const expiring = createToken(db, { role: 'viewer' });
  const expired = expireToken(db, expiring.id, new Date(Date.now() - 5).toISOString());
  assert.equal(expired.state, 'expired');
});

test('the token routes are admin-only for every method', () => {
  assert.equal(requiredRole('GET', '/api/tokens'), 'admin');
  assert.equal(requiredRole('POST', '/api/tokens'), 'admin');
  assert.equal(requiredRole('POST', '/api/tokens/htk_abc/retire'), 'admin');
  assert.equal(requiredRole('GET', '/api/audit/verify'), 'admin');
});
