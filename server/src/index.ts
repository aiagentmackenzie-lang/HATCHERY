import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import multipart from '@fastify/multipart';
import { MAX_UPLOAD_BYTES, submitRoutes } from './routes/submit.js';
import { statusRoutes } from './routes/status.js';
import { reportRoutes } from './routes/report.js';
import { iocRoutes } from './routes/iocs.js';
import { analysisRoutes } from './routes/analysis.js';
import { auditRoutes } from './routes/audit.js';
import { tokenRoutes } from './routes/tokens.js';
import { getDb } from './db/index.js';
import { isOpen, readTokens, requiredRole, resolveRequest, roleSatisfies } from './security/auth.js';
import { recordAudit, shouldAudit } from './security/audit.js';
import { allowedOrigins, describeAllowList, isOriginAllowed } from './security/cors.js';
import { countTokens } from './security/tokens.js';
import { auditKeyring } from './security/audit.js';
import { databasePath } from './db/index.js';
import { growthReport } from './security/auditGrowth.js';

const PORT = parseInt(process.env.HATCHERY_PORT ?? '3002', 10);
// Bind to loopback by default. This API stores live malware samples and serves
// their artefacts; exposing it on every interface by default is not a safe
// default. Set HATCHERY_HOST=0.0.0.0 deliberately, and set HATCHERY_API_TOKEN.
const HOST = process.env.HATCHERY_HOST ?? '127.0.0.1';
// Roles, not just a shared secret (D25). HATCHERY_API_TOKEN is still accepted as
// a back-compatible admin token; HATCHERY_READ_TOKEN adds a read-only role. These
// are the **bootstrap** pair: stored tokens live in the database (D30) and are
// checked after them, so retiring every stored token can never lock an operator
// out of a host they can already reach.
const TOKENS = readTokens();
// CORS is an allow-list, not a reflection (D30). `origin: true` let any web origin
// call the API from a browser; the list is exact-match, and a request with no
// Origin header (curl, the worker, the CLI) is unaffected either way.
const ALLOWED_ORIGINS = allowedOrigins();

const app = Fastify({ logger: false });

// Initialize DB on startup. An unusable audit key ring throws here: the API must
// not start and answer requests whose audit trail it cannot authenticate (D31).
let db: ReturnType<typeof getDb>;
try {
  db = getDb();
} catch (error) {
  console.error(
    `[hatchery] refusing to start: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exit(1);
}

/**
 * Name a refusal in the server log, never the credential (D30).
 *
 * The reason and the stored token id are operational facts; the presented token is
 * not, and is never in scope here. `no-credential` is the ordinary "you forgot the
 * header" case and would flood the log on a port scan, so it stays in the audit log
 * only — where it belongs, and where it is admin-readable.
 */
function logAuthRefusal(reason: string, tokenId: string | null, method: string, path: string) {
  if (reason === 'no-credential') return;
  const target = tokenId ? ` token ${tokenId}` : '';
  const line = `[hatchery] auth denied: ${reason}${target} (${method} ${path})`;
  if (reason === 'token-store-unreadable') console.error(line);
  else console.warn(line);
}

app.register(cors, {
  origin: (requestOrigin: string | undefined, callback: (err: Error | null, allow: boolean) => void) => {
    callback(null, isOriginAllowed(requestOrigin, ALLOWED_ORIGINS));
  },
  credentials: false,
  methods: ['GET', 'HEAD', 'POST', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'X-HATCHERY-Token'],
  maxAge: 600,
});

console.warn(`[hatchery] CORS allow-list — ${describeAllowList(ALLOWED_ORIGINS)}`);

{
  const ring = auditKeyring();
  if (ring) {
    console.warn(
      `[hatchery] audit chain keyed — key ${ring.active} (${ring.source})` +
        (ring.env_ignored
          ? '; HATCHERY_AUDIT_KEY is IGNORED because the key ring already exists'
          : ''),
    );
    if (ring.source === 'generated') {
      console.warn(
        `[hatchery] the audit key is at ${ring.path}, beside the database. It stops a ` +
          'database-only rewrite; it does not stop a reader of that directory. Point ' +
          'HATCHERY_AUDIT_KEY_FILE outside the data directory for that, and record ' +
          '`npm run audit -- head` somewhere else to detect a deliberate truncation.',
      );
    }
  } else {
    console.warn(
      '[hatchery] audit chain is UNKEYED — no audit key was resolved. ' +
        'GET /api/audit/verify will report assurance=unkeyed.',
    );
  }
}

// The disk-growth guard (D32): make an unbounded log visible **before** it hurts.
// It warns; it never deletes. Only `npm run audit -- compact --apply` removes rows.
{
  const growth = growthReport(db, databasePath());
  if (growth.over) {
    console.warn(
      `[hatchery] AUDIT LOG GROWTH WARNING — ${growth.reasons.join('; ')}. ` +
        'Nothing was deleted: run `npm run audit -- status` and then ' +
        '`npm run audit -- compact --apply` (retention is an operator decision).',
    );
  }
  let archived = 0;
  let segments = 0;
  try {
    const rows = db
      .prepare("SELECT key, value FROM audit_chain_meta WHERE key IN ('archive_segments', 'archived_row_total')")
      .all() as Array<{ key: string; value: string }>;
    const map = Object.fromEntries(rows.map((row) => [row.key, row.value]));
    archived = Number(map.archived_row_total ?? '0') || 0;
    segments = map.archive_segments ? (JSON.parse(map.archive_segments) as unknown[]).length : 0;
  } catch {
    // a database mid-migration; the verifier will report it
  }
  if (segments > 0) {
    console.warn(
      `[hatchery] audit chain spans ${segments} archive segment(s), ${archived} archived row(s) — ` +
        'GET /api/audit/verify reads them; a missing archive is a break, not a pass.',
    );
  }
}

if (isOpen(TOKENS, db)) {
  // Off by default so the local dashboard keeps working, but never silently: a
  // malware-sandbox API with no auth is worth saying out loud at every start.
  console.warn(
    '[hatchery] No API token configured — the API is UNAUTHENTICATED. ' +
      'Set HATCHERY_ADMIN_TOKEN (full access) or HATCHERY_READ_TOKEN (read-only).',
  );
} else {
  const stored = countTokens(db);
  console.warn(
    `[hatchery] API auth enabled — bootstrap roles: admin=${TOKENS.admin ? 'yes' : 'no'}, ` +
      `viewer=${TOKENS.viewer ? 'yes' : 'no'}; stored tokens: ${stored.live} live of ` +
      `${stored.total} total (lifecycle: npm run token -- list)`,
  );
}

// AuthN + authZ, then an append-only audit row for the outcome. Reads need the
// viewer role; anything that changes state needs admin. The token store is read per
// request (D30), so a create/retire takes effect on the next request with no
// restart; a request already authenticated keeps the actor it resolved.
app.addHook('onRequest', async (request: any, reply: any) => {
  const headers = request.headers as Record<string, unknown>;
  const path = String(request.url).split('?')[0];
  const required = requiredRole(request.method, path);

  // A public endpoint (health) needs no credential, even when tokens are set.
  if (required === 'anonymous') {
    request.hatcheryActor = { name: 'anonymous', role: 'anonymous', authenticated: false };
    return;
  }

  const resolution = resolveRequest(headers, TOKENS, db);
  const actor = resolution.actor;
  if (!actor) {
    logAuthRefusal(resolution.reason, resolution.tokenId, request.method, path);
    if (shouldAudit(path)) {
      // The reason and token id are precise here and admin-only to read; the HTTP
      // response below stays generic, so the API never becomes a token oracle. The
      // presented credential is never part of this row.
      recordAudit(db, {
        actor: 'unknown', role: 'anonymous', authenticated: false,
        method: request.method, path, statusCode: 401, action: 'auth.denied',
        detail: resolution.tokenId
          ? `auth denied: ${resolution.reason} (token ${resolution.tokenId})`
          : `auth denied: ${resolution.reason}`,
      });
    }
    request.hatcheryAudited = true;
    return reply.code(401).send({ error: 'Unauthorized' });
  }

  request.hatcheryActor = actor;
  if (!roleSatisfies(actor.role, required)) {
    if (shouldAudit(path)) {
      recordAudit(db, {
        actor: actor.name, role: actor.role, authenticated: actor.authenticated,
        method: request.method, path, statusCode: 403, action: 'request.forbidden',
        detail: `requires ${required}`,
      });
    }
    request.hatcheryAudited = true;
    reply.header('x-hatchery-required-role', required);
    return reply
      .code(403)
      .send({ error: 'Forbidden', detail: `this endpoint requires the ${required} role` });
  }
});

app.addHook('onResponse', async (request: any, reply: any) => {
  if (request.hatcheryAudited) return;
  const path = String(request.url).split('?')[0];
  if (!shouldAudit(path)) return;
  const actor = request.hatcheryActor ?? {
    name: 'anonymous', role: 'anonymous', authenticated: false,
  };
  recordAudit(db, {
    actor: actor.name,
    role: actor.role,
    authenticated: actor.authenticated,
    method: request.method,
    path, // query string is deliberately dropped: it can carry identifiers
    statusCode: reply.statusCode,
    action: reply.statusCode >= 500 ? 'request.failed' : 'request.allowed',
  });
});

// Multipart file uploads (e.g. PhishHawk attachment detonation)
// The same number the engine enforces on intake (D40/D41). A request may
// carry one sample and a handful of fields; more parts than that is not a
// submission.
app.register(multipart, {
  limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, parts: 8 },
});

// REST routes
app.register(submitRoutes);
app.register(statusRoutes);
app.register(reportRoutes);
app.register(iocRoutes);
app.register(analysisRoutes);
app.register(auditRoutes);
app.register(tokenRoutes);

// WebSocket for real-time behavioral event streaming
app.register(websocket);

app.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (connection: any, req: any) => {
    // Send welcome
    connection.socket.send(JSON.stringify({
      type: 'connected',
      message: 'HATCHERY real-time event stream',
    }));

    // Client can subscribe to a task's events
    connection.socket.on('message', (message: Buffer) => {
      try {
        const msg = JSON.parse(message.toString());

        if (msg.type === 'subscribe' && msg.task_id) {
          // Mark this connection as subscribed to a task
          (connection as any)._hatcheryTaskId = msg.task_id;

          // Send existing events for this task
          const db = getDb();
          const events = db.prepare(`
            SELECT * FROM behavioral_events WHERE task_id = ? ORDER BY id ASC
          `).all(msg.task_id);

          connection.socket.send(JSON.stringify({
            type: 'events_batch',
            task_id: msg.task_id,
            events,
            total: events.length,
          }));
        }

        if (msg.type === 'ping') {
          connection.socket.send(JSON.stringify({ type: 'pong' }));
        }
      } catch {
        // Ignore malformed messages
      }
    });

    connection.socket.on('close', () => {
      // Cleanup
    });
  });
});

// Health check
app.get('/api/health', async () => {
  return { status: 'ok', service: 'hatchery-api', version: '0.1.0' };
});

// Start
app.listen({ port: PORT, host: HOST }, (err) => {
  if (err) {
    console.error('Failed to start:', err);
    process.exit(1);
  }
  console.log(`🔥 HATCHERY API running on http://${HOST}:${PORT}`);
  console.log(`   WebSocket:    ws://${HOST}:${PORT}/ws`);
  console.log(`   Dashboard:    http://localhost:5173 (run: cd dashboard && npm run dev)`);
  if (isOpen(TOKENS, db)) {
    console.warn(
      '⚠  No API token is set: this API is unauthenticated. ' +
      'It accepts sample submissions and serves sample artefacts. ' +
      'Do not bind it to a non-loopback interface without setting ' +
      'HATCHERY_ADMIN_TOKEN / HATCHERY_READ_TOKEN.',
    );
  }
});