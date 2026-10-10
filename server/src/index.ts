import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import multipart from '@fastify/multipart';
import { submitRoutes } from './routes/submit.js';
import { statusRoutes } from './routes/status.js';
import { reportRoutes } from './routes/report.js';
import { iocRoutes } from './routes/iocs.js';
import { analysisRoutes } from './routes/analysis.js';
import { auditRoutes } from './routes/audit.js';
import { getDb } from './db/index.js';
import { isOpen, readTokens, requiredRole, resolveActor, roleSatisfies } from './security/auth.js';
import { recordAudit, shouldAudit } from './security/audit.js';

const PORT = parseInt(process.env.HATCHERY_PORT ?? '3002', 10);
// Bind to loopback by default. This API stores live malware samples and serves
// their artefacts; exposing it on every interface by default is not a safe
// default. Set HATCHERY_HOST=0.0.0.0 deliberately, and set HATCHERY_API_TOKEN.
const HOST = process.env.HATCHERY_HOST ?? '127.0.0.1';
// Roles, not just a shared secret (D25). HATCHERY_API_TOKEN is still accepted as
// a back-compatible admin token; HATCHERY_READ_TOKEN adds a read-only role.
const TOKENS = readTokens();

const app = Fastify({ logger: false });

// Initialize DB on startup
getDb();

// CORS for dashboard
app.register(cors, { origin: true });

if (isOpen(TOKENS)) {
  // Off by default so the local dashboard keeps working, but never silently: a
  // malware-sandbox API with no auth is worth saying out loud at every start.
  console.warn(
    '[hatchery] No API token configured — the API is UNAUTHENTICATED. ' +
      'Set HATCHERY_ADMIN_TOKEN (full access) or HATCHERY_READ_TOKEN (read-only).',
  );
} else {
  console.warn(
    `[hatchery] API auth enabled — roles: admin=${TOKENS.admin ? 'yes' : 'no'}, ` +
      `viewer=${TOKENS.viewer ? 'yes' : 'no'}`,
  );
}

// AuthN + authZ, then an append-only audit row for the outcome. Reads need the
// viewer role; anything that changes state needs admin.
app.addHook('onRequest', async (request: any, reply: any) => {
  const headers = request.headers as Record<string, unknown>;
  const path = String(request.url).split('?')[0];
  const required = requiredRole(request.method, path);

  // A public endpoint (health) needs no credential, even when tokens are set.
  if (required === 'anonymous') {
    request.hatcheryActor = { name: 'anonymous', role: 'anonymous', authenticated: false };
    return;
  }

  const actor = resolveActor(headers, TOKENS);
  if (!actor) {
    if (shouldAudit(path)) {
      recordAudit(getDb(), {
        actor: 'unknown', role: 'anonymous', authenticated: false,
        method: request.method, path, statusCode: 401, action: 'auth.denied',
        detail: 'missing or invalid token',
      });
    }
    request.hatcheryAudited = true;
    return reply.code(401).send({ error: 'Unauthorized' });
  }

  request.hatcheryActor = actor;
  if (!roleSatisfies(actor.role, required)) {
    if (shouldAudit(path)) {
      recordAudit(getDb(), {
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
  recordAudit(getDb(), {
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
app.register(multipart, { limits: { fileSize: 50 * 1024 * 1024 } });

// REST routes
app.register(submitRoutes);
app.register(statusRoutes);
app.register(reportRoutes);
app.register(iocRoutes);
app.register(analysisRoutes);
app.register(auditRoutes);

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
  if (isOpen(TOKENS)) {
    console.warn(
      '⚠  No API token is set: this API is unauthenticated. ' +
      'It accepts sample submissions and serves sample artefacts. ' +
      'Do not bind it to a non-loopback interface without setting ' +
      'HATCHERY_ADMIN_TOKEN / HATCHERY_READ_TOKEN.',
    );
  }
});