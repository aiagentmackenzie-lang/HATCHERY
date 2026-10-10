/**
 * Access audit endpoints (D25).
 *
 * Reading the audit log is itself an auditable admin action: a viewer token can
 * see analysis, but only an admin can see who did what.
 */

import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import { countAudit, listAudit } from '../security/audit.js';

export async function auditRoutes(app: FastifyInstance) {
  app.get('/api/audit', async (request: any, reply: any) => {
    const db = getDb();
    const query = (request.query ?? {}) as Record<string, unknown>;
    const limitRaw = query.limit;
    const limit = limitRaw === undefined ? 100 : Number.parseInt(String(limitRaw), 10);
    if (Number.isNaN(limit) || limit < 1) {
      return reply.code(400).send({ error: 'limit must be a positive integer' });
    }
    const actor = typeof query.actor === 'string' && query.actor ? query.actor : undefined;
    return reply.send({
      count: countAudit(db),
      entries: listAudit(db, { limit, actor }),
    });
  });
}
