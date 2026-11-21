/**
 * Access audit endpoints (D25/D30).
 *
 * Reading the audit log is itself an auditable admin action: a viewer token can
 * see analysis, but only an admin can see who did what. The same is true of
 * verifying the hash chain — it is a read of the security record, and the rows it
 * reads are the operator's actions.
 */

import { FastifyInstance } from 'fastify';
import { databasePath, getDb } from '../db/index.js';
import { countAudit, listAudit, recordAudit, verifyAuditChain } from '../security/audit.js';

const MAX_VERIFY_DEFAULT = 5000;

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

  /**
   * Recompute the audit hash chain (D30/D31) and the archived segments behind it (D32).
   *
   * Bounded rather than exhaustive: at most `limit` rows are checked per call and
   * an incomplete pass returns `next_after_id` for the operator to continue with.
   * A tampered, deleted, inserted or truncated row is reported at its id with a
   * classification — never skipped because it "looked fine". Compaction moved history
   * into archives; `archive.mode=full` reads them, `archive.mode=presence` only stats
   * them and the response then says the archive was **not** verified.
   */
  app.get('/api/audit/verify', async (request: any, reply: any) => {
    const db = getDb();
    const query = (request.query ?? {}) as Record<string, unknown>;
    const limitRaw = query.limit;
    const limit =
      limitRaw === undefined ? MAX_VERIFY_DEFAULT : Number.parseInt(String(limitRaw), 10);
    if (Number.isNaN(limit) || limit < 1) {
      return reply.code(400).send({ error: 'limit must be a positive integer' });
    }
    const afterRaw = query.after;
    const after =
      afterRaw === undefined ? 0 : Number.parseInt(String(afterRaw), 10);
    if (Number.isNaN(after) || after < 0) {
      return reply.code(400).send({ error: 'after must be a non-negative integer' });
    }

    // An externally recorded head (`npm run audit -- head`) makes a deliberate
    // truncation or a whole-database rollback detectable: without an anchor outside
    // the database, a rewrite of the tail plus its metadata verifies.
    let expectHead: { id: number; hash: string } | null = null;
    const expectRaw = query.expect_head;
    if (expectRaw !== undefined && String(expectRaw) !== '') {
      const match = /^(\d+):([0-9a-f]{64})$/.exec(String(expectRaw));
      if (!match) {
        return reply
          .code(400)
          .send({ error: 'expect_head must be "<id>:<64 hex chars>" (see npm run audit -- head)' });
      }
      expectHead = { id: Number(match[1]), hash: match[2] };
    }

    const result = verifyAuditChain(db, {
      limitRows: limit,
      afterId: after,
      expectHead,
      dbPath: databasePath(),
      // Reading the archive is the default because "ok" over a compacted log that was
      // never opened would be a claim the verifier cannot support. `?archive=presence`
      // stats the files instead and says plainly that it did not read them.
      archiveMode: query.archive === 'presence' ? 'presence' : 'full',
    });
    const actor = request.hatcheryActor ?? {
      name: 'anonymous',
      role: 'anonymous',
      authenticated: false,
    };
    recordAudit(db, {
      actor: actor.name,
      role: actor.role,
      authenticated: actor.authenticated,
      method: request.method,
      path: '/api/audit/verify',
      statusCode: 200,
      action: 'audit.verified',
      detail:
        `checked ${result.rows_checked} live row(s) and ` +
        `${result.archive.checked ? result.archive.rows : 0} archived row(s), ` +
        `assurance=${result.assurance}, archive=${result.archive.join}: ` +
        (result.ok
          ? 'chain intact'
          : `first break at row ${result.first_broken?.id ?? 'unknown'} ` +
            `(${result.first_broken?.classification ?? 'unknown'})`),
    });
    return reply.send(result);
  });
}
