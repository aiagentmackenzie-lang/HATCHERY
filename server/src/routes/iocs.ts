import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = path.join(__dirname, '..', '..', '..');
const RESULTS_ROOT = path.join(ENGINE_ROOT, 'results');

export async function iocRoutes(app: FastifyInstance) {
  // Get all IOCs for a task
  app.get('/api/tasks/:taskId/iocs', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const { type, severity, format = 'json' } = request.query as any;

    const db = getDb();

    // Verify task exists
    const task = db.prepare('SELECT task_id FROM tasks WHERE task_id = ?').get(taskId) as any;
    if (!task) {
      return reply.code(404).send({ error: 'Task not found' });
    }

    let query = 'SELECT * FROM iocs WHERE task_id = ?';
    const params: any[] = [taskId];

    if (type) {
      query += ' AND ioc_type = ?';
      params.push(type);
    }
    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    query += ' ORDER BY severity DESC, ioc_type, value';
    const iocs = db.prepare(query).all(...params) as any[];

    // Summary by type
    const summary: Record<string, number> = {};
    for (const ioc of iocs) {
      summary[ioc.ioc_type] = (summary[ioc.ioc_type] ?? 0) + 1;
    }

    if (format === 'stix') {
      // Serve the bundle the Python exporter produced.
      //
      // This route used to build its own STIX inline, with identifiers like
      // `indicator--<row id>` which are not valid STIX 2.1 (the spec requires
      // `type--UUID`). There were therefore two STIX producers that disagreed,
      // and the one on this side was wrong. There is now one producer.
      const stixPath = path.join(RESULTS_ROOT, taskId, 'stix_bundle.json');
      if (!fs.existsSync(stixPath)) {
        return reply.code(404).send({
          error: 'No STIX bundle for this task',
          detail: 'Run the task to completion; the engine writes stix_bundle.json.',
          path: stixPath,
        });
      }
      return reply.send(JSON.parse(fs.readFileSync(stixPath, 'utf-8')));
    }

    // Plain list format
    if (format === 'text') {
      const lines = iocs.map(ioc => `[${ioc.severity.toUpperCase()}] ${ioc.ioc_type}: ${ioc.value}`);
      reply.type('text/plain');
      return reply.send(lines.join('\n'));
    }

    return reply.send({ iocs, summary, total: iocs.length });
  });
}
