import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';

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
      return reply.send(buildSTIXBundle(taskId, iocs));
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

function buildSTIXBundle(taskId: string, iocs: any[]): any {
  const now = new Date().toISOString();
  const objects: any[] = [
    {
      type: 'identity',
      spec_version: '2.1',
      id: `identity--${taskId}`,
      created: now,
      modified: now,
      name: 'HATCHERY',
      identity_class: 'system',
    },
  ];

  for (const ioc of iocs) {
    const stixType = iocTypeToSTIX(ioc.ioc_type);
    if (!stixType) continue;

    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${ioc.id}`,
      created: now,
      modified: now,
      name: `${ioc.ioc_type}: ${ioc.value}`,
      description: ioc.context ?? `Extracted by HATCHERY from task ${taskId}`,
      indicator_types: ['malicious-activity'],
      pattern: `[${stixType} = '${ioc.value}']`,
      pattern_type: 'stix',
      valid_from: now,
      labels: [ioc.severity, ioc.source ?? 'hatchery'],
    });
  }

  return {
    type: 'bundle',
    id: `bundle--${taskId}`,
    objects,
  };
}

function iocTypeToSTIX(iocType: string): string | null {
  const mapping: Record<string, string> = {
    ip: 'ipv4-addr',
    domain: 'domain-name',
    url: 'url',
    email: 'email-addr',
    hash: 'file:hashes.\'SHA-256\'',
    registry_key: 'windows-registry-key',
    mutex: 'mutex',
    file_path: 'file:name',
  };
  return mapping[iocType] ?? null;
}