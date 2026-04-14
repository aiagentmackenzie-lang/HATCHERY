import { FastifyInstance } from 'fastify';
import { getDb, TaskRow } from '../db/index.js';

export async function statusRoutes(app: FastifyInstance) {
  // Get all tasks
  app.get('/api/tasks', async (request: any, reply: any) => {
    const db = getDb();
    const tasks = db.prepare(`
      SELECT task_id, file_name, file_size, md5, sha256, status, static_done, sandbox_done,
             created_at, completed_at, error_message
      FROM tasks ORDER BY created_at DESC LIMIT 100
    `).all();
    return reply.send({ tasks });
  });

  // Get single task status
  app.get('/api/tasks/:taskId', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();
    const task = db.prepare('SELECT * FROM tasks WHERE task_id = ?').get(taskId) as TaskRow | undefined;

    if (!task) {
      return reply.code(404).send({ error: 'Task not found' });
    }

    // Get static results if available
    const staticResults = db.prepare('SELECT * FROM static_results WHERE task_id = ?').get(taskId) as any;

    // Get sandbox results if available
    const sandboxResults = db.prepare('SELECT * FROM sandbox_results WHERE task_id = ?').get(taskId) as any;

    // Get IOC count
    const iocCount = db.prepare('SELECT ioc_type, COUNT(*) as count FROM iocs WHERE task_id = ? GROUP BY ioc_type')
      .all(taskId) as any[];

    // Get event counts by category
    const eventCounts = db.prepare(`
      SELECT category, COUNT(*) as count FROM behavioral_events WHERE task_id = ? GROUP BY category
    `).all(taskId) as any[];

    return reply.send({
      task,
      static_results: staticResults ?? null,
      sandbox_results: sandboxResults ?? null,
      ioc_summary: iocCount,
      event_summary: eventCounts,
    });
  });

  // Get behavioral events for a task (paginated, filterable)
  app.get('/api/tasks/:taskId/events', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const { category, severity, limit = 200, offset = 0 } = request.query as any;

    const db = getDb();
    let query = 'SELECT * FROM behavioral_events WHERE task_id = ?';
    const params: any[] = [taskId];

    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }
    if (severity) {
      query += ' AND severity = ?';
      params.push(severity);
    }

    query += ' ORDER BY id ASC LIMIT ? OFFSET ?';
    params.push(Number(limit), Number(offset));

    const events = db.prepare(query).all(...params);

    const total = db.prepare(`
      SELECT COUNT(*) as count FROM behavioral_events WHERE task_id = ?
      ${category ? ' AND category = ?' : ''}
      ${severity ? ' AND severity = ?' : ''}
    `).get(...params.slice(0, -2)) as any;

    return reply.send({
      events,
      total: total?.count ?? 0,
      limit: Number(limit),
      offset: Number(offset),
    });
  });
}