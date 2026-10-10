import { FastifyInstance } from 'fastify';
import path from 'path';
import { getDb, TaskRow } from '../db/index.js';
import { ingestBundle } from '../db/ingest.js';
import { RESULTS_ROOT, readQueueJob, type QueueJob } from '../db/queue.js';

/** Terminal task states: once here, the queue has nothing more to say. */
const TERMINAL = new Set(['completed', 'failed']);

/**
 * Mirror a queued job's state onto its task row.
 *
 * The queue is the single producer of job state; this is the API projecting it
 * onto its own `tasks` table so the existing dashboard queries keep working. It
 * is idempotent (ingest replaces a task's rows), and it runs lazily on read, so
 * no background timer is needed. A job that completed causes the bundle to be
 * ingested; a job that failed records the job's real error, never a silent pass.
 */
function reconcileTask(db: ReturnType<typeof getDb>, task: TaskRow | any): QueueJob | null {
  if (!task?.queue_job_id) return null;
  const job = readQueueJob(String(task.queue_job_id));
  if (!job) return null;

  if (job.status === 'completed' && task.status !== 'completed') {
    const result = ingestBundle(db, task.task_id, path.join(RESULTS_ROOT, task.task_id));
    if (!result.ok) {
      db.prepare(
        `UPDATE tasks SET status = 'failed', error_message = ?, updated_at = datetime('now')
         WHERE task_id = ?`,
      ).run(result.error ?? 'Bundle ingest failed', task.task_id);
    } else {
      console.log(
        `[hatchery] task ${task.task_id}: job ${job.job_id} completed, ingested ` +
          `${result.events} event(s), ${result.iocs} IOC(s)`,
      );
    }
  } else if (job.status === 'failed' && task.status !== 'failed') {
    db.prepare(
      `UPDATE tasks SET status = 'failed', error_message = ?, updated_at = datetime('now')
       WHERE task_id = ?`,
    ).run(job.error ?? 'the queued job failed', task.task_id);
  } else if (job.status === 'running' && task.status !== 'running') {
    db.prepare(
      "UPDATE tasks SET status = 'running', updated_at = datetime('now') WHERE task_id = ?",
    ).run(task.task_id);
  }
  return job;
}

export async function statusRoutes(app: FastifyInstance) {
  // Get all tasks
  app.get('/api/tasks', async (request: any, reply: any) => {
    const db = getDb();
    const initial = db.prepare(`
      SELECT task_id, file_name, file_size, md5, sha256, status, static_done, sandbox_done,
             created_at, completed_at, error_message, queue_job_id
      FROM tasks ORDER BY created_at DESC LIMIT 100
    `).all() as any[];

    // Reflect queue state for any task that is not yet terminal. This is the
    // projection, not a second producer: the queue owns job state, the API owns
    // this table (D27).
    for (const task of initial) {
      if (task.queue_job_id && !TERMINAL.has(String(task.status))) {
        reconcileTask(db, task);
      }
    }

    const tasks = db.prepare(`
      SELECT task_id, file_name, file_size, md5, sha256, status, static_done, sandbox_done,
             created_at, completed_at, error_message, queue_job_id
      FROM tasks ORDER BY created_at DESC LIMIT 100
    `).all();
    return reply.send({ tasks });
  });

  // Get single task status
  app.get('/api/tasks/:taskId', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();
    let task = db.prepare('SELECT * FROM tasks WHERE task_id = ?').get(taskId) as TaskRow | undefined;

    if (!task) {
      return reply.code(404).send({ error: 'Task not found' });
    }

    // Reflect the queue's state, and ingest the bundle if the job completed.
    const queue = reconcileTask(db, task);
    if (queue) {
      task = db.prepare('SELECT * FROM tasks WHERE task_id = ?').get(taskId) as TaskRow;
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
      queue: queue ?? null,
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