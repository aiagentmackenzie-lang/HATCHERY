import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = path.join(__dirname, '..', '..', '..');
const VENV_PYTHON = path.join(ENGINE_ROOT, '.venv', 'bin', 'python3');

export async function submitRoutes(app: FastifyInstance) {
  // Submit a sample for analysis
  app.post('/api/submit', async (request: any, reply: any) => {
    const body = request.body ?? {};
    let filePath: string = body.filePath;
    const timeout: number = body.timeout ?? 120;
    const noSandbox: boolean = body.noSandbox ?? false;

    if (!filePath) {
      return reply.code(400).send({ error: 'filePath is required' });
    }

    // Resolve relative paths against workspace
    if (!path.isAbsolute(filePath)) {
      filePath = path.resolve(process.cwd(), filePath);
    }

    if (!fs.existsSync(filePath)) {
      return reply.code(404).send({ error: 'File not found', path: filePath });
    }

    const taskId = randomUUID().slice(0, 12);
    const fileName = path.basename(filePath);
    const fileSize = fs.statSync(filePath).size;

    const db = getDb();
    db.prepare(`
      INSERT INTO tasks (task_id, file_name, file_path, file_size, status)
      VALUES (?, ?, ?, ?, 'running')
    `).run(taskId, fileName, filePath, fileSize);

    // Run analysis asynchronously
    runAnalysis(taskId, filePath, timeout, noSandbox);

    return reply.send({
      task_id: taskId,
      status: 'running',
      file_name: fileName,
      file_size: fileSize,
      timeout,
      no_sandbox: noSandbox,
    });
  });

  // Re-submit / re-analyze an existing task
  app.post('/api/submit/:taskId/retry', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();
    const task = db.prepare('SELECT * FROM tasks WHERE task_id = ?').get(taskId) as any;

    if (!task) {
      return reply.code(404).send({ error: 'Task not found' });
    }

    db.prepare("UPDATE tasks SET status = 'running', error_message = NULL, updated_at = datetime('now') WHERE task_id = ?")
      .run(taskId);

    runAnalysis(taskId, task.file_path, 120, false);

    return reply.send({ task_id: taskId, status: 'running' });
  });
}

function runAnalysis(taskId: string, filePath: string, timeout: number, noSandbox: boolean) {
  const args = ['-m', 'engine.cli', 'submit', filePath, '--timeout', String(timeout), '-o', `results/${taskId}`];
  if (noSandbox) args.push('--no-sandbox');

  const proc = spawn(VENV_PYTHON, args, {
    cwd: ENGINE_ROOT,
    env: {
      ...process.env,
      PYTHONPATH: ENGINE_ROOT,
      HATCHERY_TASK_ID: taskId,
    },
  });

  let stdout = '';
  let stderr = '';

  proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
  proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

  proc.on('close', (code: number) => {
    const db = getDb();
    if (code === 0) {
      db.prepare(`
        UPDATE tasks SET status = 'completed', completed_at = datetime('now'), updated_at = datetime('now')
        WHERE task_id = ?
      `).run(taskId);
    } else {
      db.prepare(`
        UPDATE tasks SET status = 'failed', error_message = ?, updated_at = datetime('now')
        WHERE task_id = ?
      `).run(stderr.slice(0, 2000), taskId);
    }
  });
}