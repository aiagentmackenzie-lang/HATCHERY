import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import fs from 'fs';
import { pipeline } from 'stream/promises';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = path.join(__dirname, '..', '..', '..');
const VENV_PYTHON = path.join(ENGINE_ROOT, '.venv', 'bin', 'python3');
const UPLOADS_DIR = path.join(ENGINE_ROOT, 'uploads');

export async function submitRoutes(app: FastifyInstance) {
  // Submit a sample for analysis (JSON filePath or multipart file upload)
  app.post('/api/submit', async (request: any, reply: any) => {
    let filePath: string | undefined;
    let fileName: string | undefined;
    let fileSize: number | undefined;
    let timeout = 120;
    let noSandbox = false;

    if (request.isMultipart()) {
      // PhishHawk-style multipart upload: iterate parts to find file + fields
      const parts = request.parts();
      let uploadedFile: any = null;
      const fields: Record<string, string> = {};

      for await (const part of parts) {
        if (part.type === 'file') {
          uploadedFile = part;
        } else if (part.value !== undefined) {
          fields[part.fieldname] = String(part.value);
        }
      }

      if (!uploadedFile || !uploadedFile.filename) {
        return reply.code(400).send({ error: 'No file uploaded' });
      }

      if (fields.timeout) timeout = parseInt(fields.timeout, 10) || 120;
      if (fields.noSandbox) noSandbox = fields.noSandbox === 'true';

      const uploadFileName: string = uploadedFile.filename;
      const taskId = randomUUID().slice(0, 12);
      const taskUploadDir = path.join(UPLOADS_DIR, taskId);
      fs.mkdirSync(taskUploadDir, { recursive: true });
      filePath = path.join(taskUploadDir, uploadFileName);

      await pipeline(uploadedFile.file, fs.createWriteStream(filePath));
      const stats = fs.statSync(filePath);
      fileName = uploadFileName;
      fileSize = stats.size;
    } else {
      // Existing JSON body path
      const body = request.body ?? {};
      filePath = body.filePath;
      timeout = body.timeout ?? 120;
      noSandbox = body.noSandbox ?? false;

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

      const stats = fs.statSync(filePath);
      fileName = path.basename(filePath);
      fileSize = stats.size;
    }

    if (!filePath || !fileName || fileSize === undefined) {
      return reply.code(400).send({ error: 'Unable to determine sample file' });
    }

    const taskId = randomUUID().slice(0, 12);

    const db = getDb();
    db.prepare(`
      INSERT INTO tasks (task_id, file_name, file_path, file_size, status)
      VALUES (?, ?, ?, ?, 'running')
    `).run(taskId, fileName, filePath, fileSize);

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

  let stderr = '';

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
