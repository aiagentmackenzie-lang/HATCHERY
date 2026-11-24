import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import { enqueueJob, RESULTS_ROOT } from '../db/queue.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import fs from 'fs';
import { pipeline } from 'stream/promises';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_ROOT = path.join(__dirname, '..', '..', '..');

/**
 * The largest sample the API accepts, in bytes.
 *
 * This is the engine's own intake limit (`DEFAULT_MAX_SAMPLE_BYTES` in
 * `engine/store/store.py`: 256 MiB). The two numbers are asserted equal in
 * `test/upload_limit.test.mjs`, because two limits that disagree is how a
 * 100 MiB sample becomes "refused by the API, accepted by the engine" — and a
 * limit nobody can state is not a limit.
 */
export const MAX_UPLOAD_BYTES = 256 * 1024 * 1024;

/**
 * Where multipart uploads land before the worker reads them.
 *
 * `HATCHERY_UPLOADS_DIR` exists so a test (and an operator with a separate
 * volume) can move it without touching the checkout: a refused upload must be
 * provably absent from the directory, and a test that writes into the repo
 * cannot prove that.
 */
const UPLOADS_DIR = process.env.HATCHERY_UPLOADS_DIR
  ? path.resolve(process.env.HATCHERY_UPLOADS_DIR)
  : path.join(ENGINE_ROOT, 'uploads');

/**
 * Roots a caller may point `filePath` at.
 *
 * Previously any absolute path on the host was accepted, which turned the
 * submission endpoint into a reader for arbitrary local files: submit
 * /etc/shadow, then fetch the report and read the extracted strings. A security
 * tool must not offer that. Override with HATCHERY_ALLOWED_SAMPLE_ROOTS
 * (colon-separated) if you have a different intake directory.
 */
/**
 * Canonicalise a path for comparison.
 *
 * macOS checkouts under /tmp are reached through the /private/tmp symlink, and
 * a user may legitimately submit through a symlinked path. Comparing unresolved
 * strings made the allowed-root check reject the same file it should accept, so
 * resolve symlinks on both sides before comparing.
 */
function canonicalPath(candidate: string): string {
  try {
    return fs.realpathSync.native(candidate);
  } catch {
    try {
      return path.join(fs.realpathSync.native(path.dirname(candidate)), path.basename(candidate));
    } catch {
      return path.resolve(candidate);
    }
  }
}

function allowedSampleRoots(): string[] {
  const configured = process.env.HATCHERY_ALLOWED_SAMPLE_ROOTS;
  if (configured) {
    return configured.split(path.delimiter).filter(Boolean).map(canonicalPath);
  }
  return [path.join(ENGINE_ROOT, 'samples'), UPLOADS_DIR].map(canonicalPath);
}

function isAllowedSamplePath(candidate: string): boolean {
  const resolved = canonicalPath(candidate);
  return allowedSampleRoots().some(
    (root) => resolved === root || resolved.startsWith(root + path.sep),
  );
}

// Bytes, not characters: the filesystem limit is NAME_MAX bytes, and a name of
// 120 emoji is 480 bytes. Well below 255 so the write can never be the thing
// that fails a submission.
export const MAX_FILENAME_BYTES = 200;

/**
 * Reduce a client-supplied filename to a bare, bounded name.
 *
 * `path.join(dir, "../../etc/passwd")` escapes `dir`; busboy hands over the raw
 * client filename. Strip any directory component and any traversal segments,
 * then bound the length in bytes.
 */

export function safeFilename(name: string): string {
  const base = path.basename(name.replace(/\\/g, '/'));
  const cleaned = base.replace(/[^\w.\- ]+/g, '_').replace(/^\.+/, '');
  if (!cleaned) return `sample-${randomUUID().slice(0, 8)}`;
  if (Buffer.byteLength(cleaned) <= MAX_FILENAME_BYTES) return cleaned;
  // Keep the extension: the engine still uses it as a hint, and a name cut to
  // the limit that happens to lose ".doc" is a worse lie than a shorter stem.
  const extension = path.extname(cleaned).slice(0, 16);
  let stem = cleaned.slice(0, cleaned.length - extension.length).replace(/\.+$/, '');
  while (stem.length > 1 && Buffer.byteLength(stem + extension) > MAX_FILENAME_BYTES) {
    stem = stem.slice(0, -1);
  }
  return `${stem || 'sample'}${extension}`;
}

export async function submitRoutes(app: FastifyInstance) {
  // Submit a sample for analysis (JSON filePath or multipart file upload)
  app.post('/api/submit', async (request: any, reply: any) => {
    let filePath: string | undefined;
    let fileName: string | undefined;
    let fileSize: number | undefined;
    let timeout = 120;
    let noSandbox = false;

    const taskId = randomUUID().slice(0, 12);

    if (request.isMultipart()) {
      // PhishHawk-style multipart upload: iterate parts to find file + fields
      const parts = request.parts();
      let uploadedFile: any = null;
      const fields: Record<string, string> = {};
      const taskUploadDir = path.join(UPLOADS_DIR, taskId);

      // Any failure in here — the size limit, a client disconnect, a busboy
      // error — must leave nothing behind. Before this, a refused upload left
      // the partial file and its directory on disk for every request.
      try {
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

        // One task id, used for the upload directory AND the database row. The
        // previous revision generated two, so the uploaded file lived in a
        // directory named after a task that did not exist.
        const safeName = safeFilename(String(uploadedFile.filename));
        fs.mkdirSync(taskUploadDir, { recursive: true });
        filePath = path.join(taskUploadDir, safeName);

        await pipeline(uploadedFile.file, fs.createWriteStream(filePath));

        // Belt and braces: if the plugin is ever configured with
        // `throwFileSizeLimit: false`, the stream ends truncated and the route
        // must still refuse rather than store half a sample.
        if (uploadedFile.file.truncated) {
          fs.rmSync(taskUploadDir, { recursive: true, force: true });
          return reply.code(413).send({
            error: 'sample too large',
            limit: MAX_UPLOAD_BYTES,
          });
        }

        const stats = fs.statSync(filePath);
        fileName = safeName;
        fileSize = stats.size;
      } catch (error) {
        fs.rmSync(taskUploadDir, { recursive: true, force: true });
        throw error;
      }
    } else {
      const body = request.body ?? {};
      filePath = body.filePath;
      timeout = body.timeout ?? 120;
      noSandbox = body.noSandbox ?? false;

      if (!filePath) {
        return reply.code(400).send({ error: 'filePath is required' });
      }

      if (!path.isAbsolute(filePath)) {
        filePath = path.resolve(ENGINE_ROOT, filePath);
      }

      if (!isAllowedSamplePath(filePath)) {
        return reply.code(403).send({
          error: 'filePath is outside the permitted sample roots',
          allowed_roots: allowedSampleRoots(),
        });
      }
      // Hand the worker the canonical path, so it reads the file that was
      // actually validated rather than a symlink alias.
      filePath = canonicalPath(filePath);

      if (!fs.existsSync(filePath)) {
        return reply.code(404).send({ error: 'File not found', path: filePath });
      }

      const stats = fs.statSync(filePath);
      // Refuse before enqueueing. The worker would refuse it too (D40), but a
      // task that is queued only to fail is a worse answer than a 413: the
      // caller learns the reason now, and nothing is written.
      if (stats.size > MAX_UPLOAD_BYTES) {
        return reply.code(413).send({
          error: 'sample too large',
          limit: MAX_UPLOAD_BYTES,
          size: stats.size,
        });
      }
      fileName = path.basename(filePath);
      fileSize = stats.size;
    }

    if (!filePath || !fileName || fileSize === undefined) {
      return reply.code(400).send({ error: 'Unable to determine sample file' });
    }

    const db = getDb();
    // The task row is the API's projection; the queue is the source of job
    // state. The job id is aligned with the task id so GET /api/tasks/:id can
    // map one to the other directly.
    db.prepare(`
      INSERT INTO tasks (task_id, file_name, file_path, file_size, status, queue_job_id)
      VALUES (?, ?, ?, ?, 'queued', ?)
    `).run(taskId, fileName, filePath, fileSize, taskId);

    const enqueued = enqueueJob({
      jobId: taskId,
      filePath,
      outputDir: path.join(RESULTS_ROOT, taskId),
      timeout,
      noSandbox,
    });
    if (!enqueued.ok) {
      // Fail loudly: a task that was not queued is not "running".
      db.prepare(
        `UPDATE tasks SET status = 'failed', error_message = ?, updated_at = datetime('now')
         WHERE task_id = ?`,
      ).run(enqueued.error ?? 'could not enqueue the job', taskId);
      return reply.code(503).send({
        task_id: taskId,
        status: 'failed',
        error: enqueued.error ?? 'could not enqueue the job',
      });
    }

    return reply.send({
      task_id: taskId,
      queue_job_id: enqueued.jobId ?? taskId,
      status: 'queued',
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

    // Re-queue rather than spawn: the queue refuses to touch a job that is
    // still running under a live lease.
    const enqueued = enqueueJob({
      jobId: taskId,
      filePath: task.file_path,
      outputDir: path.join(RESULTS_ROOT, taskId),
      timeout: 120,
      noSandbox: false,
      requeue: true,
    });
    if (!enqueued.ok) {
      return reply.code(409).send({ error: enqueued.error ?? 'could not re-queue the job' });
    }

    db.prepare(
      `UPDATE tasks SET status = 'queued', error_message = NULL, updated_at = datetime('now'),
                        queue_job_id = ?
       WHERE task_id = ?`,
    ).run(enqueued.jobId ?? taskId, taskId);

    return reply.send({ task_id: taskId, status: 'queued', queue_job_id: enqueued.jobId ?? taskId });
  });
}
