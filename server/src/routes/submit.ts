import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import { enqueueJob, enqueueStored, requeueJob, RESULTS_ROOT } from '../db/queue.js';
import { storeSampleFromStream, type EnqueueResult } from '../db/queue.js';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import fs from 'fs';

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
 * Where a `filePath` submission may point.
 *
 * `HATCHERY_UPLOADS_DIR` still moves this root, but since D42 **nothing is written
 * to it by the API**: a multipart upload is streamed into the encrypted sample
 * store and never touches a filesystem. The variable survives because a deployment
 * may still keep samples it wants to submit by path on a separate volume, and
 * because the setup gate points it at a temporary root to prove nothing appears
 * there.
 */
const UPLOADS_DIR = process.env.HATCHERY_UPLOADS_DIR
  ? path.resolve(process.env.HATCHERY_UPLOADS_DIR)
  : path.join(ENGINE_ROOT, 'uploads');

/**
 * The status code for an engine refusal, by the engine's own reason code (D42).
 *
 * `too-large` and `empty` are the caller's mistake; `not-found` means the address
 * vanished between storing and queueing; anything else is the engine's state and
 * is a 503. The route never pattern-matches a sentence to decide this.
 */
function refusalStatus(result: EnqueueResult): number {
  switch (result.reason) {
    case 'too-large':
      return 413;
    case 'empty':
      return 400;
    case 'not-found':
      return 410;
    default:
      return 503;
  }
}

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
    /** D42: the content address of a sample that arrived on the wire. */
    let storedSha: string | undefined;

    const taskId = randomUUID().slice(0, 12);

    if (request.isMultipart()) {
      // D42: the body is consumed **as it arrives** and piped straight into the
      // encrypted store. Two defects are fixed by that one change:
      //
      //   1. The API used to stream up to 256 MiB of live malware into
      //      `uploads/<taskId>/` as a PLAINTEXT file — the one place the store's
      //      encryption-at-rest claim was not true.
      //   2. The route collected the file part and piped it *after* the loop, so
      //      busboy's backpressure to an unread part deadlocked the request: a
      //      96 KiB upload answered, 128 KiB never did. Small fixtures answered,
      //      which is exactly how a gate can be green and the feature broken.
      //
      // Nothing here can leave residue: the store writes a blob before any job
      // row exists, so a refusal or a disconnect leaves either a complete blob or
      // nothing — never a partial file under a task directory.
      const parts = request.parts();
      const fields: Record<string, string> = {};
      let truncated = false;

      for await (const part of parts) {
        if (part.type === 'file') {
          if (storedSha !== undefined) {
            // `files: 1` already refuses this; if the plugin is ever reconfigured
            // the route must still not store two samples under one task id.
            return reply.code(413).send({ error: 'files limit reached' });
          }
          if (!part.filename) {
            return reply.code(400).send({ error: 'No file uploaded' });
          }

          const safeName = safeFilename(String(part.filename));
          const stored = await storeSampleFromStream(part.file, {
            jobId: taskId,
            fileName: safeName,
          });

          if (!stored.ok) {
            // Belt and braces: if the plugin is ever configured with
            // `throwFileSizeLimit: false`, the stream ends truncated and the
            // route must still refuse rather than store half a sample.
            if (part.file.truncated) {
              return reply.code(413).send({
                error: 'sample too large',
                limit: MAX_UPLOAD_BYTES,
              });
            }
            const status = refusalStatus(stored);
            return reply.code(status).send({
              error: stored.error ?? 'the sample could not be stored',
              reason: stored.reason,
              ...(stored.limit !== undefined ? { limit: stored.limit } : {}),
            });
          }

          storedSha = stored.sha256!;
          fileName = safeName;
          fileSize = stored.size!;
          truncated = Boolean(part.file.truncated);
        } else if (part.value !== undefined) {
          fields[part.fieldname] = String(part.value);
        }
      }

      if (!storedSha) {
        return reply.code(400).send({ error: 'No file uploaded' });
      }

      // A truncated stream must never become a job. The engine stored the bytes
      // it received, so a blob may exist — a prunable orphan — but the address is
      // not queued, because queueing it would claim a sample HATCHERY never saw in
      // full. This is why the store and the enqueue are two calls: a refusal here
      // cannot leave a job behind.
      if (truncated) {
        return reply.code(413).send({
          error: 'sample too large',
          limit: MAX_UPLOAD_BYTES,
        });
      }

      // The form's options are applied *after* the whole body has been read, so
      // a client may send them before or after the file. That is the other
      // reason the store and the enqueue are two calls.
      if (fields.timeout) timeout = parseInt(fields.timeout, 10) || 120;
      if (fields.noSandbox) noSandbox = fields.noSandbox === 'true';
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

    if (!fileName || fileSize === undefined || (!filePath && !storedSha)) {
      return reply.code(400).send({ error: 'Unable to determine sample file' });
    }

    const db = getDb();
    // The task row is the API's projection; the queue is the source of job
    // state. The job id is aligned with the task id so GET /api/tasks/:id can
    // map one to the other directly.
    //
    // D42: a stream-supplied sample has no path. `file_path` records the store
    // marker (`store:<sha256>`) rather than a plausible-looking path that does
    // not exist, and `sample_store_ref` names the address the worker runs.
    const recordedPath = filePath ?? `store:${storedSha}`;
    db.prepare(`
      INSERT INTO tasks (task_id, file_name, file_path, file_size, status, queue_job_id, sample_store_ref)
      VALUES (?, ?, ?, ?, 'queued', ?, ?)
    `).run(taskId, fileName, recordedPath, fileSize, taskId, storedSha ?? null);

    const outputDir = path.join(RESULTS_ROOT, taskId);
    const enqueued = storedSha
      ? enqueueStored({
          jobId: taskId,
          sha256: storedSha,
          fileName,
          outputDir,
          timeout,
          noSandbox,
        })
      : enqueueJob({
          jobId: taskId,
          filePath: filePath!,
          outputDir,
          timeout,
          noSandbox,
        });
    if (!enqueued.ok) {
      // Fail loudly: a task that was not queued is not "running".
      db.prepare(
        `UPDATE tasks SET status = 'failed', error_message = ?, updated_at = datetime('now')
         WHERE task_id = ?`,
      ).run(enqueued.error ?? 'could not enqueue the job', taskId);
      return reply.code(refusalStatus(enqueued)).send({
        task_id: taskId,
        status: 'failed',
        error: enqueued.error ?? 'could not enqueue the job',
        ...(enqueued.reason ? { reason: enqueued.reason } : {}),
      });
    }

    return reply.send({
      task_id: taskId,
      queue_job_id: enqueued.jobId ?? taskId,
      status: 'queued',
      file_name: fileName,
      file_size: fileSize,
      ...(storedSha ? { sample_store_ref: storedSha } : {}),
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
    // still running under a live lease. D42: the re-queue runs from what the job
    // already records — its store reference, name, output directory and
    // arguments — rather than from `task.file_path`, which a stream-supplied
    // sample does not have and an operator may have deleted. It also stops a
    // retry from silently replacing an emulated or static-only job with a plain
    // one, which the old route did by passing a fresh timeout and noSandbox.
    const enqueued = requeueJob(String(task.queue_job_id ?? taskId));
    if (!enqueued.ok) {
      const status = enqueued.reason === 'not-found' ? 404 : 409;
      return reply.code(status).send({ error: enqueued.error ?? 'could not re-queue the job' });
    }

    db.prepare(
      `UPDATE tasks SET status = 'queued', error_message = NULL, updated_at = datetime('now'),
                        queue_job_id = ?
       WHERE task_id = ?`,
    ).run(enqueued.jobId ?? taskId, taskId);

    return reply.send({ task_id: taskId, status: 'queued', queue_job_id: enqueued.jobId ?? taskId });
  });
}
