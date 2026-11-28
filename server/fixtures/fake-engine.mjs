#!/usr/bin/env node
/**
 * A stand-in for the engine CLI, for the server's own unit tests (D42).
 *
 * `npm test` runs in CI's `server-gate`, which has no Python and no engine
 * installed — that job's job is to test the API, not the analysis pipeline. The
 * upload route now shells out to the engine to **store a streamed sample** and
 * then to **queue the address**, so without a stand-in the upload tests would
 * either silently invoke a real engine (green locally, red in CI) or be skipped
 * (a gate that proves nothing).
 *
 * So this script implements exactly the contract the route depends on, and
 * nothing else:
 *
 *   store put --stdin --json  → read stdin, print one JSON object with an address
 *   submit --from-store … --enqueue → print one JSON object with the job id
 *   queue <id> --requeue --json     → print one JSON object with the job id
 *
 * A fixed address is deliberate: the test asserts the *plumbing* (bytes arrive,
 * an address comes back, nothing lands under `uploads/`, the task records the
 * reference), not the cryptography — which the engine's own suite proves against
 * a real store. `verify_setup.sh` runs the same path with the real engine.
 */

import { createHash } from 'node:crypto';

/** The address the stub claims, over the bytes it received. */
function address(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function argValue(flag, fallback = '') {
  const index = process.argv.indexOf(flag);
  return index !== -1 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const command = process.argv.slice(2).join(' ');

// D43's admission tests prove a refusal happens *before the body is read* by
// asserting this log did not grow: no log entry means the engine was never asked
// to store anything, which is the only honest way to show the byte quota ran
// ahead of the read rather than after it.
if (process.env.HATCHERY_TEST_ENGINE_LOG) {
  const { appendFileSync } = await import('node:fs');
  appendFileSync(process.env.HATCHERY_TEST_ENGINE_LOG, `${command}\n`);
}

if (command.includes('store put')) {
  const bytes = await readStdin();
  if (bytes.length === 0) {
    // The real engine refuses an empty sample on stderr and exits 1; the route
    // must translate that into a 400 rather than a 500.
    process.stderr.write(JSON.stringify({ ok: false, reason: 'empty', message: 'refusing to store an empty sample' }) + '\n');
    process.exit(1);
  }
  process.stdout.write(
    JSON.stringify({
      ok: true,
      sha256: address(bytes),
      size: bytes.length,
      blob: `${address(bytes)}.sample`,
      encrypted: true,
    }) + '\n',
  );
} else if (command.includes('submit') && command.includes('--enqueue')) {
  process.stdout.write(
    JSON.stringify({
      ok: true,
      job_id: argValue('--job-id', 'stub-job'),
      status: 'queued',
      sample_path: `store:${argValue('--from-store')}`,
      sample_store_ref: argValue('--from-store'),
      sample_name: argValue('--name'),
    }) + '\n',
  );
} else if (command.includes('queue') && command.includes('--requeue')) {
  const args = process.argv.slice(2);
  const jobId = args[args.indexOf('queue') + 1] ?? 'stub-job';
  process.stdout.write(JSON.stringify({ ok: true, job_id: jobId }) + '\n');
} else {
  process.stderr.write(`fake engine: unsupported invocation: ${command}\n`);
  process.exit(2);
}
