import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';

export async function analysisRoutes(app: FastifyInstance) {
  // NOTE: `POST /api/analyze/static` was removed. It returned a task_id that was
  // never inserted into the database and never analysed — an endpoint that lied.
  // Submit through POST /api/submit with {"noSandbox": true} instead.

  // Get process tree for a task
  app.get('/api/tasks/:taskId/process-tree', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();

    const events = db.prepare(`
      SELECT pid, syscall_name, args, timestamp, category
      FROM behavioral_events
      WHERE task_id = ? AND category = 'process'
      ORDER BY id ASC
    `).all(taskId) as any[];

    // Build process tree from execve/fork/clone events
    const tree = buildProcessTree(events);
    return reply.send(tree);
  });

  // Get network connections for a task
  app.get('/api/tasks/:taskId/network', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();

    const events = db.prepare(`
      SELECT pid, syscall_name, args, return_value, timestamp
      FROM behavioral_events
      WHERE task_id = ? AND category = 'network'
      ORDER BY id ASC
    `).all(taskId) as any[];

    const connections = extractConnections(events);
    return reply.send({ connections, total: connections.length });
  });

  // Get file system changes for a task
  app.get('/api/tasks/:taskId/filesystem', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();

    const events = db.prepare(`
      SELECT pid, syscall_name, args, return_value, timestamp, severity
      FROM behavioral_events
      WHERE task_id = ? AND category = 'file'
      ORDER BY id ASC
    `).all(taskId) as any[];

    return reply.send({ events, total: events.length });
  });
}

interface ProcessNode {
  pid: number;
  children: ProcessNode[];
  syscalls: { name: string; args: string; timestamp: string }[];
}

function buildProcessTree(events: any[]): ProcessNode {
  const procs = new Map<number, ProcessNode>();
  let rootPid = 0;

  for (const ev of events) {
    if (!procs.has(ev.pid)) {
      procs.set(ev.pid, { pid: ev.pid, children: [], syscalls: [] });
    }
    const node = procs.get(ev.pid)!;
    node.syscalls.push({ name: ev.syscall_name, args: ev.args ?? '', timestamp: ev.timestamp });

    // First PID seen is the root.
    if (rootPid === 0) rootPid = ev.pid;

    // NOTE: strace's clone/fork lines do not carry the child pid in a form this
    // parser can read, so the tree here is grouped by pid rather than truly
    // parented. A real parent map needs the `clone(...) = <child pid>` return
    // value parsed at ingest time. Tracked as a known gap.
  }

  return procs.get(rootPid) ?? { pid: 0, children: [], syscalls: [] };
}

interface NetworkConnection {
  timestamp: string;
  pid: number;
  syscall: string;
  dst_addr: string;
  dst_port: number;
  protocol: string;
}

function extractConnections(events: any[]): NetworkConnection[] {
  const connections: NetworkConnection[] = [];

  for (const ev of events) {
    try {
      const args = JSON.parse(ev.args ?? '{}');
      // Accept both the normalised event shape written by the engine's bundle
      // (dst_ip/dst_port) and the older addr/ip keys some callers may send.
      const dstAddr = args.dst_ip ?? args.addr ?? args.ip ?? 'unknown';
      const dstPort = args.dst_port ?? args.port ?? 0;
      connections.push({
        timestamp: ev.timestamp,
        pid: ev.pid,
        syscall: ev.syscall_name,
        dst_addr: dstAddr,
        dst_port: dstPort,
        protocol: args.protocol ?? 'tcp',
      });
    } catch {
      // Malformed args are skipped rather than aborting the whole response.
    }
  }

  return connections;
}