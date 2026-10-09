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
      SELECT pid, syscall_name, args, return_value, timestamp, category
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

export interface ProcessNode {
  pid: number;
  children: ProcessNode[];
  syscalls: { name: string; args: string; timestamp: string }[];
}

export function buildProcessTree(events: any[]): ProcessNode {
  const info = new Map<number, ProcessNode>();
  const parentOf = new Map<number, number>();
  const order: number[] = [];
  const CLONE = new Set(['clone', 'fork', 'vfork', 'clone3']);

  for (const ev of events) {
    if (!info.has(ev.pid)) {
      info.set(ev.pid, { pid: ev.pid, children: [], syscalls: [] });
      order.push(ev.pid);
    }
    info.get(ev.pid)!.syscalls.push({
      name: ev.syscall_name,
      args: ev.args ?? '',
      timestamp: ev.timestamp,
    });

    // strace renders a successful clone as `clone(...) = <child pid>`. The
    // engine stores that return value, so the parent map can be built here —
    // this is what turns the PID-grouped view into a real process tree.
    if (CLONE.has(ev.syscall_name)) {
      const child = Number.parseInt(String(ev.return_value ?? '').trim(), 10);
      if (Number.isInteger(child) && child > 0 && child !== ev.pid) {
        parentOf.set(child, ev.pid);
      }
    }
  }

  // Root is the earliest process that was never itself a clone child.
  const rootPid = order.find((pid) => !parentOf.has(pid)) ?? order[0];
  if (rootPid === undefined) return { pid: 0, children: [], syscalls: [] };

  const visited = new Set<number>();
  const attach = (pid: number): ProcessNode => {
    visited.add(pid);
    const node = info.get(pid) ?? { pid, children: [], syscalls: [] };
    node.children = order
      .filter((child) => parentOf.get(child) === pid && !visited.has(child))
      .map((child) => attach(child));
    return node;
  };

  return attach(rootPid);
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