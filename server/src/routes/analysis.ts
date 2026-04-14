import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';

export async function analysisRoutes(app: FastifyInstance) {
  // Run static-only analysis (no sandbox)
  app.post('/api/analyze/static', async (request: any, reply: any) => {
    const { filePath } = request.body ?? {};
    if (!filePath) {
      return reply.code(400).send({ error: 'filePath is required' });
    }

    const db = getDb();
    const taskId = crypto.randomUUID().slice(0, 12);

    // TODO: spawn static analysis subprocess
    // For now, return task placeholder
    return reply.send({
      task_id: taskId,
      status: 'pending',
      analysis_type: 'static',
    });
  });

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

    // First PID seen is root
    if (rootPid === 0) rootPid = ev.pid;

    // execve with new PID = child process
    if (ev.syscall_name === 'clone' || ev.syscall_name === 'fork') {
      try {
        const args = JSON.parse(ev.args ?? '{}');
        const childPid = args.child_pid ?? args.pid;
        if (childPid && !procs.has(childPid)) {
          const child: ProcessNode = { pid: childPid, children: [], syscalls: [] };
          procs.set(childPid, child);
          node.children.push(child);
        }
      } catch { /* ignore parse errors */ }
    }
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
    if (ev.syscall_name === 'connect') {
      try {
        const args = JSON.parse(ev.args ?? '{}');
        connections.push({
          timestamp: ev.timestamp,
          pid: ev.pid,
          syscall: 'connect',
          dst_addr: args.addr ?? args.ip ?? 'unknown',
          dst_port: args.port ?? 0,
          protocol: args.protocol ?? 'tcp',
        });
      } catch { /* skip */ }
    }
  }

  return connections;
}