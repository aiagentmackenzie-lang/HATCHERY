import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import { submitRoutes } from './routes/submit.js';
import { statusRoutes } from './routes/status.js';
import { reportRoutes } from './routes/report.js';
import { iocRoutes } from './routes/iocs.js';
import { analysisRoutes } from './routes/analysis.js';
import { getDb } from './db/index.js';

const PORT = parseInt(process.env.HATCHERY_PORT ?? '3002', 10);
const HOST = process.env.HATCHERY_HOST ?? '0.0.0.0';

const app = Fastify({ logger: false });

// Initialize DB on startup
getDb();

// CORS for dashboard
app.register(cors, { origin: true });

// REST routes
app.register(submitRoutes);
app.register(statusRoutes);
app.register(reportRoutes);
app.register(iocRoutes);
app.register(analysisRoutes);

// WebSocket for real-time behavioral event streaming
app.register(websocket);

app.register(async function (fastify) {
  fastify.get('/ws', { websocket: true }, (connection: any, req: any) => {
    // Send welcome
    connection.socket.send(JSON.stringify({
      type: 'connected',
      message: 'HATCHERY real-time event stream',
    }));

    // Client can subscribe to a task's events
    connection.socket.on('message', (message: Buffer) => {
      try {
        const msg = JSON.parse(message.toString());

        if (msg.type === 'subscribe' && msg.task_id) {
          // Mark this connection as subscribed to a task
          (connection as any)._hatcheryTaskId = msg.task_id;

          // Send existing events for this task
          const db = getDb();
          const events = db.prepare(`
            SELECT * FROM behavioral_events WHERE task_id = ? ORDER BY id ASC
          `).all(msg.task_id);

          connection.socket.send(JSON.stringify({
            type: 'events_batch',
            task_id: msg.task_id,
            events,
            total: events.length,
          }));
        }

        if (msg.type === 'ping') {
          connection.socket.send(JSON.stringify({ type: 'pong' }));
        }
      } catch {
        // Ignore malformed messages
      }
    });

    connection.socket.on('close', () => {
      // Cleanup
    });
  });
});

// Health check
app.get('/api/health', async () => {
  return { status: 'ok', service: 'hatchery-api', version: '0.1.0' };
});

// Start
app.listen({ port: PORT, host: HOST }, (err) => {
  if (err) {
    console.error('Failed to start:', err);
    process.exit(1);
  }
  console.log(`🔥 HATCHERY API running on http://${HOST}:${PORT}`);
  console.log(`   WebSocket:    ws://${HOST}:${PORT}/ws`);
  console.log(`   Dashboard:    http://localhost:5173 (run: cd dashboard && npm run dev)`);
});