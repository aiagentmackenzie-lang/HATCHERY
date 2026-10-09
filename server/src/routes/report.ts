import { FastifyInstance } from 'fastify';
import { getDb } from '../db/index.js';
import fs from 'fs';
import path from 'path';

export async function reportRoutes(app: FastifyInstance) {
  // Get full analysis report
  app.get('/api/tasks/:taskId/report', async (request: any, reply: any) => {
    const { taskId } = request.params as { taskId: string };
    const db = getDb();

    const task = db.prepare('SELECT * FROM tasks WHERE task_id = ?').get(taskId) as any;
    if (!task) {
      return reply.code(404).send({ error: 'Task not found' });
    }

    const staticResults = db.prepare('SELECT * FROM static_results WHERE task_id = ?').get(taskId) as any;
    const sandboxResults = db.prepare('SELECT * FROM sandbox_results WHERE task_id = ?').get(taskId) as any;
    const iocs = db.prepare('SELECT * FROM iocs WHERE task_id = ? ORDER BY severity DESC, ioc_type').all(taskId) as any[];
    const eventCounts = db.prepare(`
      SELECT category, COUNT(*) as count FROM behavioral_events WHERE task_id = ? GROUP BY category
    `).all(taskId) as any[];

    // Build report
    const report: any = {
      task_id: taskId,
      file_name: task.file_name,
      file_size: task.file_size,
      hashes: {
        md5: task.md5,
        sha1: task.sha1,
        sha256: task.sha256,
      },
      status: task.status,
      created_at: task.created_at,
      completed_at: task.completed_at,
      static_analysis: null,
      sandbox_analysis: null,
      iocs,
      event_summary: eventCounts,
    };

    if (staticResults) {
      report.static_analysis = {
        strings: safeJsonParse(staticResults.strings_json),
        pe: safeJsonParse(staticResults.pe_json),
        elf: safeJsonParse(staticResults.elf_json),
        yara: safeJsonParse(staticResults.yara_json),
        capa: safeJsonParse(staticResults.capa_json),
        packer: safeJsonParse(staticResults.packer_json),
        delivery: safeJsonParse(staticResults.delivery_json),
        mitre: safeJsonParse(staticResults.mitre_json),
      };
    }

    if (sandboxResults) {
      report.sandbox_analysis = {
        status: sandboxResults.status,
        exit_code: sandboxResults.exit_code,
        duration_seconds: sandboxResults.duration_seconds,
        error: sandboxResults.error_message,
        evasion: safeJsonParse(sandboxResults.evasion_json),
      };
    }

    const { format = 'json' } = request.query as any;

    if (format === 'markdown') {
      reply.type('text/markdown');
      return reply.send(generateMarkdown(report));
    }

    if (format === 'stix') {
      // Check if STIX bundle exists on disk
      const stixPath = path.join('results', taskId, 'stix_bundle.json');
      if (fs.existsSync(stixPath)) {
        const stix = JSON.parse(fs.readFileSync(stixPath, 'utf-8'));
        return reply.send(stix);
      }
      return reply.code(404).send({ error: 'STIX bundle not found' });
    }

    if (format === 'navigator') {
      const navigatorPath = path.join('results', taskId, 'attack-navigator.json');
      if (fs.existsSync(navigatorPath)) {
        return reply.send(JSON.parse(fs.readFileSync(navigatorPath, 'utf-8')));
      }
      return reply.code(404).send({ error: 'ATT&CK Navigator layer not found' });
    }

    if (format === 'ocsf') {
      const ocsfPath = path.join('results', taskId, 'ocsf.json');
      if (fs.existsSync(ocsfPath)) {
        return reply.send(JSON.parse(fs.readFileSync(ocsfPath, 'utf-8')));
      }
      return reply.code(404).send({ error: 'OCSF findings not found' });
    }

    return reply.send(report);
  });
}

function safeJsonParse(str: string | null | undefined): any {
  if (!str) return null;
  try { return JSON.parse(str); } catch { return null; }
}

function generateMarkdown(report: any): string {
  const lines: string[] = [];
  lines.push(`# HATCHERY Analysis Report`);
  lines.push(``);
  lines.push(`**Task ID:** ${report.task_id}`);
  lines.push(`**File:** ${report.file_name} (${report.file_size} bytes)`);
  lines.push(`**Status:** ${report.status}`);
  lines.push(`**Created:** ${report.created_at}`);
  if (report.completed_at) lines.push(`**Completed:** ${report.completed_at}`);
  lines.push(``);

  if (report.hashes?.sha256) {
    lines.push(`## Hashes`);
    lines.push(``);
    lines.push(`| Algorithm | Value |`);
    lines.push(`|-----------|-------|`);
    if (report.hashes.md5) lines.push(`| MD5 | \`${report.hashes.md5}\` |`);
    if (report.hashes.sha1) lines.push(`| SHA1 | \`${report.hashes.sha1}\` |`);
    lines.push(`| SHA256 | \`${report.hashes.sha256}\` |`);
    lines.push(``);
  }

  if (report.static_analysis?.yara?.matches?.length) {
    lines.push(`## YARA Matches`);
    lines.push(``);
    for (const m of report.static_analysis.yara.matches) {
      lines.push(`- **${m.rule}**: ${m.meta?.description ?? 'N/A'}`);
    }
    lines.push(``);
  }

  if (report.static_analysis?.capa?.capabilities?.length) {
    lines.push(`## Capabilities (capa)`);
    lines.push(``);
    for (const c of report.static_analysis.capa.capabilities) {
      lines.push(`- **${c.name}** (${c.namespace})`);
    }
    lines.push(``);
  }

  if (report.static_analysis?.delivery?.format && report.static_analysis.delivery.format !== 'unknown') {
    const d = report.static_analysis.delivery;
    lines.push(`## Delivery Format`);
    lines.push(``);
    lines.push(`**Format:** \`${d.format}\`${d.format_detail ? ` — ${d.format_detail}` : ''}`);
    if (d.flags?.length) {
      lines.push(`**Flags:** ${d.flags.map((f: string) => `\`${f}\``).join(', ')}`);
    }
    if (d.children?.length) {
      lines.push(``);
      lines.push(`### Extracted files (${d.children.length})`);
      lines.push(``);
      lines.push(`| File | Size | Format | Flags |`);
      lines.push(`|---|---:|---|---|`);
      for (const child of d.children) {
        lines.push(
          `| \`${child.name}\` | ${child.size} | ${child.format} | ` +
          `${(child.flags ?? []).join(', ') || '-'} |`,
        );
      }
    }
    if (d.unsupported?.length) {
      lines.push(``);
      lines.push(`**Detected but not extracted:**`);
      lines.push(``);
      for (const item of d.unsupported) {
        lines.push(`- \`${item.path}\` (${item.format}) — ${item.reason}`);
      }
    }
    lines.push(``);
  }

  if (report.sandbox_analysis?.evasion) {
    const ev = report.sandbox_analysis.evasion;
    lines.push(`## Evasion Assessment`);
    lines.push(``);
    lines.push(`**Score:** ${ev.score}/100 — **${String(ev.verdict ?? 'none').toUpperCase()}**`);
    if (ev.inconclusive) {
      lines.push(``);
      lines.push(`> **INCONCLUSIVE (evasive):** the sample reconnoitered and then exited without observable impact. This is not a clean result.`);
    }
    lines.push(``);
    lines.push(`| Signal | Severity | Count |`);
    lines.push(`|--------|:--:|--:|`);
    for (const f of ev.findings ?? []) {
      lines.push(`| \`${f.signal}\` | ${f.severity} | ${f.count} |`);
    }
    lines.push(``);
  }

  if (report.iocs?.length) {
    lines.push(`## IOCs`);
    lines.push(``);
    lines.push(`| Type | Value | Severity | Source |`);
    lines.push(`|------|-------|----------|--------|`);
    for (const ioc of report.iocs) {
      lines.push(`| ${ioc.ioc_type} | \`${ioc.value}\` | ${ioc.severity} | ${ioc.source ?? '-'} |`);
    }
    lines.push(``);
  }

  if (report.event_summary?.length) {
    lines.push(`## Behavioral Events`);
    lines.push(``);
    lines.push(`| Category | Count |`);
    lines.push(`|----------|-------|`);
    for (const e of report.event_summary) {
      lines.push(`| ${e.category} | ${e.count} |`);
    }
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(`*Generated by HATCHERY — Watch it hatch. Watch it burn.*`);
  return lines.join('\n');
}