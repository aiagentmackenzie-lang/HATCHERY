import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DB_PATH =
  process.env.HATCHERY_DB_PATH ?? path.join(__dirname, '..', '..', '..', 'data', 'hatchery.db');

/**
 * Locate schema.sql.
 *
 * `tsc` does not copy non-TypeScript assets, so after `npm run build` the
 * schema is not next to the compiled output. Resolve it from the source tree
 * instead of assuming the build layout — the built server otherwise never
 * starts, which is exactly what happened before this existed.
 */
function findSchemaPath(): string {
  const candidates = [
    path.join(__dirname, 'schema.sql'), // tsx / src/db
    path.join(__dirname, '..', '..', 'src', 'db', 'schema.sql'), // dist/db -> src/db
    path.join(process.cwd(), 'src', 'db', 'schema.sql'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(
    `Could not find schema.sql. Looked in:\n  ${candidates.join('\n  ')}`,
  );
}

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (db) return db;

  // Ensure data directory exists
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Run schema on first create
  const schema = fs.readFileSync(findSchemaPath(), 'utf-8');
  db.exec(schema);

  migrate(db);

  return db;
}

/**
 * Additive migrations for databases created before a column existed.
 *
 * `CREATE TABLE IF NOT EXISTS` does not add columns to an existing table, so a
 * database from a previous revision would silently lack them and every insert
 * naming the column would fail at runtime. Check, then ALTER.
 */
function migrate(database: Database.Database): void {
  const sandboxColumns = database
    .prepare('PRAGMA table_info(sandbox_results)')
    .all() as Array<{ name: string }>;
  if (!sandboxColumns.some((c) => c.name === 'evasion_json')) {
    database.exec('ALTER TABLE sandbox_results ADD COLUMN evasion_json TEXT');
  }

  const staticColumns = database
    .prepare('PRAGMA table_info(static_results)')
    .all() as Array<{ name: string }>;
  if (!staticColumns.some((c) => c.name === 'delivery_json')) {
    database.exec('ALTER TABLE static_results ADD COLUMN delivery_json TEXT');
  }
  if (!staticColumns.some((c) => c.name === 'emulation_json')) {
    database.exec('ALTER TABLE static_results ADD COLUMN emulation_json TEXT');
  }
  if (!staticColumns.some((c) => c.name === 'triage_json')) {
    database.exec('ALTER TABLE static_results ADD COLUMN triage_json TEXT');
  }

  // D27: the durable job a task was queued as. `CREATE TABLE IF NOT EXISTS`
  // does not add columns to an existing table, so a database from before the
  // queue would silently lack it and every insert naming it would fail.
  const taskColumns = database
    .prepare('PRAGMA table_info(tasks)')
    .all() as Array<{ name: string }>;
  if (!taskColumns.some((c) => c.name === 'queue_job_id')) {
    database.exec('ALTER TABLE tasks ADD COLUMN queue_job_id TEXT');
  }
  // The index must be created after the column exists, otherwise a database
  // from before the queue fails at schema load with "no such column".
  database.exec('CREATE INDEX IF NOT EXISTS idx_tasks_queue ON tasks(queue_job_id)');
}

export interface TaskRow {
  task_id: string;
  file_name: string;
  file_path: string;
  file_size: number;
  md5: string | null;
  sha1: string | null;
  sha256: string | null;
  status: string;
  static_done: number;
  sandbox_done: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  error_message: string | null;
  queue_job_id: string | null;
}

export interface BehavioralEventRow {
  id: number;
  task_id: string;
  timestamp: string;
  pid: number;
  syscall_name: string;
  category: string;
  severity: string;
  args: string;
  return_value: string;
  raw_line: string;
}

export interface IocRow {
  id: number;
  task_id: string;
  ioc_type: string;
  value: string;
  severity: string;
  context: string | null;
  source: string | null;
}