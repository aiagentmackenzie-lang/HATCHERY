import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DB_PATH = path.join(__dirname, '..', '..', '..', 'data', 'hatchery.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

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
  const schema = fs.readFileSync(SCHEMA_PATH, 'utf-8');
  db.exec(schema);

  return db;
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