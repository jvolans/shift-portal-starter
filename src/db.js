import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const dbPath = path.join(__dirname, '..', 'data.sqlite');
const db = new Database(dbPath);

db.exec(`
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    personal_number TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT,
    email TEXT,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    site TEXT,
    role TEXT,
    notes TEXT,
    updated_at TEXT NOT NULL
  );
`);

export function ensureSeed() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (count === 0) {
    const hash1 = bcrypt.hashSync('49563', 10);
    const hash2 = bcrypt.hashSync('39102', 10);
    db.prepare('INSERT INTO users (personal_number, full_name, phone, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, 1)').run('49563', 'Jan Volanský', '+420701111111', 'jan@example.com', hash1);
    db.prepare('INSERT INTO users (personal_number, full_name, phone, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, 0)').run('39102', 'Jana Kroutilová', '+420702222222', 'jana@example.com', hash2);
    db.prepare('INSERT INTO shifts (user_id, date, start_time, end_time, site, role, notes, updated_at) VALUES (1, date("now","+1 day"), "06:00", "14:00", "Provoz A", "Kuchyň", "", datetime("now"))').run();
    db.prepare('INSERT INTO shifts (user_id, date, start_time, end_time, site, role, notes, updated_at) VALUES (1, date("now","+2 day"), "14:00", "22:00", "Provoz B", "Pokladna", "", datetime("now"))').run();
  }
}

export { db };
