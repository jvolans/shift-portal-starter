import { Pool } from 'pg';
import bcrypt from 'bcryptjs';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false
});

export async function migrate() {
  const sql = `
  create table if not exists users (
    id serial primary key,
    personal_number text unique not null,
    full_name text not null default '',
    phone text,
    email text,
    password_hash text not null,
    is_admin boolean not null default false,
    consent_at timestamptz
  );

  create table if not exists shifts (
    id serial primary key,
    user_id integer not null references users(id) on delete cascade,
    date date not null,
    start_time text not null,
    end_time text not null,
    site text,         -- používáme jako "Work Center"
    notes text,
    updated_at timestamptz not null default now()
  );
  create index if not exists idx_shifts_user_date on shifts(user_id, date);

  create table if not exists reset_tokens (
    id serial primary key,
    user_id integer not null references users(id) on delete cascade,
    token text not null unique,
    expires_at timestamptz not null,
    used boolean not null default false,
    created_at timestamptz not null default now()
  );`;
  await pool.query(sql);
}

export async function ensureSeed() {
  const { rows } = await pool.query('select count(*)::int as c from users');
  if (rows[0].c === 0) {
    const h1 = bcrypt.hashSync('49563', 10);
    const h2 = bcrypt.hashSync('39102', 10);
    await pool.query(
      `insert into users (personal_number, full_name, phone, email, password_hash, is_admin, consent_at)
       values
       ($1,$2,$3,$4,$5,true, now()),
       ($6,$7,$8,$9,$10,false, now())`,
      ['49563','Jan Volanský','+420701111111','jan@example.com',h1,
       '39102','Jana Kroutilová','+420702222222','jana@example.com',h2]
    );
    const u1 = await pool.query('select id from users where personal_number=$1',['49563']);
    await pool.query(
      `insert into shifts (user_id,date,start_time,end_time,site,notes) values
       ($1, current_date+1, '06:00','14:00','WC-100',''),
       ($1, current_date+2, '14:00','22:00','WC-200','')`,
      [u1.rows[0].id]
    );
  }
}
