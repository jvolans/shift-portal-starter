// server.js
import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import cookieSession from 'cookie-session';
import multer from 'multer';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import { pool, migrate, ensureSeed } from './src/db.js';
import { createEvents } from 'ics';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieSession({
  name: 'shift_portal_session',
  keys: [process.env.SESSION_SECRET || 'dev_key'],
  maxAge: 7 * 24 * 60 * 60 * 1000
}));

const upload = multer({ storage: multer.memoryStorage() });

// === DB init ===
await migrate();
await ensureSeed();

// === Helpers ===
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}
async function loadUser(req) {
  if (!req.session.userId) return null;
  const { rows } = await pool.query('select * from users where id=$1',[req.session.userId]);
  return rows[0] || null;
}
async function requireAdmin(req, res, next) {
  const u = await loadUser(req);
  if (!u || !u.is_admin) return res.status(403).send('Forbidden');
  next();
}
async function requireConsent(req, res, next) {
  const u = await loadUser(req);
  if (!u) return res.redirect('/login');
  if (!u.is_admin && !u.consent_at) return res.redirect('/consent');
  next();
}

function mailer() {
  if (!process.env.SMTP_HOST) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
  });
}

// === Routes ===
app.get('/', (req, res) => res.redirect(req.session.userId ? '/me/shifts' : '/login'));

// Login / Logout
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', async (req, res) => {
  const { personal_number, password } = req.body;
  const { rows } = await pool.query('select * from users where personal_number=$1',[personal_number]);
  const u = rows[0];
  if (!u || !bcrypt.compareSync(password, u.password_hash)) {
    return res.status(401).render('login', { error: 'Špatné osobní číslo nebo heslo.' });
  }
  req.session.userId = u.id;
  if (!u.is_admin && !u.consent_at) return res.redirect('/consent');
  res.redirect('/me/shifts');
});
app.post('/logout', (req, res) => { req.session = null; res.redirect('/login'); });

// GDPR – zásady + souhlas
app.get('/privacy', (req, res) => res.render('privacy'));
app.get('/consent', requireAuth, async (req, res) => {
  const user = await loadUser(req);
  if (user.consent_at) return res.redirect('/me/shifts');
  res.render('consent');
});
app.post('/consent', requireAuth, async (req, res) => {
  await pool.query('update users set consent_at = now() where id=$1',[req.session.userId]);
  res.redirect('/me/shifts');
});

// Moje směny
app.get('/me/shifts', requireAuth, requireConsent, async (req, res) => {
  const user = await loadUser(req);
  const { rows: shifts } = await pool.query(
    'select * from shifts where user_id=$1 order by date, start_time',[user.id]
  );
  res.render('shifts', { user, shifts });
});

// Profil (změna tel/email)
app.get('/profile', requireAuth, requireConsent, async (req, res) => {
  const user = await loadUser(req);
  res.render('profile', { user, message: null, error: null });
});
app.post('/profile', requireAuth, requireConsent, async (req, res) => {
  const { phone, email } = req.body;
  try {
    await pool.query('update users set phone=$1, email=$2 where id=$3', [(phone||'').trim(), (email||'').trim(), req.session.userId]);
    const user = await loadUser(req);
    res.render('profile', { user, message: 'Uloženo.', error: null });
  } catch (e) {
    const user = await loadUser(req);
    res.render('profile', { user, message: null, error: e.message });
  }
});

// Změna hesla (přihlášený)
app.post('/profile/change-password', requireAuth, requireConsent, async (req, res) => {
  const { current_password, new_password } = req.body;
  const user = await loadUser(req);
  if (!bcrypt.compareSync(current_password, user.password_hash)) {
    return res.status(400).render('profile', { user, message: null, error: 'Aktuální heslo nesouhlasí.' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  await pool.query('update users set password_hash=$1 where id=$2', [hash, user.id]);
  res.render('profile', { user: await loadUser(req), message: 'Heslo změněno.', error: null });
});

// Zapomenuté heslo
app.get('/forgot', (req, res) => res.render('forgot', { message: null, error: null }));
app.post('/forgot', async (req, res) => {
  const { personal_number, email } = req.body;
  let user = null;
  if (personal_number) user = (await pool.query('select * from users where personal_number=$1',[personal_number])).rows[0];
  if (!user && email) user = (await pool.query('select * from users where email=$1',[email])).rows[0];
  if (!user) return res.status(400).render('forgot', { message: null, error: 'Uživatel nenalezen.' });

  const token = crypto.randomBytes(24).toString('hex');
  const expires = new Date(Date.now() + 1000*60*30); // 30 min
  await pool.query('insert into reset_tokens (user_id, token, expires_at) values ($1,$2,$3)', [user.id, token, expires]);

  const link = `${req.protocol}://${req.get('host')}/reset/${token}`;
  const tx = mailer();
  if (tx && user.email) {
    await tx.sendMail({
      from: process.env.SMTP_FROM || 'noreply@example.com',
      to: user.email,
      subject: 'Obnova hesla – Směny',
      text: `Klikni pro nastavení nového hesla: ${link}`,
      html: `Klikni pro nastavení nového hesla: <a href="${link}">${link}</a>`
    });
    return res.render('forgot', { message: 'Odkaz byl odeslán na tvůj e-mail.', error: null });
  } else {
    // Dev fallback: ukážeme link přímo (když není SMTP)
    return res.render('forgot', { message: `Reset odkaz: ${link}`, error: null });
  }
});
app.get('/reset/:token', async (req, res) => {
  const { rows } = await pool.query('select * from reset_tokens where token=$1 and used=false and expires_at>now()',[req.params.token]);
  if (!rows[0]) return res.status(400).send('Neplatný nebo prošlý odkaz.');
  res.render('reset', { token: req.params.token, error: null, message: null });
});
app.post('/reset/:token', async (req, res) => {
  const { rows } = await pool.query('select * from reset_tokens where token=$1 and used=false and expires_at>now()',[req.params.token]);
  const t = rows[0];
  if (!t) return res.status(400).send('Neplatný nebo prošlý odkaz.');
  const hash = bcrypt.hashSync(req.body.new_password, 10);
  await pool.query('update users set password_hash=$1 where id=$2', [hash, t.user_id]);
  await pool.query('update reset_tokens set used=true where id=$1', [t.id]);
  res.render('reset', { token: null, message: 'Heslo nastaveno. Můžeš se přihlásit.', error: null });
});

// Admin
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
  const { rows: users } = await pool.query('select id, personal_number, full_name, phone, email from users order by personal_number');
  res.render('admin', { users, message: null, error: null });
});
app.post('/admin/add-user', requireAuth, requireAdmin, async (req, res) => {
  const { personal_number, full_name, phone, email, password } = req.body;
  try {
    const hash = bcrypt.hashSync(password || personal_number, 10);
    await pool.query('insert into users (personal_number, full_name, phone, email, password_hash, is_admin) values ($1,$2,$3,$4,$5,false)', [personal_number.trim(), full_name.trim(), (phone||'').trim(), (email||'').trim(), hash]);
    res.redirect('/admin');
  } catch (e) {
    const { rows: users } = await pool.query('select id, personal_number, full_name, phone, email from users order by personal_number');
    res.status(400).render('admin', { users, message: null, error: e.message });
  }
});
app.post('/admin/import-shifts', requireAuth, requireAdmin, upload.single('csvfile'), async (req, res) => {
  try {
    const csv = req.file?.buffer?.toString('utf-8') || '';
    const records = parse(csv, { columns: true, skip_empty_lines: true, trim: true });
    let created=0, updated=0, skipped=0;
    await pool.query('begin');
    try {
      for (const r of records) {
        const u = (await pool.query('select id from users where personal_number=$1',[String(r.PersonalNumber).trim()])).rows[0];
        if (!u) { skipped++; continue; }
        const ex = (await pool.query('select id from shifts where user_id=$1 and date=$2 and start_time=$3 and end_time=$4',[u.id, r.Date, r.Start, r.End])).rows[0];
        if (ex) {
          await pool.query('update shifts set date=$1,start_time=$2,end_time=$3,site=$4,role=$5,notes=$6,updated_at=now() where id=$7',
            [r.Date, r.Start, r.End, r.Site||'', r.Role||'', r.Notes||'', ex.id]);
          updated++;
        } else {
          await pool.query('insert into shifts (user_id,date,start_time,end_time,site,role,notes) values ($1,$2,$3,$4,$5,$6,$7)',
            [u.id, r.Date, r.Start, r.End, r.Site||'', r.Role||'', r.Notes||'']);
          created++;
        }
      }
      await pool.query('commit');
    } catch (e) {
      await pool.query('rollback');
      throw e;
    }
    const { rows: users } = await pool.query('select id, personal_number, full_name, phone, email from users order by personal_number');
    res.render('admin', { users, message: `Import hotov: vytvořeno ${created}, aktualizováno ${updated}, přeskočeno ${skipped}.`, error: null });
  } catch (e) {
    const { rows: users } = await pool.query('select id, personal_number, full_name, phone, email from users order by personal_number');
    res.status(400).render('admin', { users, message: null, error: e.message });
  }
});

// ICS export
app.get('/me/shifts.ics', requireAuth, requireConsent, async (req, res) => {
  const user = await loadUser(req);
  const { rows: shifts } = await pool.query('select * from shifts where user_id=$1 and date>=current_date order by date, start_time',[user.id]);
  const events = shifts.map(s => {
    const d = new Date(s.date);
    const Y = d.getUTCFullYear(), M = d.getUTCMonth()+1, D = d.getUTCDate();
    const [sh, sm] = s.start_time.split(':').map(Number);
    const [eh, em] = s.end_time.split(':').map(Number);
    return {
      title: `Směna ${s.role || ''} (${s.site || ''})`.trim(),
      description: s.notes || '',
      location: s.site || '',
      start: [Y, M, D, sh, sm],
      end: [Y, M, D, eh, em]
    };
  });
  createEvents(events, (error, value) => {
    if (error) return res.status(500).send('ICS error');
    res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="moje-směny.ics"');
    res.send(value);
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Shift portal listening on :' + port));
