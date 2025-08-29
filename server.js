import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import cookieSession from 'cookie-session';
import multer from 'multer';
import { parse } from 'csv-parse/sync';
import { fileURLToPath } from 'url';
import { db, ensureSeed } from './src/db.js';
import { createEvents } from 'ics';

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieSession({
  name: 'shift_portal_session',
  keys: [process.env.SESSION_SECRET || 'dev_key'],
  maxAge: 7 * 24 * 60 * 60 * 1000
}));

const upload = multer({ storage: multer.memoryStorage() });

// Seed demo data
ensureSeed();

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const stmt = db.prepare('SELECT is_admin FROM users WHERE id = ?');
  const row = stmt.get(req.session.userId);
  if (!row || !row.is_admin) return res.status(403).send('Forbidden');
  next();
}

app.get('/', (req, res) => res.redirect(req.session.userId ? '/me/shifts' : '/login'));

app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', (req, res) => {
  const { personal_number, password } = req.body;
  const row = db.prepare('SELECT * FROM users WHERE personal_number = ?').get(personal_number);
  if (!row) return res.status(401).render('login', { error: 'Špatné osobní číslo nebo heslo.' });
  const ok = bcrypt.compareSync(password, row.password_hash);
  if (!ok) return res.status(401).render('login', { error: 'Špatné osobní číslo nebo heslo.' });
  req.session.userId = row.id;
  res.redirect('/me/shifts');
});

app.post('/logout', (req, res) => { req.session = null; res.redirect('/login'); });

app.get('/me/shifts', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const shifts = db.prepare('SELECT * FROM shifts WHERE user_id = ? ORDER BY date, start_time').all(user.id);
  res.render('shifts', { user, shifts });
});

// Admin
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, personal_number, full_name, phone, email FROM users ORDER BY personal_number').all();
  res.render('admin', { users, message: null, error: null });
});

app.post('/admin/add-user', requireAuth, requireAdmin, (req, res) => {
  const { personal_number, full_name, phone, email, password } = req.body;
  try {
    const hash = bcrypt.hashSync(password || personal_number, 10);
    db.prepare('INSERT INTO users (personal_number, full_name, phone, email, password_hash, is_admin) VALUES (?, ?, ?, ?, ?, 0)')
      .run(personal_number.trim(), full_name.trim(), phone.trim(), (email||'').trim(), hash);
    res.redirect('/admin');
  } catch (e) {
    res.status(400).render('admin', { users: db.prepare('SELECT id, personal_number, full_name, phone, email FROM users').all(), message: null, error: e.message });
  }
});

app.post('/admin/import-shifts', requireAuth, requireAdmin, upload.single('csvfile'), (req, res) => {
  try {
    const csv = req.file?.buffer?.toString('utf-8') || '';
    const records = parse(csv, { columns: true, skip_empty_lines: true, trim: true });
    const findUser = db.prepare('SELECT id FROM users WHERE personal_number = ?');
    const ins = db.prepare('INSERT INTO shifts (user_id, date, start_time, end_time, site, role, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now"))');
    const upd = db.prepare('UPDATE shifts SET date=?, start_time=?, end_time=?, site=?, role=?, notes=?, updated_at=datetime("now") WHERE id=?');
    const findExisting = db.prepare('SELECT id FROM shifts WHERE user_id=? AND date=? AND start_time=? AND end_time=?');
    let created = 0, updated = 0, skipped = 0;
    db.transaction(() => {
      for (const r of records) {
        const u = findUser.get(String(r.PersonalNumber).trim());
        if (!u) { skipped++; continue; }
        const ex = findExisting.get(u.id, r.Date, r.Start, r.End);
        if (ex) {
          upd.run(r.Date, r.Start, r.End, r.Site||'', r.Role||'', r.Notes||'', ex.id);
          updated++;
        } else {
          ins.run(u.id, r.Date, r.Start, r.End, r.Site||'', r.Role||'', r.Notes||'');
          created++;
        }
      }
    })();
    res.render('admin', { users: db.prepare('SELECT id, personal_number, full_name, phone, email FROM users').all(), message: `Import hotov: ${created} vytvořeno, ${updated} aktualizováno, ${skipped} přeskočeno.`, error: null });
  } catch (e) {
    res.status(400).render('admin', { users: db.prepare('SELECT id, personal_number, full_name, phone, email FROM users').all(), message: null, error: e.message });
  }
});

// ICS export
app.get('/me/shifts.ics', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const shifts = db.prepare('SELECT * FROM shifts WHERE user_id = ? AND date >= date() ORDER BY date, start_time').all(user.id);
  const events = shifts.map(s => {
    const [Y, M, D] = s.date.split('-').map(n => parseInt(n,10));
    const [sh, sm] = s.start_time.split(':').map(n => parseInt(n,10));
    const [eh, em] = s.end_time.split(':').map(n => parseInt(n,10));
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
