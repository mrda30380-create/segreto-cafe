const express = require('express');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!ADMIN_PASSWORD) {
  console.warn('WARNING: ADMIN_PASSWORD is not set.');
}

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: '20kb' }));


const db = new Database(process.env.DB_PATH || path.join(__dirname, 'segretto.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS bookings (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  booking_date TEXT NOT NULL,
  table_name TEXT NOT NULL,
  drink TEXT NOT NULL,
  start_minute INTEGER NOT NULL,
  end_minute INTEGER NOT NULL,
  start_text TEXT NOT NULL,
  end_text TEXT NOT NULL,
  price INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('held','paid','cancelled')),
  created_at TEXT NOT NULL,
  hold_expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_bookings_date_table
ON bookings(booking_date, table_name, start_minute, end_minute, status);

CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
`);

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function requireAdmin(req, res, next) {
  const token = parseCookies(req).segretto_admin;
  if (!token) return res.status(401).json({error:'Unauthorized'});
  const hash = hashToken(token);
  const row = db.prepare('SELECT expires_at FROM admin_sessions WHERE token_hash=?').get(hash);
  if (!row || row.expires_at < Date.now()) {
    if (row) db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(hash);
    return res.status(401).json({error:'Unauthorized'});
  }
  next();
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

const drinks = {
  'سيجريتو لاتيه': 28,
  'قهوة مختصة V60': 35,
  'إسبريسو': 20,
  'كابوتشينو': 30,
  'كرواسون ومشروب ساخن': 45
};

function parseTime(value) {
  if (!value) return NaN;
  let s = String(value).trim()
    .replace(/[أإآ]/g, 'ا')
    .replace(/صباحا|صباحًا|ص/g, 'AM')
    .replace(/مساءا|مساءً|مساء|م/g, 'PM')
    .replace(/\s+/g, ' ')
    .toUpperCase();

  const m = s.match(/^(\d{1,2})\s*:\s*(\d{2})\s*(AM|PM)$/);
  if (!m) return NaN;
  let hour = Number(m[1]);
  const minute = Number(m[2]);
  if (hour < 1 || hour > 12 || minute < 0 || minute > 59) return NaN;
  if (m[3] === 'AM') {
    if (hour === 12) hour = 0;
  } else if (hour !== 12) {
    hour += 12;
  }
  return hour * 60 + minute;
}

function overlaps(aStart, aEnd, bStart, bEnd) {
  return aStart < bEnd && bStart < aEnd;
}

function validDate(s) {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) &&
    !Number.isNaN(Date.parse(`${s}T00:00:00Z`));
}

function cleanupExpiredHolds() {
  db.prepare(`
    UPDATE bookings
    SET status='cancelled'
    WHERE status='held' AND hold_expires_at IS NOT NULL AND hold_expires_at < ?
  `).run(new Date().toISOString());
}

function conflictExists(date, table, start, end) {
  cleanupExpiredHolds();
  const rows = db.prepare(`
    SELECT start_minute, end_minute
    FROM bookings
    WHERE booking_date=? AND table_name=?
      AND status IN ('held','paid')
  `).all(date, table);

  return rows.some(r => overlaps(start, end, r.start_minute, r.end_minute));
}

app.get('/api/tables', (req, res) => {
  const date = String(req.query.date || '');
  if (!validDate(date)) return res.status(400).json({error:'تاريخ غير صالح.'});

  cleanupExpiredHolds();

  const tables = [];
  for (let i = 1; i <= 20; i++) {
    const name = `طاولة رقم ${i}`;
    const rows = db.prepare(`
      SELECT 1 FROM bookings
      WHERE booking_date=? AND table_name=? AND status IN ('held','paid')
      LIMIT 1
    `).all(date, name);

    tables.push({name, available: rows.length === 0});
  }
  res.json({tables});
});

app.post('/api/bookings/hold', (req, res) => {
  const {name, phone, bookingDate, table, drink, startTime, endTime} = req.body || {};

  if (typeof name !== 'string' || name.trim().length < 2 || name.length > 100)
    return res.status(400).json({error:'الاسم غير صالح.'});
  if (typeof phone !== 'string' || !/^[0-9+\-\s()]{7,20}$/.test(phone))
    return res.status(400).json({error:'رقم الهاتف غير صالح.'});
  if (!validDate(bookingDate))
    return res.status(400).json({error:'تاريخ غير صالح.'});
  if (!/^طاولة رقم (?:[1-9]|1[0-9]|20)$/.test(table || ''))
    return res.status(400).json({error:'الطاولة غير صالحة.'});
  if (!Object.prototype.hasOwnProperty.call(drinks, drink))
    return res.status(400).json({error:'المشروب غير صالح.'});

  const start = parseTime(startTime);
  const end = parseTime(endTime);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end)
    return res.status(400).json({error:'وقت الحجز غير صالح.'});

  // SQLite transaction makes the server-side conflict check + insert atomic.
  const tx = db.transaction(() => {
    if (conflictExists(bookingDate, table, start, end)) return null;

    const id = crypto.randomUUID();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    db.prepare(`
      INSERT INTO bookings
      (id,name,phone,booking_date,table_name,drink,start_minute,end_minute,start_text,end_text,price,status,created_at,hold_expires_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      id, name.trim(), phone.trim(), bookingDate, table, drink, start, end,
      String(startTime).trim(), String(endTime).trim(), drinks[drink], 'held',
      new Date().toISOString(), expires
    );

    return {holdId:id, bookingDate, table, drink, startTime, endTime, price:drinks[drink]};
  });

  const result = tx();
  if (!result) return res.status(409).json({error:'الطاولة محجوزة بالفعل في هذه الفترة.'});
  res.status(201).json(result);
});

// Payment gateway intentionally left unconfigured.
// Configure PAYMENT_CHECKOUT_URL only after adding the real provider.
app.post('/api/payments/create-checkout', (req, res) => {
  const {holdId} = req.body || {};
  if (!holdId) return res.status(400).json({error:'الحجز المؤقت غير صالح.'});

  const row = db.prepare(`
    SELECT id, status, hold_expires_at FROM bookings WHERE id=?
  `).get(holdId);

  if (!row || row.status !== 'held')
    return res.status(404).json({error:'الحجز المؤقت غير موجود.'});

  if (row.hold_expires_at && row.hold_expires_at < new Date().toISOString()) {
    db.prepare(`UPDATE bookings SET status='cancelled' WHERE id=?`).run(holdId);
    return res.status(410).json({error:'انتهت مدة الحجز المؤقت.'});
  }

  // Leave actual gateway integration for the user.
  const gateway = process.env.PAYMENT_CHECKOUT_URL;
  if (!gateway) return res.json({checkoutUrl:null});

  const url = new URL(gateway);
  url.searchParams.set('holdId', holdId);
  res.json({checkoutUrl:url.toString()});
});

// Simple admin API. Password is read only from environment, never stored in frontend.
app.post('/api/admin/login', (req, res) => {
  const password = String(req.body?.password || '');
  const expected = String(process.env.ADMIN_PASSWORD || '');
  if (!expected || password !== expected) {
    return res.status(401).json({error:'بيانات الدخول غير صحيحة'});
  }
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  db.prepare('INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?,?)')
    .run(hashToken(token), expiresAt);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie',
    `segretto_admin=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
  res.json({ok:true});
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  const token = parseCookies(req).segretto_admin;
  if (token) db.prepare('DELETE FROM admin_sessions WHERE token_hash=?').run(hashToken(token));
  res.setHeader('Set-Cookie', 'segretto_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ok:true});
});

app.get('/api/admin/bookings', requireAdmin, (req, res) => {
  cleanupExpiredHolds();
  const rows = db.prepare(`
    SELECT id,name,phone,booking_date AS bookingDate,table_name AS tableName,
           drink,start_text AS startTime,end_text AS endTime,price,status,created_at AS createdAt
    FROM bookings ORDER BY booking_date DESC, start_minute ASC
  `).all();
  res.json({bookings:rows});
});

app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  dotfiles: 'deny'
}));

app.use((req,res) => res.status(404).json({error:'Not found'}));

app.listen(PORT, () => {
  console.log(`Segreto server running on port ${PORT}`);
});
