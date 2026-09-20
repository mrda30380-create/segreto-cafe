const express = require('express');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));

const memoryStore = {
  bookings: [],
  adminSessions: {}
};

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
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const hash = hashToken(token);
  const session = memoryStore.adminSessions[hash];
  if (!session || session.expires_at < Date.now()) {
    delete memoryStore.adminSessions[hash];
    return res.status(401).json({ error: 'Unauthorized' });
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

app.get('/api/tables', (req, res) => {
  const tables = [];
  for (let i = 1; i <= 20; i++) {
    tables.push({ name: `طاولة رقم ${i}`, available: true });
  }
  res.json({ tables });
});

app.post('/api/admin/login', (req, res) => {
  const password = String(req.body?.password || '');
  const expected = String(process.env.ADMIN_PASSWORD || '123456');
  if (password !== expected) {
    return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  memoryStore.adminSessions[hashToken(token)] = { expires_at: expiresAt };
  
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `segretto_admin=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
  res.json({ ok: true });
});

app.get('/api/admin/bookings', requireAdmin, (req, res) => {
  res.json({ bookings: memoryStore.bookings });
});

app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  dotfiles: 'deny'
}));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

module.exports = app;
