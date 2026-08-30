import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const app = express();
const db = new Database('view49.db');
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

db.exec(`CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 is_premium INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

const signToken = user => jwt.sign(
  { sub: user.id, email: user.email, premium: !!user.is_premium },
  JWT_SECRET,
  { expiresIn: '7d' }
);

function auth(req, res, next) {
  const token = req.cookies.view49_session;
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id,email,is_premium FROM users WHERE id=?').get(payload.sub);
    if (!user) return res.status(401).json({ error: 'Invalid session' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired or invalid' });
  }
}

function premiumOnly(req, res, next) {
  if (!req.user?.is_premium) return res.status(403).json({ error: 'Premium membership required' });
  next();
}

app.post('/api/auth/signup', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8)
    return res.status(400).json({ error: 'Valid email and password of at least 8 characters are required' });
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (email,password_hash) VALUES (?,?)').run(email, passwordHash);
    const user = { id: result.lastInsertRowid, email, is_premium: 0 };
    res.cookie('view49_session', signToken(user), { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 });
    res.status(201).json({ user: { id: user.id, email, premium: false } });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid email or password' });
  res.cookie('view49_session', signToken(user), { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 });
  res.json({ user: { id: user.id, email: user.email, premium: !!user.is_premium } });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('view49_session', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
  res.json({ ok: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email, premium: !!req.user.is_premium } });
});

app.get('/api/premium', auth, premiumOnly, (req, res) => {
  res.json({ ok: true, message: 'Premium content unlocked' });
});

app.listen(PORT, () => console.log(`View49 auth server running on http://localhost:${PORT}`));
