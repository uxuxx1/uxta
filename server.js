import express from 'express';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import pg from 'pg';
import bcrypt from 'bcrypt';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { Server } from 'socket.io';
import { createServer } from 'http';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import cron from 'node-cron';
import helmet from 'helmet';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = createServer(app);
const io = new Server(server);

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const PgSession = pgSession(session);
app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'uxtes_secret_2016',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname}`)
});
const upload = multer({ limits: { fileSize: 20 * 1024 * 1024 }, storage });

cron.schedule('0 0 * * *', async () => {
  try {
    const old = await pool.query('SELECT file_uuid FROM messages WHERE file_uuid IS NOT NULL AND sent_at < NOW() - INTERVAL \'15 days\' AND file_deleted = FALSE');
    for (let row of old.rows) {
      const p = path.join(uploadDir, row.file_uuid);
      if (fs.existsSync(p)) fs.unlinkSync(p);
      await pool.query('UPDATE messages SET file_deleted = TRUE WHERE file_uuid = $1', [row.file_uuid]);
    }
  } catch (err) {
    console.error('Cron cleanup error:', err);
  }
});

app.post('/register', async (req, res) => {
  try {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ error: 'login and password required' });
    const exists = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
    if (exists.rows.length) return res.status(400).json({ error: 'login already taken' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query('INSERT INTO users (login, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id', [login, hash, login]);
    req.session.userId = result.rows[0].id;
    res.json({ ok: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'registration failed', details: err.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { login, password, token } = req.body;
    const user = await pool.query('SELECT id, password_hash, twofa_secret FROM users WHERE login = $1', [login]);
    if (!user.rows.length) return res.status(401).json({ error: 'wrong login or password' });
    const match = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'wrong login or password' });
    if (user.rows[0].twofa_secret) {
      if (!token) return res.status(401).json({ need2fa: true });
      const verified = speakeasy.totp.verify({ secret: user.rows[0].twofa_secret, encoding: 'base32', token });
      if (!verified) return res.status(401).json({ error: 'invalid 2fa code' });
    }
    req.session.userId = user.rows[0].id;
    res.json({ ok: true });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'login failed', details: err.message });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/me', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
    const user = await pool.query('SELECT id, login, display_name, bio, avatar, twofa_secret IS NOT NULL as has2fa FROM users WHERE id = $1', [req.session.userId]);
    res.json(user.rows[0]);
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'failed', details: err.message });
  }
});

app.post('/profile', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
    const { display_name, bio, avatar, new_password, twofa_enable, twofa_token } = req.body;
    const updates = [];
    const values = [];
    if (display_name !== undefined) { updates.push(`display_name = $${updates.length+1}`); values.push(display_name); }
    if (bio !== undefined) { updates.push(`bio = $${updates.length+1}`); values.push(bio); }
    if (avatar !== undefined && avatar.length < 50000) { updates.push(`avatar = $${updates.length+1}`); values.push(avatar); }
    if (new_password) { updates.push(`password_hash = $${updates.length+1}`); values.push(await bcrypt.hash(new_password, 10)); }
    if (twofa_enable !== undefined) {
      const user = await pool.query('SELECT twofa_secret FROM users WHERE id = $1', [req.session.userId]);
      if (twofa_enable === true && !user.rows[0].twofa_secret) {
        const secret = speakeasy.generateSecret({ length: 20 });
        const verified = speakeasy.totp.verify({ secret: secret.base32, encoding: 'base32', token: twofa_token });
        if (!verified) return res.status(400).json({ error: 'invalid 2fa token' });
        updates.push(`twofa_secret = $${updates.length+1}`); values.push(secret.base32);
      } else if (twofa_enable === false) {
        updates.push(`twofa_secret = NULL`);
      }
    }
    if (updates.length) {
      values.push(req.session.userId);
      await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length}`, values);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'profile update failed', details: err.message });
  }
});

app.get('/users', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json([]);
    const users = await pool.query('SELECT id, login, display_name, avatar FROM users WHERE id != $1', [req.session.userId]);
    res.json(users.rows);
  } catch (err) {
    console.error('Users list error:', err);
    res.status(500).json([]);
  }
});

app.post('/block', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
    const { block_user_id, block } = req.body;
    if (block) {
      await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.session.userId, block_user_id]);
    } else {
      await pool.query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, block_user_id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Block error:', err);
    res.status(500).json({ error: 'block failed', details: err.message });
  }
});

app.get('/blocks', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json([]);
    const blocks = await pool.query('SELECT blocked_id FROM blocks WHERE blocker_id = $1', [req.session.userId]);
    res.json(blocks.rows.map(r => r.blocked_id));
  } catch (err) {
    console.error('Blocks error:', err);
    res.status(500).json([]);
  }
});

app.post('/deletechat', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
    const { with_user_id } = req.body;
    await pool.query('DELETE FROM messages WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1)', [req.session.userId, with_user_id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete chat error:', err);
    res.status(500).json({ error: 'delete failed', details: err.message });
  }
});

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
    const { to_id } = req.body;
    if (!req.file) return res.status(400).json({ error: 'no file' });
    const blocked = await pool.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, to_id]);
    if (blocked.rows.length) return res.status(403).json({ error: 'blocked' });
    const fileUuid = `${Date.now()}_${req.file.filename}`;
    const newPath = path.join(uploadDir, fileUuid);
    fs.renameSync(req.file.path, newPath);
    const msg = await pool.query('INSERT INTO messages (from_id, to_id, text, file_uuid, file_name, file_size) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', 
      [req.session.userId, to_id, `[file] ${req.file.originalname}`, fileUuid, req.file.originalname, req.file.size]);
    const data = { id: msg.rows[0].id, from_id: req.session.userId, to_id, text: `[file] ${req.file.originalname}`, file_uuid: fileUuid, file_name: req.file.originalname, file_size: req.file.size, sent_at: new Date() };
    io.to(`user_${to_id}`).emit('new_message', data);
    res.json({ ok: true, message: data });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'upload failed', details: err.message });
  }
});

app.get('/download/:uuid', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).send('unauth');
    const file = await pool.query('SELECT file_uuid, file_name, file_deleted, from_id, to_id FROM messages WHERE file_uuid = $1', [req.params.uuid]);
    if (!file.rows.length || file.rows[0].file_deleted) return res.status(404).send('expired');
    if (file.rows[0].from_id !== req.session.userId && file.rows[0].to_id !== req.session.userId) return res.status(403).send('not allowed');
    const p = path.join(uploadDir, file.rows[0].file_uuid);
    if (!fs.existsSync(p)) return res.status(404).send('missing');
    res.download(p, file.rows[0].file_name);
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).send('server error');
  }
});

app.get('/history/:userId', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json([]);
    const other = parseInt(req.params.userId);
    const blocked = await pool.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, other]);
    if (blocked.rows.length) return res.json([]);
    const msgs = await pool.query(`
      SELECT id, from_id, to_id, text, file_uuid, file_name, file_size, file_deleted, sent_at 
      FROM messages 
      WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1)
      ORDER BY sent_at ASC LIMIT 200
    `, [req.session.userId, other]);
    res.json(msgs.rows);
  } catch (err) {
    console.error('History error:', err);
    res.status(500).json([]);
  }
});

app.get('/2fa/qrcode', async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
    const user = await pool.query('SELECT login FROM users WHERE id = $1', [req.session.userId]);
    const secret = speakeasy.generateSecret({ length: 20 });
    const otpauth = speakeasy.otpauthURL({ secret: secret.ascii, label: `uxtes:${user.rows[0].login}`, algorithm: 'sha1' });
    const qr = await QRCode.toDataURL(otpauth);
    res.json({ secret: secret.base32, qr });
  } catch (err) {
    console.error('2FA QR error:', err);
    res.status(500).json({ error: 'failed', details: err.message });
  }
});

io.use((socket, next) => {
  const req = socket.request;
  if (req.session && req.session.userId) return next();
  next(new Error('unauth'));
});

io.on('connection', (socket) => {
  const userId = socket.request.session.userId;
  socket.join(`user_${userId}`);
  socket.on('private_message', async (data) => {
    try {
      const { to_id, text } = data;
      if (!text.trim()) return;
      const blocked = await pool.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [userId, to_id]);
      if (blocked.rows.length) return;
      const msg = await pool.query('INSERT INTO messages (from_id, to_id, text) VALUES ($1, $2, $3) RETURNING id, sent_at', [userId, to_id, text]);
      const messageData = { id: msg.rows[0].id, from_id: userId, to_id, text, sent_at: msg.rows[0].sent_at };
      io.to(`user_${to_id}`).emit('new_message', messageData);
      socket.emit('new_message', messageData);
    } catch (err) {
      console.error('Socket message error:', err);
    }
  });
  socket.on('typing', ({ to_id, typing }) => {
    socket.to(`user_${to_id}`).emit('typing', { from_id: userId, typing });
  });
  socket.on('call_offer', (data) => { socket.to(`user_${data.to}`).emit('call_offer', { from: userId, offer: data.offer }); });
  socket.on('call_answer', (data) => { socket.to(`user_${data.to}`).emit('call_answer', { from: userId, answer: data.answer }); });
  socket.on('ice_candidate', (data) => { socket.to(`user_${data.to}`).emit('ice_candidate', { from: userId, candidate: data.candidate }); });
});

app.use((err, req, res, next) => {
  console.error('Express global error:', err);
  res.status(500).json({ error: 'server error', details: err.message });
});

app.get('*', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
  <title>uxtes · skype 2015</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; }
    body { background: #eef2f5; height: 100vh; display: flex; justify-content: center; align-items: center; }
    .app { width: 100%; max-width: 1300px; height: 95vh; background: white; box-shadow: 0 2px 12px rgba(0,0,0,0.1); display: flex; flex-direction: column; overflow: hidden; }
    .top-bar { display: flex; justify-content: space-between; padding: 10px 20px; background: #e8e8e8; border-bottom: 1px solid #ccc; font-size: 14px; font-weight: 500; }
    .top-bar button { background: white; border: 1px solid #aaa; padding: 4px 12px; cursor: pointer; font-size: 12px; border-radius: 2px; transition: 0.1s; }
    .top-bar button:hover { background: #f5f5f5; }
    .main { display: flex; flex: 1; overflow: hidden; }
    .sidebar { width: 280px; background: #f7f7f7; border-right: 1px solid #ddd; display: flex; flex-direction: column; }
    .search { padding: 12px; border-bottom: 1px solid #e0e0e0; }
    .search input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 2px; font-size: 13px; }
    .users-list { flex: 1; overflow-y: auto; }
    .user-item { padding: 10px 12px; border-bottom: 1px solid #eee; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: background 0.1s; }
    .user-item:hover { background: #ebebeb; }
    .avatar { width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; font-size: 16px; font-weight: bold; color: white; text-transform: uppercase; border-radius: 2px; }
    .user-info { flex: 1; }
    .user-name { font-size: 14px; font-weight: 500; }
    .user-login { font-size: 11px; color: #666; }
    .block-badge { color: #d32f2f; font-size: 10px; margin-left: 6px; }
    .chat-area { flex: 1; display: flex; flex-direction: column; background: white; }
    .chat-header { padding: 10px 16px; border-bottom: 1px solid #ddd; background: #f9f9f9; display: flex; justify-content: space-between; align-items: center; }
    .chat-header button { background: white; border: 1px solid #aaa; padding: 4px 10px; font-size: 12px; cursor: pointer; border-radius: 2px; margin-left: 6px; }
    .messages { flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 8px; background: #fff; }
    .message { max-width: 70%; padding: 8px 12px; background: #f0f0f0; border-radius: 2px; align-self: flex-start; font-size: 13px; line-height: 1.4; box-shadow: 0 1px 0 rgba(0,0,0,0.05); }
    .message.own { align-self: flex-end; background: #e1e1e1; }
    .message-text { word-break: break-word; }
    .file-link { color: #0066cc; text-decoration: none; border-bottom: 1px dotted; cursor: pointer; }
    .typing-indicator { font-size: 11px; color: #888; margin-left: 16px; margin-bottom: 6px; font-style: italic; }
    .input-area { padding: 12px; border-top: 1px solid #ddd; display: flex; gap: 8px; background: #fdfdfd; }
    .input-area input[type="text"] { flex: 1; padding: 8px; border: 1px solid #ccc; border-radius: 2px; font-size: 13px; }
    .input-area button { padding: 6px 14px; background: white; border: 1px solid #aaa; cursor: pointer; border-radius: 2px; font-size: 12px; }
    .profile-panel { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 100; }
    .profile-card { background: white; width: 400px; padding: 24px; border: 1px solid #999; box-shadow: 0 4px 12px rgba(0,0,0,0.2); display: flex; flex-direction: column; gap: 12px; }
    .profile-card input, .profile-card textarea { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 2px; font-size: 13px; }
    .profile-card button { padding: 6px 12px; background: white; border: 1px solid #aaa; cursor: pointer; border-radius: 2px; }
    video { width: 180px; background: #222; position: fixed; bottom: 20px; right: 20px; z-index: 200; border: 2px solid white; border-radius: 2px; box-shadow: 0 2px 8px black; }
    .error-msg { color: #d32f2f; font-size: 12px; margin-top: 6px; }
    @media (max-width: 700px) { .sidebar { width: 240px; } .message { max-width: 85%; } }
  </style>
</head>
<body>
<div class="app" id="app"></div>
<script src="/socket.io/socket.io.js"></script>
<script>
let socket = null;
let currentUser = null;
let selectedUserId = null;
let typingTimeout = null;
let peerConnection = null;
let localStream = null;
let blockedUsers = new Set();
let notificationPermission = false;
let audioCtx = null;

function showErrorDialog(title, message, details = '') {
  const div = document.createElement('div');
  div.style.position = 'fixed';
  div.style.top = '20px';
  div.style.left = '50%';
  div.style.transform = 'translateX(-50%)';
  div.style.backgroundColor = '#fff0f0';
  div.style.border = '1px solid #d32f2f';
  div.style.borderRadius = '2px';
  div.style.padding = '16px';
  div.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
  div.style.zIndex = '10000';
  div.style.maxWidth = '500px';
  div.style.width = '90%';
  div.innerHTML = \`
    <strong style="color:#d32f2f;">\${escapeHtml(title)}</strong>
    <div style="margin-top:8px; font-family:monospace; font-size:12px; background:#fce4e4; padding:8px; overflow-x:auto;">
      \${escapeHtml(message)}\${details ? '<br>' + escapeHtml(details) : ''}
    </div>
    <button id="copyErrorBtn" style="margin-top:12px; padding:4px 12px; background:white; border:1px solid #aaa; cursor:pointer;">Copy error</button>
    <button id="closeErrorBtn" style="margin-left:8px; padding:4px 12px; background:white; border:1px solid #aaa; cursor:pointer;">Close</button>
  \`;
  document.body.appendChild(div);
  document.getElementById('copyErrorBtn').onclick = () => {
    const fullError = \`\${title}\n\${message}\${details ? '\\n' + details : ''}\`;
    navigator.clipboard.writeText(fullError);
    alert('Error copied to clipboard');
  };
  document.getElementById('closeErrorBtn').onclick = () => div.remove();
  setTimeout(() => div.remove(), 10000);
}

const originalFetch = window.fetch;
window.fetch = function(...args) {
  return originalFetch.apply(this, args).then(async (res) => {
    if (!res.ok) {
      let errorData = { error: \`HTTP \${res.status}\`, details: '' };
      try {
        const cloned = res.clone();
        errorData = await cloned.json();
      } catch(e) {}
      showErrorDialog('Request failed', errorData.error || res.statusText, errorData.details || '');
      throw new Error(errorData.error || res.statusText);
    }
    return res;
  }).catch((err) => {
    if (!err.message.includes('showErrorDialog')) {
      showErrorDialog('Network error', err.message, '');
    }
    throw err;
  });
};

window.addEventListener('error', (e) => {
  showErrorDialog('JavaScript error', e.message, e.filename + ':' + e.lineno);
});
window.addEventListener('unhandledrejection', (e) => {
  showErrorDialog('Unhandled promise rejection', e.reason?.message || String(e.reason), '');
});

function playBeep() {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();
  osc.connect(gain);
  gain.connect(audioCtx.destination);
  osc.frequency.value = 800;
  gain.gain.value = 0.15;
  osc.start();
  gain.gain.exponentialRampToValueAtTime(0.00001, audioCtx.currentTime + 0.4);
  osc.stop(audioCtx.currentTime + 0.4);
}

function notify(title, body) {
  if (notificationPermission && document.hidden) {
    new Notification(title, { body, icon: '' });
    playBeep();
  }
}

async function requestNotif() {
  if ('Notification' in window) {
    const perm = await Notification.requestPermission();
    notificationPermission = (perm === 'granted');
  }
}

function renderAuth() {
  document.getElementById('app').innerHTML = \`
    <div style="display: flex; justify-content: center; align-items: center; height: 100%; background: #eef2f5;">
      <div style="width: 340px; background: white; padding: 28px; border: 1px solid #ccc; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <h2 style="font-weight: 500; margin-bottom: 20px;">uxtes</h2>
        <div id="authForm">
          <input type="text" id="login" placeholder="login" style="width:100%; margin-bottom:12px; padding:8px; border:1px solid #ccc; border-radius:2px;">
          <input type="password" id="password" placeholder="password" style="width:100%; margin-bottom:12px; padding:8px; border:1px solid #ccc; border-radius:2px;">
          <div id="twofaField" style="display:none;"><input type="text" id="twofaToken" placeholder="2FA code" style="width:100%; margin-bottom:12px; padding:8px;"></div>
          <button id="doLogin" style="margin-right:8px; padding:6px 16px;">Login</button>
          <button id="doReg" style="padding:6px 16px;">Register</button>
          <div id="authError" class="error-msg" style="margin-top:12px;"></div>
        </div>
      </div>
    </div>
  \`;
  const loginBtn = document.getElementById('doLogin');
  const regBtn = document.getElementById('doReg');
  const loginInput = document.getElementById('login');
  const passInput = document.getElementById('password');
  loginBtn.onclick = async () => {
    const login = loginInput.value;
    const password = passInput.value;
    let token = document.getElementById('twofaToken')?.value;
    try {
      const res = await fetch('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({login, password, token}) });
      const data = await res.json();
      if (res.ok) location.reload();
      else if (data.need2fa) document.getElementById('twofaField').style.display = 'block';
      else showErrorDialog('Login error', data.error || 'unknown error', data.details || '');
    } catch (err) {
      showErrorDialog('Login exception', err.message, '');
    }
  };
  regBtn.onclick = async () => {
    const login = loginInput.value;
    const password = passInput.value;
    try {
      const res = await fetch('/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({login, password}) });
      const data = await res.json();
      if (res.ok) location.reload();
      else showErrorDialog('Registration error', data.error || 'unknown error', data.details || '');
    } catch (err) {
      showErrorDialog('Registration exception', err.message, '');
    }
  };
}

async function loadBlocks() {
  const res = await fetch('/blocks');
  const blocks = await res.json();
  blockedUsers.clear();
  blocks.forEach(id => blockedUsers.add(id));
}

async function deleteChatWith(userId) {
  if (!confirm('delete entire chat history?')) return;
  await fetch('/deletechat', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ with_user_id: userId }) });
  if (selectedUserId === userId) {
    document.querySelector('.messages').innerHTML = '<div style="padding:20px;text-align:center;color:#777;">chat cleared</div>';
  }
}

async function toggleBlock(userId) {
  const currentlyBlocked = blockedUsers.has(userId);
  const action = !currentlyBlocked;
  await fetch('/block', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ block_user_id: userId, block: action }) });
  await loadBlocks();
  if (selectedUserId === userId) {
    if (action) {
      document.querySelector('.messages').innerHTML = '<div style="padding:20px;text-align:center;">user blocked</div>';
    } else {
      loadHistory(userId);
    }
  }
  renderUsersList();
}

async function renderUsersList() {
  const res = await fetch('/users');
  const users = await res.json();
  const container = document.querySelector('.users-list');
  if (!container) return;
  const colors = ['#6c8ebf', '#7c9c7e', '#b88a6b', '#a27c9c', '#8faa7e'];
  container.innerHTML = users.map((u, idx) => {
    const letter = (u.display_name || u.login)[0].toUpperCase();
    const color = colors[idx % colors.length];
    return \`
      <div class="user-item" data-id="\${u.id}">
        <div class="avatar" style="background:\${color};">\${letter}</div>
        <div class="user-info">
          <div class="user-name">\${escapeHtml(u.display_name || u.login)} \${blockedUsers.has(u.id) ? '<span class="block-badge">[blocked]</span>' : ''}</div>
          <div class="user-login">@\${escapeHtml(u.login)}</div>
        </div>
      </div>
    \`;
  }).join('');
  document.querySelectorAll('.user-item').forEach(el => {
    el.onclick = () => selectUser(parseInt(el.dataset.id));
  });
}

function escapeHtml(str) { return str.replace(/[&<>]/g, function(m){if(m==='&') return '&amp;'; if(m==='<') return '&lt;'; if(m==='>') return '&gt;'; return m;}); }

async function selectUser(userId) {
  selectedUserId = userId;
  const userName = document.querySelector(\`.user-item[data-id="\${userId}"] .user-name\`)?.innerText || 'chat';
  document.querySelector('.chat-header').innerHTML = \`
    <span style="font-weight:500;">\${escapeHtml(userName)}</span>
    <div>
      <button id="blockBtn">\${blockedUsers.has(userId) ? 'unblock' : 'block'}</button>
      <button id="deleteChatBtn">delete chat</button>
      <button id="callBtn">call</button>
    </div>
  \`;
  document.getElementById('blockBtn').onclick = () => toggleBlock(userId);
  document.getElementById('deleteChatBtn').onclick = () => deleteChatWith(userId);
  document.getElementById('callBtn').onclick = () => startCall(userId);
  if (blockedUsers.has(userId)) {
    document.querySelector('.messages').innerHTML = '<div style="padding:20px;text-align:center;">blocked</div>';
    return;
  }
  await loadHistory(userId);
}

async function loadHistory(userId) {
  const res = await fetch('/history/' + userId);
  const msgs = await res.json();
  const container = document.querySelector('.messages');
  container.innerHTML = msgs.map(m => \`
    <div class="message \${m.from_id === currentUser.id ? 'own' : ''}">
      <div class="message-text">\${renderMessageText(m)}</div>
      <div style="font-size:10px; color:#888; margin-top:4px;">\${new Date(m.sent_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</div>
    </div>
  \`).join('');
  container.scrollTop = container.scrollHeight;
}

function renderMessageText(m) {
  if (m.file_uuid && !m.file_deleted) {
    return \`[file] \${escapeHtml(m.file_name)} (\${(m.file_size/1024).toFixed(0)} KB) - <a class="file-link" onclick="downloadFile('\${m.file_uuid}')">download</a>\`;
  } else if (m.file_deleted) {
    return \`[file expired]\`;
  }
  return escapeHtml(m.text);
}

window.downloadFile = async (uuid) => {
  window.open('/download/' + uuid, '_blank');
};

async function loadProfile() {
  const res = await fetch('/me');
  currentUser = await res.json();
  document.querySelector('.top-bar').innerHTML = \`
    <span>uxtes · \${escapeHtml(currentUser.login)}</span>
    <div><button id="profileBtn">profile</button><button id="logoutBtn">logout</button></div>
  \`;
  document.getElementById('profileBtn').onclick = showProfileModal;
  document.getElementById('logoutBtn').onclick = async () => { await fetch('/logout'); location.reload(); };
}

function showProfileModal() {
  const modal = document.createElement('div');
  modal.className = 'profile-panel';
  modal.innerHTML = \`
    <div class="profile-card">
      <h3 style="font-weight:500;">profile settings</h3>
      <input type="text" id="displayName" placeholder="display name" value="\${escapeHtml(currentUser.display_name)}">
      <textarea id="bio" placeholder="bio" rows="2">\${escapeHtml(currentUser.bio)}</textarea>
      <input type="password" id="newPass" placeholder="new password (leave empty to keep)">
      <div><label><input type="checkbox" id="twofaCheck" \${currentUser.has2fa ? 'checked' : ''}> enable 2FA</label></div>
      <div id="twofaQr" style="display:none;"></div>
      <input type="text" id="twofaTokenInput" placeholder="2FA token to confirm" style="display:none;">
      <div style="display:flex; gap:8px; margin-top:8px;">
        <button id="saveProfile">save</button>
        <button id="closeModal">cancel</button>
      </div>
    </div>
  \`;
  document.body.appendChild(modal);
  const twofaCheck = modal.querySelector('#twofaCheck');
  const qrDiv = modal.querySelector('#twofaQr');
  const tokenInput = modal.querySelector('#twofaTokenInput');
  twofaCheck.onchange = async (e) => {
    if (e.target.checked && !currentUser.has2fa) {
      const res = await fetch('/2fa/qrcode');
      const data = await res.json();
      qrDiv.innerHTML = \`<img src="\${data.qr}" style="width:130px;"><br><code style="font-size:11px;">\${data.secret}</code>\`;
      qrDiv.style.display = 'block';
      tokenInput.style.display = 'block';
    } else {
      qrDiv.style.display = 'none';
      tokenInput.style.display = 'none';
    }
  };
  modal.querySelector('#saveProfile').onclick = async () => {
    const body = {
      display_name: modal.querySelector('#displayName').value,
      bio: modal.querySelector('#bio').value,
      new_password: modal.querySelector('#newPass').value,
      twofa_enable: twofaCheck.checked,
      twofa_token: tokenInput.value
    };
    await fetch('/profile', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    modal.remove();
    location.reload();
  };
  modal.querySelector('#closeModal').onclick = () => modal.remove();
}

function initSocket() {
  socket = io();
  socket.on('new_message', (msg) => {
    if (msg.from_id === selectedUserId || msg.to_id === selectedUserId) {
      const container = document.querySelector('.messages');
      if (container && !blockedUsers.has(msg.from_id)) {
        const html = \`
          <div class="message \${msg.from_id === currentUser.id ? 'own' : ''}">
            <div class="message-text">\${renderMessageText(msg)}</div>
            <div style="font-size:10px;color:#888;margin-top:4px;">\${new Date(msg.sent_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</div>
          </div>
        \`;
        container.insertAdjacentHTML('beforeend', html);
        container.scrollTop = container.scrollHeight;
      }
    }
    if (msg.from_id !== currentUser.id) {
      notify(\`\${msg.from_id}\`, msg.text.length > 50 ? msg.text.slice(0,50)+'…' : msg.text);
    }
  });
  socket.on('typing', ({ from_id, typing }) => {
    if (from_id === selectedUserId && !blockedUsers.has(from_id)) {
      const indicator = document.querySelector('.typing-indicator');
      if (typing) {
        if (!indicator) document.querySelector('.messages')?.insertAdjacentHTML('afterend', '<div class="typing-indicator">/* typing ... */</div>');
        else indicator.style.display = 'block';
      } else {
        if (indicator) indicator.remove();
      }
    }
  });
  socket.on('call_offer', async ({ from, offer }) => {
    if (confirm(\`incoming call from user \${from}\`)) acceptCall(from, offer);
  });
  socket.on('call_answer', ({ from, answer }) => {
    if (peerConnection) peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
  });
  socket.on('ice_candidate', ({ candidate }) => {
    if (peerConnection) peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
  });
}

let localVideo = null;
async function startCall(toUserId) {
  if (blockedUsers.has(toUserId)) return alert('cannot call blocked user');
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    localVideo = document.createElement('video');
    localVideo.srcObject = localStream;
    localVideo.autoplay = true;
    localVideo.style.position = 'fixed';
    localVideo.style.bottom = '20px';
    localVideo.style.right = '20px';
    localVideo.style.width = '180px';
    localVideo.style.border = '2px solid white';
    document.body.appendChild(localVideo);
    peerConnection = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
    localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
    peerConnection.onicecandidate = (e) => {
      if (e.candidate) socket.emit('ice_candidate', { to: toUserId, candidate: e.candidate });
    };
    peerConnection.ontrack = (e) => {
      const remoteVideo = document.createElement('video');
      remoteVideo.srcObject = e.streams[0];
      remoteVideo.autoplay = true;
      remoteVideo.style.position = 'fixed';
      remoteVideo.style.bottom = '220px';
      remoteVideo.style.right = '20px';
      remoteVideo.style.width = '180px';
      remoteVideo.style.border = '2px solid white';
      document.body.appendChild(remoteVideo);
    };
    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);
    socket.emit('call_offer', { to: toUserId, offer });
  } catch (err) {
    showErrorDialog('Call error', err.message, '');
  }
}

async function acceptCall(fromUserId, offer) {
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    localVideo = document.createElement('video');
    localVideo.srcObject = localStream;
    localVideo.autoplay = true;
    localVideo.style.position = 'fixed';
    localVideo.style.bottom = '20px';
    localVideo.style.right = '20px';
    localVideo.style.width = '180px';
    document.body.appendChild(localVideo);
    peerConnection = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
    localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
    peerConnection.onicecandidate = (e) => {
      if (e.candidate) socket.emit('ice_candidate', { to: fromUserId, candidate: e.candidate });
    };
    peerConnection.ontrack = (e) => {
      const remoteVideo = document.createElement('video');
      remoteVideo.srcObject = e.streams[0];
      remoteVideo.autoplay = true;
      remoteVideo.style.position = 'fixed';
      remoteVideo.style.bottom = '220px';
      remoteVideo.style.right = '20px';
      remoteVideo.style.width = '180px';
      document.body.appendChild(remoteVideo);
    };
    await peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);
    socket.emit('call_answer', { to: fromUserId, answer });
  } catch (err) {
    showErrorDialog('Accept call error', err.message, '');
  }
}

async function init() {
  await requestNotif();
  const meRes = await fetch('/me');
  if (meRes.status === 401) return renderAuth();
  currentUser = await meRes.json();
  await loadBlocks();
  document.getElementById('app').innerHTML = \`
    <div class="app">
      <div class="top-bar"></div>
      <div class="main">
        <div class="sidebar">
          <div class="search"><input type="text" id="searchInput" placeholder="search by login or name"></div>
          <div class="users-list"></div>
        </div>
        <div class="chat-area">
          <div class="chat-header"></div>
          <div class="messages"></div>
          <div class="input-area">
            <input type="text" id="messageInput" placeholder="type a message...">
            <input type="file" id="fileInput" style="display:none;">
            <button id="sendBtn">send</button>
            <button id="fileBtn">file</button>
          </div>
        </div>
      </div>
    </div>
  \`;
  await loadProfile();
  await renderUsersList();
  initSocket();
  const searchInput = document.getElementById('searchInput');
  searchInput.oninput = () => {
    const term = searchInput.value.toLowerCase();
    document.querySelectorAll('.user-item').forEach(el => {
      const login = el.querySelector('.user-login')?.innerText.toLowerCase();
      const name = el.querySelector('.user-name')?.innerText.toLowerCase();
      el.style.display = (login.includes(term) || name.includes(term)) ? 'flex' : 'none';
    });
  };
  const sendBtn = document.getElementById('sendBtn');
  const msgInput = document.getElementById('messageInput');
  const fileBtn = document.getElementById('fileBtn');
  const fileInput = document.getElementById('fileInput');
  sendBtn.onclick = async () => {
    if (!selectedUserId || blockedUsers.has(selectedUserId)) return alert('blocked or no chat selected');
    const text = msgInput.value.trim();
    if (!text) return;
    socket.emit('private_message', { to_id: selectedUserId, text });
    msgInput.value = '';
  };
  msgInput.oninput = () => {
    if (!selectedUserId || blockedUsers.has(selectedUserId)) return;
    socket.emit('typing', { to_id: selectedUserId, typing: true });
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => socket.emit('typing', { to_id: selectedUserId, typing: false }), 1000);
  };
  fileBtn.onclick = () => fileInput.click();
  fileInput.onchange = async (e) => {
    const file = e.target.files[0];
    if (!file || file.size > 20*1024*1024) return alert('max file size 20 MB');
    if (!selectedUserId || blockedUsers.has(selectedUserId)) return alert('blocked');
    const form = new FormData();
    form.append('file', file);
    form.append('to_id', selectedUserId);
    const res = await fetch('/upload', { method: 'POST', body: form });
    if (!res.ok) {
      const err = await res.json();
      showErrorDialog('Upload error', err.error || 'upload failed', err.details || '');
    }
    fileInput.value = '';
  };
}

init();
</script>
</body>
</html>`);
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`uxtes running on port ${port}`));
