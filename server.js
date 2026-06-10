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
  const old = await pool.query('SELECT file_uuid FROM messages WHERE file_uuid IS NOT NULL AND sent_at < NOW() - INTERVAL \'15 days\' AND file_deleted = FALSE');
  for (let row of old.rows) {
    const p = path.join(uploadDir, row.file_uuid);
    if (fs.existsSync(p)) fs.unlinkSync(p);
    await pool.query('UPDATE messages SET file_deleted = TRUE WHERE file_uuid = $1', [row.file_uuid]);
  }
});

app.post('/register', async (req, res) => {
  const { login, password } = req.body;
  if (!login || !password) return res.status(400).json({ error: 'required' });
  const exists = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
  if (exists.rows.length) return res.status(400).json({ error: 'login taken' });
  const hash = await bcrypt.hash(password, 10);
  const result = await pool.query('INSERT INTO users (login, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id', [login, hash, login]);
  req.session.userId = result.rows[0].id;
  res.json({ ok: true });
});

app.post('/login', async (req, res) => {
  const { login, password, token } = req.body;
  const user = await pool.query('SELECT id, password_hash, twofa_secret FROM users WHERE login = $1', [login]);
  if (!user.rows.length) return res.status(401).json({ error: 'invalid' });
  const match = await bcrypt.compare(password, user.rows[0].password_hash);
  if (!match) return res.status(401).json({ error: 'invalid' });
  if (user.rows[0].twofa_secret) {
    if (!token) return res.status(401).json({ need2fa: true });
    const verified = speakeasy.totp.verify({ secret: user.rows[0].twofa_secret, encoding: 'base32', token });
    if (!verified) return res.status(401).json({ error: '2fa fail' });
  }
  req.session.userId = user.rows[0].id;
  res.json({ ok: true });
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
  const user = await pool.query('SELECT id, login, display_name, bio, avatar, twofa_secret IS NOT NULL as has2fa FROM users WHERE id = $1', [req.session.userId]);
  res.json(user.rows[0]);
});

app.post('/profile', async (req, res) => {
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
});

app.get('/users', async (req, res) => {
  if (!req.session.userId) return res.status(401).json([]);
  const users = await pool.query('SELECT id, login, display_name, avatar FROM users WHERE id != $1', [req.session.userId]);
  res.json(users.rows);
});

app.post('/block', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
  const { block_user_id, block } = req.body;
  if (block) {
    await pool.query('INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [req.session.userId, block_user_id]);
  } else {
    await pool.query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, block_user_id]);
  }
  res.json({ ok: true });
});

app.get('/blocks', async (req, res) => {
  if (!req.session.userId) return res.status(401).json([]);
  const blocks = await pool.query('SELECT blocked_id FROM blocks WHERE blocker_id = $1', [req.session.userId]);
  res.json(blocks.rows.map(r => r.blocked_id));
});

app.post('/deletechat', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
  const { with_user_id } = req.body;
  await pool.query('DELETE FROM messages WHERE (from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1)', [req.session.userId, with_user_id]);
  res.json({ ok: true });
});

app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
  const { to_id } = req.body;
  if (!req.file) return res.status(400).json({ error: 'no file' });
  const blocked = await pool.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [req.session.userId, to_id]);
  if (blocked.rows.length) return res.status(403).json({ error: 'blocked' });
  const fileUuid = `${Date.now()}_${req.file.filename}`;
  const newPath = path.join(uploadDir, fileUuid);
  fs.renameSync(req.file.path, newPath);
  const msg = await pool.query('INSERT INTO messages (from_id, to_id, text, file_uuid, file_name, file_size) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id', 
    [req.session.userId, to_id, `[file: ${req.file.originalname}]`, fileUuid, req.file.originalname, req.file.size]);
  const data = { id: msg.rows[0].id, from_id: req.session.userId, to_id, text: `[file: ${req.file.originalname}]`, file_uuid: fileUuid, file_name: req.file.originalname, file_size: req.file.size, sent_at: new Date() };
  io.to(`user_${to_id}`).emit('new_message', data);
  res.json({ ok: true, message: data });
});

app.get('/download/:uuid', async (req, res) => {
  if (!req.session.userId) return res.status(401).send('unauth');
  const file = await pool.query('SELECT file_uuid, file_name, file_deleted, from_id, to_id FROM messages WHERE file_uuid = $1', [req.params.uuid]);
  if (!file.rows.length || file.rows[0].file_deleted) return res.status(404).send('expired');
  if (file.rows[0].from_id !== req.session.userId && file.rows[0].to_id !== req.session.userId) return res.status(403).send('not allowed');
  const p = path.join(uploadDir, file.rows[0].file_uuid);
  if (!fs.existsSync(p)) return res.status(404).send('missing');
  res.download(p, file.rows[0].file_name);
});

app.get('/history/:userId', async (req, res) => {
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
});

app.get('/2fa/qrcode', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'unauth' });
  const user = await pool.query('SELECT login FROM users WHERE id = $1', [req.session.userId]);
  const secret = speakeasy.generateSecret({ length: 20 });
  const otpauth = speakeasy.otpauthURL({ secret: secret.ascii, label: `uxtes:${user.rows[0].login}`, algorithm: 'sha1' });
  const qr = await QRCode.toDataURL(otpauth);
  res.json({ secret: secret.base32, qr });
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
    const { to_id, text } = data;
    if (!text.trim()) return;
    const blocked = await pool.query('SELECT 1 FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [userId, to_id]);
    if (blocked.rows.length) return;
    const msg = await pool.query('INSERT INTO messages (from_id, to_id, text) VALUES ($1, $2, $3) RETURNING id, sent_at', [userId, to_id, text]);
    const messageData = { id: msg.rows[0].id, from_id: userId, to_id, text, sent_at: msg.rows[0].sent_at };
    io.to(`user_${to_id}`).emit('new_message', messageData);
    socket.emit('new_message', messageData);
  });
  socket.on('typing', ({ to_id, typing }) => {
    socket.to(`user_${to_id}`).emit('typing', { from_id: userId, typing });
  });
  socket.on('call_offer', (data) => { socket.to(`user_${data.to}`).emit('call_offer', { from: userId, offer: data.offer }); });
  socket.on('call_answer', (data) => { socket.to(`user_${data.to}`).emit('call_answer', { from: userId, answer: data.answer }); });
  socket.on('ice_candidate', (data) => { socket.to(`user_${data.to}`).emit('ice_candidate', { from: userId, candidate: data.candidate }); });
  socket.on('disconnect', () => {});
});

app.get('*', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>uxtes · skype 2015 vibe</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', 'Arial', sans-serif; }
    body { background: white; color: black; height: 100vh; display: flex; justify-content: center; align-items: center; }
    .app { width: 100%; max-width: 1400px; height: 100%; display: flex; flex-direction: column; background: white; }
    .top-bar { display: flex; justify-content: space-between; padding: 10px 16px; border-bottom: 1px solid #ccc; background: #f5f5f5; }
    .top-bar button { background: white; border: 1px solid #aaa; padding: 4px 10px; cursor: pointer; font-size: 12px; }
    .main { display: flex; flex: 1; overflow: hidden; }
    .sidebar { width: 260px; border-right: 1px solid #ddd; display: flex; flex-direction: column; background: #fafafa; }
    .search { padding: 10px; border-bottom: 1px solid #ddd; }
    .search input { width: 100%; padding: 6px; border: 1px solid #ccc; background: white; }
    .users-list { flex: 1; overflow-y: auto; }
    .user-item { padding: 8px 12px; border-bottom: 1px solid #eee; cursor: pointer; display: flex; align-items: center; gap: 8px; }
    .user-item:hover { background: #ececec; }
    .avatar { width: 32px; height: 32px; background: #ccc; display: flex; align-items: center; justify-content: center; font-size: 14px; color: #222; }
    .user-info { flex: 1; }
    .user-name { font-size: 14px; font-weight: normal; }
    .user-login { font-size: 11px; color: #666; }
    .chat-area { flex: 1; display: flex; flex-direction: column; background: white; }
    .chat-header { padding: 10px 16px; border-bottom: 1px solid #ddd; background: #f9f9f9; display: flex; justify-content: space-between; align-items: center; }
    .chat-header button { background: white; border: 1px solid #aaa; padding: 4px 8px; font-size: 11px; cursor: pointer; margin-left: 6px; }
    .messages { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 6px; }
    .message { max-width: 75%; padding: 6px 10px; background: #f1f1f1; align-self: flex-start; font-size: 13px; }
    .message.own { align-self: flex-end; background: #e1e1e1; }
    .message-text { word-break: break-word; }
    .file-link { color: #0066cc; text-decoration: underline; cursor: pointer; }
    .typing-indicator { font-size: 11px; color: #888; margin-left: 12px; margin-bottom: 4px; font-style: italic; }
    .input-area { padding: 10px; border-top: 1px solid #ddd; display: flex; gap: 6px; flex-wrap: wrap; background: white; }
    .input-area input[type="text"] { flex: 1; padding: 6px; border: 1px solid #ccc; font-size: 13px; }
    .input-area button { padding: 6px 12px; background: white; border: 1px solid #aaa; cursor: pointer; font-size: 12px; }
    .profile-panel { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; z-index: 100; }
    .profile-card { background: white; width: 380px; padding: 20px; border: 1px solid #888; display: flex; flex-direction: column; gap: 10px; }
    .profile-card input, .profile-card textarea { width: 100%; padding: 6px; border: 1px solid #ccc; font-size: 13px; }
    .call-controls { display: flex; gap: 6px; margin-left: auto; }
    video { width: 180px; background: black; position: fixed; bottom: 20px; right: 20px; z-index: 200; border: 1px solid white; }
    .block-badge { font-size: 11px; color: #c00; margin-left: 8px; }
    @media (max-width: 700px) { .sidebar { width: 220px; } .message { max-width: 85%; } }
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

function playBeep() {
  if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  const osc = audioCtx.createOscillator();
  const gain = audioCtx.createGain();
  osc.connect(gain);
  gain.connect(audioCtx.destination);
  osc.frequency.value = 800;
  gain.gain.value = 0.2;
  osc.start();
  gain.gain.exponentialRampToValueAtTime(0.00001, audioCtx.currentTime + 0.5);
  osc.stop(audioCtx.currentTime + 0.5);
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
    <div style="width: 300px; margin: auto; background: white; padding: 20px; border: 1px solid #aaa;">
      <h2 style="font-weight: normal;">uxtes</h2>
      <div id="authForm">
        <input type="text" id="login" placeholder="login" style="width:100%; margin:8px 0; padding:6px;">
        <input type="password" id="password" placeholder="password" style="width:100%; margin:8px 0; padding:6px;">
        <div id="twofaField" style="display:none;"><input type="text" id="twofaToken" placeholder="2FA code"></div>
        <button id="doLogin" style="margin-right:6px;">Login</button>
        <button id="doReg">Register</button>
      </div>
    </div>
  \`;
  document.getElementById('doLogin').onclick = async () => {
    const login = document.getElementById('login').value;
    const password = document.getElementById('password').value;
    let token = document.getElementById('twofaToken')?.value;
    const res = await fetch('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({login, password, token}) });
    const data = await res.json();
    if (res.ok) location.reload();
    else if (data.need2fa) document.getElementById('twofaField').style.display = 'block';
    else alert('fail');
  };
  document.getElementById('doReg').onclick = async () => {
    const login = document.getElementById('login').value;
    const password = document.getElementById('password').value;
    const res = await fetch('/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({login, password}) });
    if (res.ok) location.reload();
    else alert('register fail');
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
    document.querySelector('.messages').innerHTML = '';
  }
}

async function toggleBlock(userId) {
  const currentlyBlocked = blockedUsers.has(userId);
  const action = !currentlyBlocked;
  await fetch('/block', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ block_user_id: userId, block: action }) });
  await loadBlocks();
  if (selectedUserId === userId) {
    if (action) {
      document.querySelector('.messages').innerHTML = '<div style="padding:20px;text-align:center;">blocked</div>';
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
  container.innerHTML = users.map(u => \`
    <div class="user-item" data-id="\${u.id}">
      <div class="avatar">\${(u.display_name || u.login)[0].toUpperCase()}</div>
      <div class="user-info">
        <div class="user-name">\${escapeHtml(u.display_name || u.login)} \${blockedUsers.has(u.id) ? '<span class="block-badge">[blocked]</span>' : ''}</div>
        <div class="user-login">@\${escapeHtml(u.login)}</div>
      </div>
    </div>
  \`).join('');
  document.querySelectorAll('.user-item').forEach(el => {
    el.onclick = () => selectUser(parseInt(el.dataset.id));
  });
}

function escapeHtml(str) { return str.replace(/[&<>]/g, function(m){if(m==='&') return '&amp;'; if(m==='<') return '&lt;'; if(m==='>') return '&gt;'; return m;}); }

async function selectUser(userId) {
  selectedUserId = userId;
  document.querySelector('.chat-header').innerHTML = \`
    <span>\${document.querySelector(\`.user-item[data-id="\${userId}"] .user-name\`)?.innerText || 'chat'}</span>
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
      <div style="font-size:10px;color:#888;">\${new Date(m.sent_at).toLocaleTimeString()}</div>
    </div>
  \`).join('');
  container.scrollTop = container.scrollHeight;
}

function renderMessageText(m) {
  if (m.file_uuid && !m.file_deleted) {
    return \`📎 <a class="file-link" onclick="downloadFile('\${m.file_uuid}')">\${escapeHtml(m.file_name)}</a> (\${(m.file_size/1024).toFixed(0)} KB)\`;
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
      <h3>profile</h3>
      <input type="text" id="displayName" placeholder="display name" value="\${escapeHtml(currentUser.display_name)}">
      <textarea id="bio" placeholder="bio" rows="2">\${escapeHtml(currentUser.bio)}</textarea>
      <input type="password" id="newPass" placeholder="new password (leave empty to keep)">
      <div><label><input type="checkbox" id="twofaCheck" \${currentUser.has2fa ? 'checked' : ''}> enable 2FA</label></div>
      <div id="twofaQr" style="display:none;"></div>
      <input type="text" id="twofaTokenInput" placeholder="2FA token to confirm" style="display:none;">
      <button id="saveProfile">save</button>
      <button id="closeModal">close</button>
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
      qrDiv.innerHTML = \`<img src="\${data.qr}" style="width:150px;"><br><code>\${data.secret}</code>\`;
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
        container.insertAdjacentHTML('beforeend', \`
          <div class="message \${msg.from_id === currentUser.id ? 'own' : ''}">
            <div class="message-text">\${renderMessageText(msg)}</div>
            <div style="font-size:10px;color:#888;">\${new Date(msg.sent_at).toLocaleTimeString()}</div>
          </div>
        \`);
        container.scrollTop = container.scrollHeight;
      }
    }
    if (msg.from_id !== currentUser.id) {
      notify(msg.from_id, msg.text);
    }
  });
  socket.on('typing', ({ from_id, typing }) => {
    if (from_id === selectedUserId && !blockedUsers.has(from_id)) {
      const indicator = document.querySelector('.typing-indicator');
      if (typing) {
        if (!indicator) document.querySelector('.messages')?.insertAdjacentHTML('afterend', '<div class="typing-indicator">/* typing */</div>');
        else indicator.style.display = 'block';
      } else {
        if (indicator) indicator.remove();
      }
    }
  });
  socket.on('call_offer', async ({ from, offer }) => {
    if (confirm('incoming call from user ' + from)) acceptCall(from, offer);
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
  if (blockedUsers.has(toUserId)) return alert('blocked');
  localStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
  localVideo = document.createElement('video');
  localVideo.srcObject = localStream;
  localVideo.autoplay = true;
  localVideo.style.position = 'fixed';
  localVideo.style.bottom = '20px';
  localVideo.style.right = '20px';
  localVideo.style.width = '180px';
  localVideo.style.border = '1px solid white';
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
    document.body.appendChild(remoteVideo);
  };
  const offer = await peerConnection.createOffer();
  await peerConnection.setLocalDescription(offer);
  socket.emit('call_offer', { to: toUserId, offer });
}

async function acceptCall(fromUserId, offer) {
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
          <div class="search"><input type="text" id="searchInput" placeholder="search by login"></div>
          <div class="users-list"></div>
        </div>
        <div class="chat-area">
          <div class="chat-header"></div>
          <div class="messages"></div>
          <div class="input-area">
            <input type="text" id="messageInput" placeholder="message...">
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
    if (!selectedUserId || blockedUsers.has(selectedUserId)) return alert('blocked or no chat');
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
    if (!file || file.size > 20*1024*1024) return alert('max 20mb');
    if (!selectedUserId || blockedUsers.has(selectedUserId)) return alert('blocked');
    const form = new FormData();
    form.append('file', file);
    form.append('to_id', selectedUserId);
    const res = await fetch('/upload', { method: 'POST', body: form });
    if (res.ok) fileInput.value = '';
    else alert('upload fail');
  };
}

init();
</script>
</body>
</html>`);
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`uxtes running on port ${port}`));
