const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const UAParser = require('ua-parser-js');

const app = express();
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session (simple, for a single account)
app.use(session({
  secret: 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24*60*60*1000 } // 1 day
}));

// Single account (from your memory)
const ACCOUNT_EMAIL = 's-abdallah.ali@zewailcity.edu.eg';
const ACCOUNT_PASS = 'Abdallah2020=';

// helper to get IP (works behind proxies if x-forwarded-for is set)
function getIP(req) {
  const xff = (req.headers['x-forwarded-for'] || '').split(',').shift().trim();
  if (xff) return xff;
  return req.socket.remoteAddress;
}

// Serve login page (index.html in /public)
app.get('/', (req, res) => {
  if (req.session && req.session.logged) return res.redirect('/dashboard.html');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// handle login
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (email === ACCOUNT_EMAIL && password === ACCOUNT_PASS) {
    req.session.logged = true;
    req.session.user = email;
    return res.json({ ok: true, redirect: '/dashboard.html' });
  }
  return res.status(401).json({ ok: false, message: 'Invalid credentials' });
});

// handle logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// endpoint to receive client info and save to logs.json
app.post('/log', (req, res) => {
  if (!req.session || !req.session.logged) return res.status(401).json({ ok: false });

  const clientIP = getIP(req);
  const ua = req.headers['user-agent'] || '';
  const parser = new UAParser(ua);
  const uaResult = parser.getResult();

  const payload = {
    email: req.session.user || null,
    timestamp: new Date().toISOString(),
    ip: clientIP,
    geolocation: req.body.geolocation || null, // { latitude, longitude, accuracy }
    userAgent: ua,
    browser: uaResult.browser,
    os: uaResult.os,
    device: uaResult.device,
    additional: req.body.additional || null
  };

  // ensure logs file exists
  const logsPath = path.join(__dirname, 'logs.json');
  let line = JSON.stringify(payload) + '\n';
  fs.appendFile(logsPath, line, (err) => {
    if (err) {
      console.error('Failed to write log:', err);
      return res.status(500).json({ ok: false, message: 'Server error' });
    }
    return res.json({ ok: true });
  });
});

// protected endpoint to view logs (only when logged-in)
app.get('/logs', (req, res) => {
  if (!req.session || !req.session.logged) return res.status(401).send('Unauthorized');
  const logsPath = path.join(__dirname, 'logs.json');
  if (!fs.existsSync(logsPath)) return res.send('No logs yet.');
  res.sendFile(logsPath);
});

// start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on http://localhost:${PORT}`);
});
