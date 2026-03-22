/**
 * SHIELD Test Fixture — Vulnerable Express.js Application
 * DO NOT USE IN PRODUCTION — contains intentional vulnerabilities
 */
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const db = require('./db'); // assume mysql2 or pg

const app = express();
app.use(express.json());

// CWE-798: Hardcoded credentials
const jwtSecret = 'myhardcodedsupersecretjwtkey1234';
const dbPassword = 'admin:SuperSecret123@localhost';

// CWE-89: SQL Injection via template literal
app.get('/api/users', async (req, res) => {
  const userId = req.query.id;
  // BAD: direct string interpolation in SQL query
  const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
  res.json(result.rows);
});

// CWE-89: SQL Injection via string concatenation
app.post('/api/search', async (req, res) => {
  const { username } = req.body;
  // BAD: string concatenation
  const sql = "SELECT * FROM users WHERE username = '" + username + "'";
  const result = await db.query(sql);
  res.json(result.rows);
});

// CWE-78: Command Injection via exec with user input
app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  // BAD: user-controlled command argument
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.json({ output: stdout, error: stderr });
  });
});

// CWE-78: Command injection with template literal
app.post('/api/convert', (req, res) => {
  const { filename } = req.body;
  exec(`ffmpeg -i /uploads/${filename} -o /converted/${filename}.mp4`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ result: stdout });
  });
});

// CWE-22: Path Traversal
app.get('/api/files/:filename', (req, res) => {
  const filename = req.params.filename;
  // BAD: user-controlled path with path.join
  const filePath = path.join('/var/uploads', filename);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

// CWE-22: Path traversal — direct concatenation
app.get('/api/logs', (req, res) => {
  const logFile = req.query.file;
  fs.readFileSync('/var/logs/' + logFile, 'utf8');
});

// CWE-306: Missing authentication on sensitive admin route
app.get('/api/admin/users', async (req, res) => {
  // BAD: no auth middleware
  const users = await db.query('SELECT * FROM users');
  res.json(users.rows);
});

// CWE-306: Missing auth on payment route
app.delete('/api/admin/delete', async (req, res) => {
  // BAD: destructive operation without authentication
  const { userId } = req.body;
  await db.query(`DELETE FROM users WHERE id = ${userId}`);
  res.json({ success: true });
});

// CWE-94: eval() with dynamic input
app.post('/api/calculate', (req, res) => {
  const { formula } = req.body;
  // BAD: eval with user input
  const result = eval(formula);
  res.json({ result });
});

// CWE-1321: Prototype Pollution
app.post('/api/settings', (req, res) => {
  const userSettings = req.body;
  // BAD: Object.assign with unvalidated user input
  const settings = Object.assign({}, defaultSettings, userSettings);
  res.json({ settings });
});

const defaultSettings = { theme: 'dark', language: 'en' };

app.listen(3000, () => console.log('Server started on port 3000'));
