// Creates the first admin user so you can log in. Run: npm run seed
require('dotenv').config();
const { db } = require('./db');
const { createUser } = require('./auth');

const email = process.env.ADMIN_EMAIL || 'admin@callahantrans.com';
const password = process.env.ADMIN_PASSWORD || 'changeme123';

const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email.toLowerCase());
if (existing) {
  console.log(`Admin already exists: ${email}`);
} else {
  createUser({ email, name: 'Administrator', role: 'admin', password });
  console.log(`Created admin: ${email} / ${password}  (change this password)`);
}
process.exit(0);
