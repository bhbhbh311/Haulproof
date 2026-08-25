// SQLite data layer. One file DB for the whole service (swap for Postgres in prod).
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(path.join(DATA_DIR, 'pods'), { recursive: true });

const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('journal_mode = WAL');

db.exec(`
-- A customer (tenant). HaulProof is sold to many carriers; each is fully walled off.
CREATE TABLE IF NOT EXISTS orgs (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  deviceKey    TEXT UNIQUE NOT NULL,             -- drivers of this customer authenticate with this key
  contactName  TEXT,
  contactEmail TEXT,
  contactPhone TEXT,
  address      TEXT,
  active       INTEGER NOT NULL DEFAULT 1,
  createdAt    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,
  orgId      TEXT,                                 -- which customer this login belongs to (NULL = platform super-admin)
  email      TEXT UNIQUE NOT NULL,
  name       TEXT,
  role       TEXT NOT NULL DEFAULT 'dispatcher',   -- 'superadmin' | 'admin' | 'dispatcher' | 'sales'
  passHash   TEXT NOT NULL,
  createdAt  INTEGER NOT NULL
);

-- A load is identified by our loadNumber AND/OR the customer's PO number.
CREATE TABLE IF NOT EXISTS loads (
  id          TEXT PRIMARY KEY,
  orgId       TEXT,
  loadNumber  TEXT,
  poNumber    TEXT,
  customer    TEXT,
  consignee   TEXT,
  origin      TEXT,
  destination TEXT,
  status      TEXT NOT NULL DEFAULT 'open',
  createdBy   TEXT,
  createdAt   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loads_po   ON loads(poNumber);
CREATE INDEX IF NOT EXISTS idx_loads_load ON loads(loadNumber);

-- A POD is a document uploaded/prepared by dispatch and signed by a driver.
CREATE TABLE IF NOT EXISTS pods (
  id          TEXT PRIMARY KEY,
  orgId       TEXT,
  loadId      TEXT,
  loadNumber  TEXT,
  poNumber    TEXT,
  consignee   TEXT,
  docType     TEXT DEFAULT 'POD',
  filename    TEXT,
  filepath    TEXT NOT NULL,
  sizeBytes   INTEGER,
  gps         TEXT,
  signedAt    INTEGER,
  recipients  TEXT,
  driver      TEXT,
  fields      TEXT,
  status      TEXT NOT NULL DEFAULT 'received',
  uploadedAt  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pods_po        ON pods(poNumber);
CREATE INDEX IF NOT EXISTS idx_pods_load      ON pods(loadNumber);
CREATE INDEX IF NOT EXISTS idx_pods_consignee ON pods(consignee);

-- A named driver on a customer's roster. Drivers don't log into the portal; each gets a personal
-- token baked into their driver-app link, so signing is attributed to them and they can be revoked alone.
CREATE TABLE IF NOT EXISTS drivers (
  id         TEXT PRIMARY KEY,
  orgId      TEXT NOT NULL,
  name       TEXT NOT NULL,
  phone      TEXT,
  token      TEXT UNIQUE NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1,
  createdAt  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drivers_org   ON drivers(orgId);
CREATE INDEX IF NOT EXISTS idx_drivers_token ON drivers(token);

-- Reusable signature-box layouts a customer approves for a standard form (Phase 2: auto-apply).
CREATE TABLE IF NOT EXISTS templates (
  id         TEXT PRIMARY KEY,
  orgId      TEXT NOT NULL,
  name       TEXT NOT NULL,
  docType    TEXT DEFAULT 'POD',
  fields     TEXT,                                 -- JSON signature/date field layout
  createdBy  TEXT,
  createdAt  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_templates_org ON templates(orgId);
`);

// --- Migrations for databases created before multi-customer support ---
function hasColumn(table, col) {
  try { return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col); }
  catch { return false; }
}
function addColumn(table, col, decl) {
  if (!hasColumn(table, col)) { try { db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`); } catch (e) {} }
}
addColumn('users', 'orgId', 'TEXT');
addColumn('loads', 'orgId', 'TEXT');
addColumn('pods',  'orgId', 'TEXT');
addColumn('pods',  'fields', 'TEXT');   // older DBs predate the signature template column

// Org indexes are created AFTER the columns are guaranteed to exist (legacy DBs add orgId above).
db.exec(`
CREATE INDEX IF NOT EXISTS idx_loads_org ON loads(orgId);
CREATE INDEX IF NOT EXISTS idx_pods_org  ON pods(orgId);
`);

module.exports = { db, DATA_DIR };
