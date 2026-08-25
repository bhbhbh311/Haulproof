// SQLite data layer. One file DB for the whole service (swap for Postgres in prod).
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(path.join(DATA_DIR, 'pods'), { recursive: true });

const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id         TEXT PRIMARY KEY,
  email      TEXT UNIQUE NOT NULL,
  name       TEXT,
  role       TEXT NOT NULL DEFAULT 'dispatcher',   -- 'admin' | 'dispatcher' | 'sales'
  passHash   TEXT NOT NULL,
  createdAt  INTEGER NOT NULL
);

-- A load is identified by our loadNumber AND/OR the customer's PO number.
CREATE TABLE IF NOT EXISTS loads (
  id          TEXT PRIMARY KEY,
  loadNumber  TEXT,
  poNumber    TEXT,                                 -- customer PO — how sales/dispatch look it up
  customer    TEXT,
  consignee   TEXT,
  origin      TEXT,
  destination TEXT,
  status      TEXT NOT NULL DEFAULT 'open',         -- 'open' | 'delivered' | 'invoiced'
  createdBy   TEXT,
  createdAt   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loads_po   ON loads(poNumber);
CREATE INDEX IF NOT EXISTS idx_loads_load ON loads(loadNumber);

-- A POD is a signed document uploaded from the driver app.
CREATE TABLE IF NOT EXISTS pods (
  id          TEXT PRIMARY KEY,
  loadId      TEXT,
  loadNumber  TEXT,
  poNumber    TEXT,
  consignee   TEXT,
  docType     TEXT DEFAULT 'POD',                   -- POD | BOL | LUMPER | OTHER
  filename    TEXT,
  filepath    TEXT NOT NULL,
  sizeBytes   INTEGER,
  gps         TEXT,                                 -- JSON {lat,lng}
  signedAt    INTEGER,
  recipients  TEXT,                                 -- JSON [emails] the consignee wants a copy sent to
  driver      TEXT,
  fields      TEXT,                                 -- JSON signature/date template a dispatcher placed
  status      TEXT NOT NULL DEFAULT 'received',     -- received | prepared | signed | emailed
  uploadedAt  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pods_po        ON pods(poNumber);
CREATE INDEX IF NOT EXISTS idx_pods_load      ON pods(loadNumber);
CREATE INDEX IF NOT EXISTS idx_pods_consignee ON pods(consignee);
`);

// Migrate older databases that predate the signature-template column.
try { db.prepare(`SELECT fields FROM pods LIMIT 1`).get(); }
catch { try { db.exec(`ALTER TABLE pods ADD COLUMN fields TEXT`); } catch {} }

module.exports = { db, DATA_DIR };
