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
  kind         TEXT NOT NULL DEFAULT 'customer',  -- 'customer' | 'carrier'
  deviceKey    TEXT UNIQUE NOT NULL,             -- drivers of this org authenticate with this key
  mcNumber     TEXT,                             -- carrier MC/docket number
  dotNumber    TEXT,                             -- carrier USDOT number
  fmcsaVerified INTEGER NOT NULL DEFAULT 0,      -- 1 = confirmed against FMCSA, 0 = manual/override
  allowedToOperate TEXT,                         -- FMCSA "allowed to operate" (Y/N) at time of verification
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
  carrierId   TEXT,                               -- assigned carrier (orgs.id where kind='carrier')
  carrierName TEXT,                               -- snapshot of the carrier name at assignment
  driverName  TEXT,                               -- driver the carrier put on this load
  truck       TEXT,
  trailer     TEXT,
  createdBy   TEXT,
  createdAt   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_loads_po      ON loads(poNumber);
CREATE INDEX IF NOT EXISTS idx_loads_load    ON loads(loadNumber);
-- (idx_loads_carrier is created after migrations, once the carrierId column is guaranteed to exist)

-- A timeline of everything that happened to a load / PO#, for the admin's recorded history.
CREATE TABLE IF NOT EXISTS load_events (
  id         TEXT PRIMARY KEY,
  orgId      TEXT NOT NULL,                        -- the customer org that owns the load
  loadId     TEXT,
  poNumber   TEXT,
  type       TEXT NOT NULL,                        -- created | document_uploaded | prepared | carrier_assigned | driver_assigned | signed | note
  detail     TEXT,                                 -- human-readable detail
  actor      TEXT,                                 -- who did it (email or driver/carrier name)
  createdAt  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_load ON load_events(loadId);
CREATE INDEX IF NOT EXISTS idx_events_po   ON load_events(poNumber);

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
// Carrier + assignment columns (added to existing installs).
addColumn('orgs',  'kind', "TEXT NOT NULL DEFAULT 'customer'");
addColumn('orgs',  'mcNumber', 'TEXT');
addColumn('orgs',  'dotNumber', 'TEXT');
addColumn('orgs',  'fmcsaVerified', 'INTEGER NOT NULL DEFAULT 0');
addColumn('orgs',  'allowedToOperate', 'TEXT');
addColumn('loads', 'carrierId', 'TEXT');
addColumn('loads', 'carrierName', 'TEXT');
addColumn('loads', 'driverName', 'TEXT');
addColumn('loads', 'truck', 'TEXT');
addColumn('loads', 'trailer', 'TEXT');
addColumn('loads', 'brokerId', 'TEXT');    // a customer can hand a load to a broker, who then assigns the carrier
addColumn('loads', 'brokerName', 'TEXT');
addColumn('drivers', 'email', 'TEXT');   // optional driver email (for sending their link)
addColumn('drivers', 'pinHash', 'TEXT'); // optional per-driver PIN (bcrypt) that gates their link
// Carrier → customer document hand-off: a carrier-owned doc can be offered to a customer who then accepts it.
addColumn('pods', 'assignedDriverId', 'TEXT');   // a prepared doc can be assigned to a specific driver
addColumn('pods', 'assignedDriverName', 'TEXT');
addColumn('pods', 'assignedFulfilledAt', 'INTEGER');   // set when the assigned prepared doc gets signed → drops off "Your loads"
addColumn('pods', 'signedByDriverId', 'TEXT');   // which driver (personal token) signed this → powers "your recent documents"
addColumn('pods', 'offeredToOrgId', 'TEXT');
addColumn('pods', 'claimStatus', 'TEXT');   // null/'none' | 'offered' | 'accepted' | 'declined'
addColumn('pods', 'offeredFromOrgId', 'TEXT'); // on the customer's accepted copy: which carrier sent it
// Multi-role orgs (an org can be e.g. both a customer AND a receiver) + parent/child locations.
addColumn('orgs', 'roles', 'TEXT');       // JSON array of roles, e.g. ["customer","receiver"]; backfilled from kind
addColumn('orgs', 'parentId', 'TEXT');    // optional parent org (a location rolls up to its parent company)
// Receiver/consignee link on a signed document, so a receiver can look up what was delivered to them
// even when the load was created by a different customer.
addColumn('pods', 'receiverId', 'TEXT');
addColumn('pods', 'receiverName', 'TEXT');
// Backfill roles for existing orgs from their single kind.
try {
  const _needRoles = db.prepare(`SELECT id, kind FROM orgs WHERE roles IS NULL OR roles = ''`).all();
  const _setRoles = db.prepare(`UPDATE orgs SET roles = ? WHERE id = ?`);
  for (const o of _needRoles) { _setRoles.run(JSON.stringify([o.kind || 'customer']), o.id); }
} catch (e) { console.error('roles backfill failed', e.message); }

// Org indexes are created AFTER the columns are guaranteed to exist (legacy DBs add orgId above).
db.exec(`
CREATE INDEX IF NOT EXISTS idx_loads_org     ON loads(orgId);
CREATE INDEX IF NOT EXISTS idx_pods_org      ON pods(orgId);
CREATE INDEX IF NOT EXISTS idx_loads_carrier ON loads(carrierId);
CREATE INDEX IF NOT EXISTS idx_loads_broker  ON loads(brokerId);
CREATE TABLE IF NOT EXISTS broker_carriers (
  brokerId  TEXT NOT NULL,
  carrierId TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  PRIMARY KEY (brokerId, carrierId)
);
-- Which receivers a given customer/carrier/broker works with. The receiver record itself is
-- global (shared, deduped), but a customer only sees the receivers they have linked here.
CREATE TABLE IF NOT EXISTS customer_receivers (
  orgId      TEXT NOT NULL,
  receiverId TEXT NOT NULL,
  createdAt  INTEGER NOT NULL,
  PRIMARY KEY (orgId, receiverId)
);
CREATE INDEX IF NOT EXISTS idx_custrecv_org ON customer_receivers(orgId);
-- A customer's saved roster of approved carriers / brokers (partnerKind = 'carrier' | 'broker').
CREATE TABLE IF NOT EXISTS approved_partners (
  ownerOrgId   TEXT NOT NULL,
  partnerOrgId TEXT NOT NULL,
  partnerKind  TEXT NOT NULL,
  createdAt    INTEGER NOT NULL,
  PRIMARY KEY (ownerOrgId, partnerOrgId)
);
CREATE INDEX IF NOT EXISTS idx_approved_owner ON approved_partners(ownerOrgId);
CREATE TABLE IF NOT EXISTS access_requests (
  id TEXT PRIMARY KEY,
  code TEXT,
  kind TEXT,            -- 'company' | 'driver'
  orgType TEXT,         -- 'customer' | 'carrier' | 'broker' (company requests)
  contactName TEXT,
  email TEXT,
  phone TEXT,
  company TEXT,
  mcNumber TEXT,
  dotNumber TEXT,
  targetCompany TEXT,   -- driver requests: which company they want to join (free text)
  note TEXT,
  status TEXT DEFAULT 'pending',   -- pending | granted | denied
  thread TEXT DEFAULT '[]',
  createdOrgId TEXT,
  createdDriverId TEXT,
  createdAt INTEGER,
  decidedAt INTEGER
);
CREATE INDEX IF NOT EXISTS idx_reqs_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_reqs_code   ON access_requests(code);
CREATE INDEX IF NOT EXISTS idx_pods_receiver ON pods(receiverId);
CREATE INDEX IF NOT EXISTS idx_orgs_parent   ON orgs(parentId);
`);

module.exports = { db, DATA_DIR };
