'use strict';

/*
 * Modulo de base de datos (SQLite via node:sqlite nativo).
 *
 * NOTA ACADEMICA: este archivo contiene decisiones de diseno INSEGURAS de forma
 * INTENCIONAL (ver README, catalogo de vulnerabilidades). Marcadas con [VULN-xx].
 */

const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = path.join(__dirname, '..', 'data', 'vulnshop.db');
const db = new DatabaseSync(DB_PATH);

// [VULN-A02] Cryptographic Failures: los passwords se "hashean" con MD5 (roto,
// rapido de crackear, sin salt). Lo correcto seria bcrypt/argon2 con salt.
function md5(text) {
  return crypto.createHash('md5').update(String(text)).digest('hex');
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT UNIQUE NOT NULL,
      email      TEXT,
      password   TEXT NOT NULL,          -- [VULN-A02] MD5 sin salt
      role       TEXT NOT NULL DEFAULT 'user',
      full_name  TEXT,
      address    TEXT,
      credit_card TEXT,                   -- [VULN-A02] tarjeta en texto plano
      reset_token INTEGER                 -- [VULN-A04] token de reset secuencial/predecible
    );

    CREATE TABLE IF NOT EXISTS products (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL,
      description TEXT,
      price       REAL NOT NULL DEFAULT 0,
      stock       INTEGER NOT NULL DEFAULT 0,
      image_url   TEXT
    );

    CREATE TABLE IF NOT EXISTS comments (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      username   TEXT,
      body       TEXT,                    -- [VULN-A03] se renderiza sin escapar (XSS almacenado)
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS orders (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL,
      total      REAL NOT NULL DEFAULT 0,
      items_json TEXT,
      status     TEXT DEFAULT 'pagado',
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);
}

function seedIfEmpty() {
  const row = db.prepare('SELECT COUNT(*) AS n FROM users').get();
  if (row.n > 0) return;

  // [VULN-A05] Security Misconfiguration + [VULN-A07]: credenciales por defecto
  // bien conocidas y password debilisimo para el admin.
  const insertUser = db.prepare(
    `INSERT INTO users (username, email, password, role, full_name, address, credit_card)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  insertUser.run('admin', 'admin@vulnshop.local', md5('admin123'), 'admin',
    'Administrador', 'Oficina Central, San Jose', '4111-1111-1111-1111');
  insertUser.run('daniel', 'daniel@vulnshop.local', md5('password'), 'user',
    'Daniel Saborio', 'Alajuela, CR', '5500-0000-0000-0004');
  insertUser.run('alejandro', 'alejandro@vulnshop.local', md5('qwerty'), 'user',
    'Alejandro Cordero', 'Heredia, CR', '3400-0000-0000-009');

  const insertProduct = db.prepare(
    'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)'
  );
  const products = [
    ['Teclado mecanico RGB', 'Switches azules, retroiluminado, USB-C.', 45.99, 25, 'https://picsum.photos/seed/kbd/400/300'],
    ['Mouse gamer 16000 DPI', 'Sensor optico, 7 botones programables.', 29.5, 40, 'https://picsum.photos/seed/mouse/400/300'],
    ['Monitor 27" 144Hz', 'Panel IPS, 1ms, FreeSync.', 219.0, 10, 'https://picsum.photos/seed/monitor/400/300'],
    ['Auriculares inalambricos', 'Cancelacion de ruido, 30h bateria.', 89.99, 18, 'https://picsum.photos/seed/head/400/300'],
    ['Webcam 1080p', 'Microfono dual, enfoque automatico.', 34.0, 30, 'https://picsum.photos/seed/cam/400/300'],
    ['SSD NVMe 1TB', 'Lectura 3500 MB/s, PCIe Gen3.', 74.9, 22, 'https://picsum.photos/seed/ssd/400/300']
  ];
  for (const p of products) insertProduct.run(...p);

  const insertComment = db.prepare(
    'INSERT INTO comments (product_id, username, body) VALUES (?, ?, ?)'
  );
  insertComment.run(1, 'daniel', 'Excelente teclado, muy recomendado!');
  insertComment.run(1, 'alejandro', 'La iluminacion es increible.');
  insertComment.run(3, 'daniel', 'El monitor vale cada centimo.');
}

initSchema();
seedIfEmpty();

module.exports = { db, md5 };
