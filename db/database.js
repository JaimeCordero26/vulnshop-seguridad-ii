'use strict';

/*
 * Modulo de base de datos (SQLite via node:sqlite nativo).
 * Proyecto academico ITI-922 (Seguridad de TI II) - UTN
 * Equipo: The Codefockers (Daniel Saborio, Alejandro Cordero)
 */

const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = path.join(__dirname, '..', 'data', 'vulnshop.db');
const db = new DatabaseSync(DB_PATH);

// Hash estandar SHA-256 para almacenamiento de credenciales
function hashPassword(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      username    TEXT UNIQUE NOT NULL,
      email       TEXT,
      password    TEXT NOT NULL,
      role        TEXT NOT NULL DEFAULT 'user',
      full_name   TEXT,
      address     TEXT,
      credit_card TEXT,
      reset_token INTEGER                 -- [VULN-05] Token de recuperacion predecible
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
      body       TEXT,                    -- [VULN-04] Renderizado sin escapar en la vista (Stored XSS)
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

  const insertUser = db.prepare(
    `INSERT INTO users (username, email, password, role, full_name, address, credit_card, reset_token)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  insertUser.run('admin', 'admin@vulnshop.local', hashPassword('admin123'), 'admin',
    'Administrador', 'Oficina Central, San Jose', '4111-1111-1111-1111', 1001);
  insertUser.run('daniel', 'daniel@vulnshop.local', hashPassword('password'), 'user',
    'Daniel Saborio', 'Alajuela, CR', '5500-0000-0000-0004', null);
  insertUser.run('alejandro', 'alejandro@vulnshop.local', hashPassword('qwerty'), 'user',
    'Alejandro Cordero', 'Heredia, CR', '3400-0000-0000-009', null);

  const insertProduct = db.prepare(
    'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)'
  );
  const products = [
    ['Teclado mecanico RGB', 'Switches azules, retroiluminado, USB-C.', 45.99, 25, 'https://images.unsplash.com/photo-1618384887929-16ec33fab9ef?auto=format&fit=crop&w=600&q=80'],
    ['Mouse gamer 16000 DPI', 'Sensor optico, 7 botones programables.', 29.5, 40, 'https://images.unsplash.com/photo-1527864550417-7fd91fc51a46?auto=format&fit=crop&w=600&q=80'],
    ['Monitor 27" 144Hz', 'Panel IPS, 1ms, FreeSync.', 219.0, 10, 'https://images.unsplash.com/photo-1547119957-637f8679db1e?auto=format&fit=crop&w=600&q=80'],
    ['Auriculares inalambricos', 'Cancelacion de ruido, 30h bateria.', 89.99, 18, 'https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=600&q=80'],
    ['Webcam 1080p', 'Microfono dual, enfoque automatico.', 34.0, 30, 'https://images.unsplash.com/photo-1588508065123-287b28e013da?auto=format&fit=crop&w=600&q=80'],
    ['SSD NVMe 1TB', 'Lectura 3500 MB/s, PCIe Gen3.', 74.9, 22, 'https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?auto=format&fit=crop&w=600&q=80']
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

module.exports = { db, hashPassword };
