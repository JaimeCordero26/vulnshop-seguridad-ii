'use strict';

/*
 * Recrea la base de datos desde cero (borra data/vulnshop.db y vuelve a sembrar).
 * Uso: npm run seed
 */

const fs = require('node:fs');
const path = require('node:path');

const DB_PATH = path.join(__dirname, '..', 'data', 'vulnshop.db');
if (fs.existsSync(DB_PATH)) {
  fs.unlinkSync(DB_PATH);
  console.log('Base de datos anterior eliminada.');
}

// Al requerir el modulo se crea el esquema y se siembran los datos por defecto.
require('./database');
console.log('Base de datos recreada y sembrada en:', DB_PATH);
console.log('Usuarios: admin/admin123, daniel/password, alejandro/qwerty');
