'use strict';

/*
 * ============================================================================
 *  VulnShop - servidor Express
 *  Proyecto academico ITI-922 (Seguridad de TI II) - UTN
 *  Equipo: The Codefockers (Daniel Saborio, Alejandro Cordero)
 * ============================================================================
 *
 *  ADVERTENCIA: esta aplicacion contiene vulnerabilidades INTENCIONALES con
 *  fines educativos. NO debe desplegarse en produccion ni exponerse a Internet.
 *  Cada fallo esta marcado con [VULN-Axx] segun OWASP Top 10 2021. El catalogo
 *  completo con pasos de explotacion esta en README.md.
 * ============================================================================
 */

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const _ = require('lodash'); // [VULN-A06] lodash 4.17.11: prototype pollution (CVE-2019-10744)

const { db, md5 } = require('./db/database');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Configuracion de vistas -------------------------------------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// [VULN-A05] Security Misconfiguration: no se desactiva X-Powered-By, por lo que
// el servidor revela "Express" en las cabeceras (fingerprinting). Lo correcto:
// app.disable('x-powered-by').

// [VULN-A02] Cryptographic Failures / [VULN-A07]: secreto de sesion HARDCODEADO
// en el repositorio, debil y reutilizado. Ademas la cookie no es httpOnly real
// ni secure, sin rotacion. Lo correcto: secreto aleatorio desde variable de
// entorno y cookie { httpOnly: true, secure: true, sameSite: 'lax' }.
app.use(session({
  secret: 'keyboard_cat_123',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false }
}));

// Archivos estaticos y subidas
app.use('/public', express.static(path.join(__dirname, 'public')));
// [VULN-A08]/[VULN-A01]: las subidas se sirven tal cual, sin control de tipo.
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Variables disponibles en todas las vistas
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// --- Subida de archivos SIN validacion ---------------------------------------
// [VULN-A08] Software and Data Integrity Failures + [VULN-A01]: se conserva el
// nombre original (sin sanitizar) y se acepta CUALQUIER tipo/tamano de archivo.
// Permite subir .html/.svg (XSS), sobreescribir archivos o path traversal.
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'uploads'),
    filename: (req, file, cb) => cb(null, file.originalname)
  })
});

// ============================================================================
//  RUTAS PUBLICAS
// ============================================================================

// Home: catalogo de productos
app.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id').all();
  res.render('index', { products, query: null });
});

// [VULN-A03] Injection (SQLi): el parametro q se concatena directamente a la
// consulta SQL. Permite UNION-based injection para volcar la tabla users.
app.get('/search', (req, res, next) => {
  const q = req.query.q || '';
  try {
    const sql =
      "SELECT * FROM products WHERE name LIKE '%" + q + "%' " +
      "OR description LIKE '%" + q + "%'";
    const products = db.prepare(sql).all();
    res.render('index', { products, query: q });
  } catch (err) {
    next(err); // [VULN-A05] el error muestra la consulta/stack al atacante
  }
});

// Detalle de producto + comentarios
app.get('/product/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).send('Producto no encontrado');
  const comments = db.prepare(
    'SELECT * FROM comments WHERE product_id = ? ORDER BY id DESC'
  ).all(req.params.id);
  res.render('product', { product, comments });
});

// [VULN-A03] Injection (XSS almacenado): el cuerpo del comentario se guarda sin
// sanitizar y luego se renderiza sin escapar (<%- %> en la vista product.ejs).
// Tambien [VULN-A07]: no hay token CSRF en el formulario.
app.post('/product/:id/comment', (req, res) => {
  const username = (req.session.user && req.session.user.username) || 'anonimo';
  db.prepare('INSERT INTO comments (product_id, username, body) VALUES (?, ?, ?)')
    .run(req.params.id, username, req.body.body);
  res.redirect('/product/' + req.params.id);
});

// ============================================================================
//  AUTENTICACION
// ============================================================================

app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', (req, res) => {
  const { username, email, password, full_name } = req.body;
  // [VULN-A07] Identification & Authentication Failures: NO se valida fortaleza
  // de la contrasena; se aceptan passwords como "123". Sin verificacion de email.
  try {
    db.prepare(
      'INSERT INTO users (username, email, password, role, full_name) VALUES (?, ?, ?, ?, ?)'
    ).run(username, email, md5(password), 'user', full_name || username);
    res.redirect('/login');
  } catch (err) {
    res.render('register', { error: 'El usuario ya existe.' });
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));

// [VULN-A03] Injection (SQLi) + [VULN-A07] (sin bloqueo de intentos / fuerza bruta)
app.post('/login', (req, res, next) => {
  const { username, password } = req.body;
  try {
    // El username se concatena -> bypass con:  admin' --
    const sql =
      "SELECT * FROM users WHERE username = '" + username + "' " +
      "AND password = '" + md5(password) + "'";
    const user = db.prepare(sql).get();
    if (user) {
      // [VULN-A07] Session fixation: NO se regenera el id de sesion tras el login.
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.redirect('/');
    }
    res.render('login', { error: 'Credenciales invalidas.' });
  } catch (err) {
    next(err);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// --- Recuperacion de contrasena (diseno inseguro) ----------------------------
app.get('/forgot', (req, res) => res.render('forgot', { message: null }));

// [VULN-A04] Insecure Design: el token de reset es PREDECIBLE (1000 + id de
// usuario). Un atacante puede adivinar el token de cualquier usuario (p.ej. el
// admin es id=1 -> token 1001) y tomar control de la cuenta.
app.post('/forgot', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(req.body.identifier, req.body.identifier);
  let message = 'Si el usuario existe, se genero un enlace de recuperacion.';
  if (user) {
    const token = 1000 + user.id;
    db.prepare('UPDATE users SET reset_token = ? WHERE id = ?').run(token, user.id);
    // En una app real el enlace se enviaria por correo; aqui lo mostramos.
    message = 'Enlace de recuperacion: /reset?token=' + token;
  }
  res.render('forgot', { message });
});

app.get('/reset', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(req.query.token);
  if (!user) return res.send('Token invalido o expirado.');
  res.render('reset', { token: req.query.token });
});

app.post('/reset', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(req.body.token);
  if (!user) return res.send('Token invalido o expirado.');
  db.prepare('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?')
    .run(md5(req.body.password), user.id);
  res.send('Contrasena actualizada. <a href="/login">Iniciar sesion</a>');
});

// ============================================================================
//  PERFIL
// ============================================================================

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

app.get('/profile', requireLogin, (req, res) => {
  res.redirect('/profile/' + req.session.user.id);
});

// [VULN-A01] Broken Access Control (IDOR): se muestra el perfil del :id pedido
// SIN comprobar que pertenezca al usuario autenticado. Expone datos sensibles
// (direccion, numero de tarjeta en texto plano) de cualquier usuario.
app.get('/profile/:id', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).send('Usuario no encontrado');
  res.render('profile', { profile: user });
});

app.post('/profile/avatar', requireLogin, upload.single('avatar'), (req, res) => {
  res.redirect('/profile/' + req.session.user.id);
});

// [VULN-A06] Vulnerable Components + prototype pollution: _.merge de lodash
// 4.17.11 sobre datos controlados por el usuario (p.ej. __proto__) contamina
// Object.prototype del proceso.
app.post('/preferences', requireLogin, (req, res) => {
  const prefs = {};
  _.merge(prefs, req.body);
  req.session.preferences = prefs;
  res.redirect('/profile/' + req.session.user.id);
});

// ============================================================================
//  CARRITO Y PEDIDOS
// ============================================================================

app.post('/cart/add', (req, res) => {
  if (!req.session.cart) req.session.cart = [];
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.body.product_id);
  if (product) req.session.cart.push({ id: product.id, name: product.name, price: product.price });
  res.redirect('/cart');
});

app.get('/cart', (req, res) => {
  const cart = req.session.cart || [];
  const total = cart.reduce((s, i) => s + i.price, 0);
  res.render('cart', { cart, total });
});

app.post('/cart/checkout', requireLogin, (req, res) => {
  const cart = req.session.cart || [];
  const total = cart.reduce((s, i) => s + i.price, 0);
  db.prepare('INSERT INTO orders (user_id, total, items_json) VALUES (?, ?, ?)')
    .run(req.session.user.id, total, JSON.stringify(cart));
  req.session.cart = [];
  res.redirect('/orders');
});

app.get('/orders', requireLogin, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC')
    .all(req.session.user.id);
  res.render('orders', { orders });
});

// [VULN-A01] Broken Access Control (IDOR): cualquier usuario autenticado puede
// ver el pedido de cualquier otro cambiando el :id. No se valida el propietario.
app.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).send('Pedido no encontrado');
  order.items = JSON.parse(order.items_json || '[]');
  res.render('order', { order });
});

// ============================================================================
//  PANEL DE ADMINISTRACION
// ============================================================================

// [VULN-A01] Broken Access Control (escalada vertical): el panel solo exige
// estar autenticado, NO exige rol admin. Cualquier usuario normal accede al
// listado de todos los usuarios con sus hashes y tarjetas.
app.get('/admin', requireLogin, (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  res.render('admin', { users, fetched: null, error: null });
});

// [VULN-A10] Server-Side Request Forgery: el servidor hace fetch a la URL que
// indique el usuario, sin lista blanca ni validacion. Permite leer servicios
// internos (metadata cloud, localhost, red interna) o file:// via el servidor.
app.post('/admin/import-image', requireLogin, async (req, res, next) => {
  const users = db.prepare('SELECT * FROM users').all();
  try {
    const r = await fetch(req.body.url);
    const text = await r.text();
    res.render('admin', { users, fetched: text.slice(0, 4000), error: null });
  } catch (err) {
    res.render('admin', { users, fetched: null, error: String(err) });
  }
});

// [VULN-A05] Security Misconfiguration: listado de directorio de /uploads.
app.get('/files', (req, res) => {
  const dir = path.join(__dirname, 'uploads');
  const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
  res.render('files', { files });
});

// ============================================================================
//  MANEJO DE ERRORES
// ============================================================================

// [VULN-A05] Security Misconfiguration / [VULN-A09] Logging Failures: se expone
// el stack trace completo al cliente y NO se registra ningun evento de
// seguridad (logins fallidos, accesos, errores) en ningun log.
app.use((err, req, res, next) => {
  res.status(500).send(
    '<h1>Error interno</h1><pre>' + (err.stack || err) + '</pre>'
  );
});

app.listen(PORT, () => {
  console.log('VulnShop escuchando en http://localhost:' + PORT);
  console.log('Usuarios de prueba: admin/admin123, daniel/password, alejandro/qwerty');
});
