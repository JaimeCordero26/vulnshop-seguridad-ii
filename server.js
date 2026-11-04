'use strict';

/*
 * ============================================================================
 *  VulnShop - Servidor Express
 *  Proyecto academico ITI-922 (Seguridad de TI II) - UTN
 *  Equipo: The Codefockers (Daniel Saborio, Alejandro Cordero)
 * ============================================================================
 *
 *  ADVERTENCIA: Esta aplicacion contiene 6 vulnerabilidades INTENCIONALES
 *  seleccionadas especificamente para la defensa en vivo (OWASP Top 10 2021).
 *  Cada fallo esta etiquetado con [VULN-01] a [VULN-06].
 * ============================================================================
 */

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');

const { db, hashPassword } = require('./db/database');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Buenas practicas de configuracion base ----------------------------------
app.disable('x-powered-by'); // Mitigacion de fingerprinting informativo
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// Configuracion de sesion
app.use(session({
  secret: process.env.SESSION_SECRET || 'vulnshop-secure-defense-session-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// Archivos estaticos
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Middleware para pasar usuario actual a las vistas
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// Subida segura de avatares (restringido a imagenes con nombres unicos)
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'uploads'),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const uniqueName = 'avatar-' + Date.now() + '-' + Math.round(Math.random() * 1e9) + ext;
      cb(null, uniqueName);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.png', '.jpg', '.jpeg', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedExtensions.includes(ext) && file.mimetype.startsWith('image/')) {
      return cb(null, true);
    }
    cb(new Error('Solo se permiten archivos de imagen validos (PNG, JPG, WEBP).'));
  }
});

// ============================================================================
//  RUTAS PUBLICAS
// ============================================================================

// Home: catalogo de productos
app.get('/', (req, res) => {
  const products = db.prepare('SELECT * FROM products ORDER BY id').all();
  res.render('index', { products, query: null });
});

// Busqueda de productos (parametrizada de forma segura)
app.get('/search', (req, res, next) => {
  const q = req.query.q || '';
  try {
    const sql = 'SELECT * FROM products WHERE name LIKE ? OR description LIKE ?';
    const products = db.prepare(sql).all('%' + q + '%', '%' + q + '%');
    res.render('index', { products, query: q });
  } catch (err) {
    next(err);
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

// ----------------------------------------------------------------------------
// [VULN-04] OWASP A03 (Injection) - Stored XSS en Comentarios
// El texto del comentario se inserta en la base de datos sin sanitizar y
// luego se renderiza con <%- c.body %> (sin escapar) en views/product.ejs.
// ----------------------------------------------------------------------------
app.post('/product/:id/comment', (req, res) => {
  const username = (req.session.user && req.session.user.username) || 'anonimo';
  const commentBody = req.body.body || '';
  db.prepare('INSERT INTO comments (product_id, username, body) VALUES (?, ?, ?)')
    .run(req.params.id, username, commentBody);
  res.redirect('/product/' + req.params.id);
});

// ============================================================================
//  AUTENTICACION
// ============================================================================

app.get('/register', (req, res) => res.render('register', { error: null }));

app.post('/register', (req, res) => {
  const { username, email, password, full_name } = req.body;
  if (!username || !password || password.length < 4) {
    return res.render('register', { error: 'La contraseña debe tener al menos 4 caracteres.' });
  }
  try {
    db.prepare(
      'INSERT INTO users (username, email, password, role, full_name) VALUES (?, ?, ?, ?, ?)'
    ).run(username, email, hashPassword(password), 'user', full_name || username);
    console.log('[Auth] Usuario registrado:', username);
    res.redirect('/login');
  } catch (err) {
    res.render('register', { error: 'El usuario ya existe.' });
  }
});

app.get('/login', (req, res) => res.render('login', { error: null }));

// ----------------------------------------------------------------------------
// [VULN-01] OWASP A03 (Injection) - SQL Injection en Login (Bypass de autenticacion)
// El campo username se concatena directamente dentro de la consulta SQL.
// Permite ingresar como admin con el usuario: admin' --
// ----------------------------------------------------------------------------
app.post('/login', (req, res, next) => {
  const { username, password } = req.body;
  try {
    const sql =
      "SELECT * FROM users WHERE username = '" + username + "' " +
      "AND password = '" + hashPassword(password) + "'";
    const user = db.prepare(sql).get();

    if (user) {
      console.log('[Auth] Inicio de sesion exitoso:', user.username, '(Rol:', user.role + ')');
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.redirect('/');
    }
    console.log('[Auth] Fallo de inicio de sesion para usuario:', username);
    res.render('login', { error: 'Credenciales invalidas.' });
  } catch (err) {
    next(err);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ----------------------------------------------------------------------------
// [VULN-05] OWASP A04 (Insecure Design) - Token de Recuperacion Predecible
// El token de restablecimiento es predecible: 1000 + id de usuario.
// El atacante puede deducir el token del admin (id=1 -> 1001) y resetear su clave.
// ----------------------------------------------------------------------------
app.get('/forgot', (req, res) => res.render('forgot', { message: null }));

app.post('/forgot', (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?')
    .get(req.body.identifier, req.body.identifier);
  let message = 'Si el usuario existe, se genero un enlace de recuperacion.';
  if (user) {
    const token = 1000 + user.id;
    db.prepare('UPDATE users SET reset_token = ? WHERE id = ?').run(token, user.id);
    message = 'Enlace de recuperacion: /reset?token=' + token;
    console.log('[Auth] Token de reset generado para ' + user.username + ':', token);
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
    .run(hashPassword(req.body.password), user.id);
  console.log('[Auth] Contraseña actualizada para usuario ID:', user.id);
  res.send('Contraseña actualizada con exito. <a href="/login">Iniciar sesion</a>');
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

// ----------------------------------------------------------------------------
// [VULN-03] OWASP A01 (Broken Access Control) - IDOR en Perfil
// Muestra el perfil del :id solicitado sin verificar que corresponda
// al usuario en sesion. Expone direccion, email y tarjeta de credito de otros.
// ----------------------------------------------------------------------------
app.get('/profile/:id', requireLogin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).send('Usuario no encontrado');
  res.render('profile', { profile: user });
});

app.post('/profile/avatar', requireLogin, upload.single('avatar'), (req, res) => {
  res.redirect('/profile/' + req.session.user.id);
});

// ============================================================================
//  CARRITO Y PEDIDOS (Rutas protegidas contra IDOR)
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

// Consulta de pedido con autorizacion adecuada
app.get('/orders/:id', requireLogin, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!order) return res.status(404).send('Pedido no encontrado');
  if (order.user_id !== req.session.user.id && req.session.user.role !== 'admin') {
    return res.status(403).send('Acceso denegado: este pedido pertenece a otro usuario.');
  }
  order.items = JSON.parse(order.items_json || '[]');
  res.render('order', { order });
});

// ============================================================================
//  PANEL DE ADMINISTRACION
// ============================================================================

// ----------------------------------------------------------------------------
// [VULN-02] OWASP A01 (Broken Access Control) - Escalada Vertical al Panel Admin
// La ruta solo utiliza requireLogin, omitiendo verificar si el rol es 'admin'.
// Cualquier usuario comun puede acceder al listado administrativo.
// ----------------------------------------------------------------------------
app.get('/admin', requireLogin, (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, full_name, address, credit_card FROM users').all();
  res.render('admin', { users, fetched: null, error: null });
});

// ----------------------------------------------------------------------------
// [VULN-06] OWASP A10 (Server-Side Request Forgery) - SSRF en Importacion
// El servidor ejecuta fetch a cualquier URL provista por el usuario sin lista
// blanca ni validacion, permitiendo alcanzar servicios internos (localhost, etc.).
// ----------------------------------------------------------------------------
app.post('/admin/import-image', requireLogin, async (req, res) => {
  const users = db.prepare('SELECT id, username, email, role, full_name, address, credit_card FROM users').all();
  try {
    const r = await fetch(req.body.url);
    const text = await r.text();
    res.render('admin', { users, fetched: text.slice(0, 4000), error: null });
  } catch (err) {
    res.render('admin', { users, fetched: null, error: String(err) });
  }
});

// ============================================================================
//  MANEJO DE ERRORES (Sin exponer stack traces)
// ============================================================================

app.use((err, req, res, next) => {
  console.error('[Error interno]', err.message);
  res.status(500).send('<h1>500 - Error interno</h1><p>Ocurrio un error procesando su solicitud.</p>');
});

app.listen(PORT, () => {
  console.log('VulnShop escuchando en http://localhost:' + PORT);
  console.log('Credenciales de prueba: admin/admin123, daniel/password, alejandro/qwerty');
});
