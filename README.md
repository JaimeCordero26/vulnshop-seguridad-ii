# VulnShop — Aplicación web deliberadamente vulnerable

> **Equipo:** The Codefockers — Daniel Saborio · Alejandro Cordero
> **Curso:** ITI-922, Seguridad de TI II · Ingeniería del Software · Universidad Técnica Nacional
> **Proyecto 1 (20%)** · OWASP Top 10 — 2021

> ⚠️ **ADVERTENCIA:** Esta aplicación contiene vulnerabilidades de seguridad **intencionales** con fines **exclusivamente educativos**. **No** debe desplegarse en producción ni exponerse a Internet. Ejecútela únicamente en un entorno local y aislado.

---

## 1. Descripción del proyecto

### Propósito de la aplicación
**VulnShop** es una tienda en línea (e-commerce) ficticia. Permite navegar un catálogo de productos, registrarse e iniciar sesión, comentar productos, gestionar un carrito, realizar pedidos, administrar el perfil del usuario y acceder a un panel de administración. Cada funcionalidad incorpora, de forma intencional y documentada, una o más vulnerabilidades del **OWASP Top 10 (2021)** para estudiar cómo se introducen en el código y cómo se explotan.

### Funcionalidades principales
1. **Autenticación** — registro, inicio/cierre de sesión y recuperación de contraseña.
2. **Catálogo y búsqueda** de productos.
3. **Comentarios/reseñas** en cada producto.
4. **Carrito de compras y pedidos** (checkout e historial).
5. **Perfil de usuario** (datos personales, foto de perfil).
6. **Panel de administración** (listado de usuarios, importación de imágenes por URL).

### Tecnologías utilizadas
| Capa | Tecnología |
|------|------------|
| Lenguaje servidor | Node.js 22 (JavaScript) |
| Framework web | Express 4.17.1 *(versión antigua intencional, ver A06)* |
| Motor de vistas | EJS |
| Base de datos | SQLite (módulo nativo `node:sqlite`) |
| Subida de archivos | Multer |
| Utilidades | lodash 4.17.11 *(versión vulnerable intencional, ver A06)* |
| Frontend | HTML, CSS, JavaScript |

Todas las tecnologías son de software libre / open source, y la aplicación es multiplataforma (Windows y Linux).

### Arquitectura general
Aplicación monolítica **servidor-renderizado (SSR)** con patrón de rutas de Express:

```
Navegador  ──HTTP──►  Express (server.js)  ──►  Vistas EJS (/views)
                           │
                           ├──►  Capa de datos (db/database.js)  ──►  SQLite (data/vulnshop.db)
                           └──►  Archivos subidos (/uploads)
```

```
Proyecto_Seguridad_I/
├── server.js              # Servidor Express: todas las rutas y la lógica
├── db/
│   ├── database.js        # Conexión SQLite, esquema y semilla de datos
│   └── seed.js            # Recrea la base de datos desde cero
├── views/                 # Plantillas EJS (UI)
│   ├── partials/          # header.ejs, footer.ejs
│   └── *.ejs              # index, product, login, admin, profile, ...
├── public/css/style.css   # Estilos
├── uploads/               # Archivos subidos por usuarios
├── data/                  # Base de datos SQLite (se genera automáticamente)
├── package.json
└── README.md
```

---

## 2. Instrucciones de despliegue

### Requisitos previos
- **Node.js ≥ 22.5** (incluye el módulo nativo `node:sqlite`). Verifíquelo con `node --version`.
- **npm** (viene con Node.js).
- No requiere instalar ningún servidor de base de datos: SQLite es embebido.

### Pasos de instalación

**Linux / macOS:**
```bash
git clone <URL-del-repositorio-privado>
cd Proyecto_Seguridad_I
npm install
npm start
```

**Windows (PowerShell o CMD):**
```powershell
git clone <URL-del-repositorio-privado>
cd Proyecto_Seguridad_I
npm install
npm start
```

Luego abra **http://localhost:3000** en el navegador.

> El script `npm start` ejecuta `node --experimental-sqlite server.js`. La advertencia `ExperimentalWarning: SQLite is an experimental feature` es normal y no afecta el funcionamiento.

### Configuración de la base de datos
La base de datos SQLite se **crea y siembra automáticamente** la primera vez que se inicia el servidor, en `data/vulnshop.db`. No requiere configuración manual.

Para **reiniciar** la base de datos a su estado inicial (borra todos los datos y vuelve a sembrar):
```bash
npm run seed
```

Para cambiar el puerto: `PORT=8080 npm start` (Linux/macOS) o `set PORT=8080 && npm start` (Windows).

> **Nota sobre MySQL/MariaDB/PostgreSQL:** la rúbrica permite SQLite, PostgreSQL o MySQL/MariaDB. Se eligió SQLite por ser embebido y no requerir instalación de un servidor de BD, lo que simplifica el despliegue multiplataforma. La capa de datos está aislada en `db/database.js`, por lo que migrar a otro motor implicaría reemplazar únicamente ese archivo.

### Credenciales por defecto
| Usuario | Contraseña | Rol |
|---------|-----------|-----|
| `admin` | `admin123` | admin |
| `daniel` | `password` | user |
| `alejandro` | `qwerty` | user |

---

## 3. Catálogo de vulnerabilidades

Se implementaron **10 vulnerabilidades** cubriendo **9 de las 10 categorías** del OWASP Top 10 (2021). En el código, cada fallo está marcado con un comentario `[VULN-Axx]`.

> En las rutas de explotación se asume que la aplicación corre en `http://localhost:3000`.

---

### A01 — Broken Access Control (IDOR en perfiles)
- **Descripción:** El endpoint de perfil muestra los datos de cualquier usuario según el `:id` de la URL, sin verificar que ese perfil pertenezca al usuario autenticado (Insecure Direct Object Reference). Expone datos sensibles (dirección, número de tarjeta).
- **Ubicación:** `server.js` líneas **212–219** (ruta `GET /profile/:id`); vista `views/profile.ejs`.
- **Pasos de explotación:**
  1. Inicie sesión como usuario normal (`daniel` / `password`).
  2. Visite `http://localhost:3000/profile/1`.
  3. Verá el perfil del **admin**, incluyendo su número de tarjeta, sin ser el dueño.

### A01 — Broken Access Control (IDOR en pedidos)
- **Descripción:** Cualquier usuario autenticado puede ver el pedido de cualquier otro cambiando el `:id`, porque no se valida el propietario del pedido.
- **Ubicación:** `server.js` líneas **267–273** (ruta `GET /orders/:id`).
- **Pasos de explotación:**
  1. Inicie sesión como `daniel`.
  2. Visite `http://localhost:3000/orders/1` (pedido de otro usuario).
  3. Se muestra el contenido y total del pedido ajeno.

### A01 — Broken Access Control (escalada vertical al panel admin)
- **Descripción:** El panel de administración solo exige estar autenticado; **no** verifica el rol `admin`. Un usuario normal accede al listado de todos los usuarios con sus hashes y tarjetas.
- **Ubicación:** `server.js` líneas **280–285** (ruta `GET /admin`); vista `views/admin.ejs`.
- **Pasos de explotación:**
  1. Inicie sesión como `daniel` (rol `user`).
  2. Visite `http://localhost:3000/admin`.
  3. Accede al panel y ve todos los usuarios, hashes MD5 y tarjetas.

---

### A02 — Cryptographic Failures
- **Descripción:** (1) Las contraseñas se almacenan con **MD5 sin salt**, algoritmo roto y trivial de crackear con tablas rainbow. (2) Los números de **tarjeta se guardan en texto plano**. (3) El **secreto de sesión está hardcodeado** en el repositorio y la cookie no es `httpOnly`/`secure`.
- **Ubicación:**
  - MD5 sin salt: `db/database.js` líneas **17–21** (función `md5`) y columna `password` (línea 29).
  - Tarjeta en texto plano: `db/database.js` líneas **33, 72–79**; se muestra en `views/profile.ejs` y `views/admin.ejs`.
  - Secreto de sesión hardcodeado + cookie insegura: `server.js` líneas **42–50**.
- **Pasos de explotación:**
  1. Obtenga los hashes MD5 vía el panel admin o la inyección SQL (A03).
  2. Un hash como `0192023a7bbd73250516f069df18b500` corresponde a `admin123`; se revierte al instante en cualquier servicio de cracking de MD5 (ej. CrackStation) o con una tabla rainbow.
  3. La tarjeta aparece legible directamente en el perfil.

---

### A03 — Injection (SQL Injection)
- **Descripción:** La búsqueda de productos y el login concatenan directamente la entrada del usuario en la consulta SQL.
- **Ubicación:**
  - Búsqueda: `server.js` líneas **85–98** (ruta `GET /search`, consulta con `LIKE '%" + q + "%'`).
  - Login: `server.js` líneas **142–160** (ruta `POST /login`).
- **Pasos de explotación:**
  1. **Volcado de la tabla de usuarios (UNION):** visite
     `http://localhost:3000/search?q=' UNION SELECT id,username,password,role,email,address FROM users-- `
     El catálogo mostrará los usuarios con sus hashes MD5 en lugar de productos.
  2. **Bypass de autenticación:** en el login escriba usuario `admin'-- ` (con el espacio final) y cualquier contraseña. El `--` comenta la verificación de contraseña y entra como admin.

### A03 — Injection (XSS almacenado)
- **Descripción:** Los comentarios de productos se guardan sin sanitizar y se renderizan **sin escapar** (`<%- %>`), permitiendo inyectar JavaScript que se ejecuta en el navegador de cualquiera que vea el producto.
- **Ubicación:** guardado en `server.js` líneas **110–116** (`POST /product/:id/comment`); renderizado inseguro en `views/product.ejs` línea **25** (`<%- c.body %>`).
- **Pasos de explotación:**
  1. En cualquier producto, publique un comentario con:
     `<script>alert(document.cookie)</script>`
  2. Al recargar la página del producto (o cuando otro usuario la visite) el script se ejecuta. Se puede usar para robo de cookies de sesión.

---

### A04 — Insecure Design (recuperación de contraseña con token predecible)
- **Descripción:** El token de recuperación de contraseña es **predecible**: se calcula como `1000 + id_de_usuario`. Un atacante puede adivinar el token de cualquier cuenta y restablecer su contraseña.
- **Ubicación:** `server.js` líneas **169–195** (rutas `POST /forgot`, `GET/POST /reset`).
- **Pasos de explotación:**
  1. El admin tiene `id = 1`, por lo que su token es **1001**.
  2. Visite directamente `http://localhost:3000/reset?token=1001`.
  3. Establezca una nueva contraseña y tome control de la cuenta admin — sin acceso al correo de la víctima.

---

### A05 — Security Misconfiguration
- **Descripción:** Varias malas configuraciones: (1) se exponen **stack traces completos** al cliente ante cualquier error; (2) no se desactiva la cabecera **`X-Powered-By: Express`** (fingerprinting); (3) hay **listado de directorio** de los archivos subidos; (4) existen **credenciales por defecto** conocidas.
- **Ubicación:**
  - Stack trace al cliente: `server.js` líneas **313–318** (manejador de errores).
  - `X-Powered-By` no desactivado: `server.js` líneas **38–40** (comentario explicativo).
  - Listado de directorio: `server.js` líneas **302–308** (ruta `GET /files`); vista `views/files.ejs`.
  - Credenciales por defecto: `db/database.js` líneas **69–79**.
- **Pasos de explotación:**
  1. Provoque un error SQL (ej. `http://localhost:3000/search?q='`) y observe la consulta y el stack trace revelados.
  2. `curl -I http://localhost:3000/` muestra `X-Powered-By: Express`.
  3. Visite `http://localhost:3000/files` para listar y descargar archivos subidos por otros.

---

### A06 — Vulnerable and Outdated Components
- **Descripción:** Se usan dependencias **desactualizadas con CVE conocidos**: `lodash 4.17.11` (prototype pollution, **CVE-2019-10744**) y `express 4.17.1`. Además, `_.merge` se aplica sobre datos controlados por el usuario, haciendo explotable la contaminación de prototipos.
- **Ubicación:** versiones fijadas en `package.json`; uso de `_.merge` en `server.js` líneas **225–232** (ruta `POST /preferences`); import en línea **23**.
- **Pasos de explotación:**
  1. Ejecute `npm audit` para ver los CVE reportados de las dependencias.
  2. Autenticado, envíe a `POST /preferences` un cuerpo JSON con `{"__proto__": {"admin": true}}`. Con lodash 4.17.11, `_.merge` contamina `Object.prototype` del proceso, afectando a objetos creados posteriormente.
     ```bash
     curl -b cookie.txt -H "Content-Type: application/json" \
       -d '{"__proto__":{"polluted":"yes"}}' http://localhost:3000/preferences
     ```

---

### A07 — Identification and Authentication Failures
- **Descripción:** (1) **No hay bloqueo de cuenta ni límite de intentos** (fuerza bruta libre); (2) se aceptan **contraseñas débiles** en el registro (ej. `123`), sin política de complejidad; (3) **session fixation**: no se regenera el id de sesión tras el login; (4) **no hay token CSRF** en los formularios.
- **Ubicación:**
  - Sin bloqueo de intentos: `server.js` líneas **142–160** (`POST /login`).
  - Sin validación de fortaleza: `server.js` líneas **126–138** (`POST /register`).
  - Session fixation: `server.js` líneas **151–153** (no se llama `req.session.regenerate`).
  - Ausencia de CSRF: todos los formularios `POST` (ej. `views/product.ejs`, `views/profile.ejs`).
- **Pasos de explotación:**
  1. **Fuerza bruta:** itere contraseñas contra `POST /login` sin ser bloqueado nunca.
     ```bash
     for p in 123 admin admin123 password; do \
       curl -s -o /dev/null -w "$p %{http_code}\n" -d "username=admin&password=$p" \
       http://localhost:3000/login; done
     ```
  2. **Contraseña débil:** registre un usuario con contraseña `1` y será aceptada.
  3. **CSRF:** una página externa puede enviar un `POST` a `/product/1/comment` usando la sesión de la víctima, pues no hay token anti-CSRF.

---

### A08 — Software and Data Integrity Failures (subida de archivos sin restricción)
- **Descripción:** La subida de archivos **no valida tipo, extensión ni tamaño** y **conserva el nombre original sin sanitizar**. Permite subir contenido activo (`.html`, `.svg` con script), sobrescribir archivos existentes o intentar *path traversal*. Los archivos se sirven tal cual desde `/uploads`.
- **Ubicación:** configuración de Multer en `server.js` líneas **65–72** (`filename: originalname`); ruta de subida líneas **221–223** (`POST /profile/avatar`); servido estático en línea **55**.
- **Pasos de explotación:**
  1. Autenticado, en el perfil suba un archivo `evil.html` con `<script>alert('xss')</script>`.
  2. Acceda a `http://localhost:3000/uploads/evil.html`: el servidor lo entrega y el navegador ejecuta el script (XSS almacenado vía archivo).
  3. Subir un archivo con el mismo nombre que otro lo **sobrescribe**, al no haber unicidad.

---

### A09 — Security Logging and Monitoring Failures
- **Descripción:** La aplicación **no registra ningún evento de seguridad**: logins exitosos/fallidos, accesos al panel admin, intentos de IDOR o errores no se escriben en ningún log. Un ataque pasaría completamente inadvertido y sin trazabilidad forense.
- **Ubicación:** ausencia deliberada de logging en todas las rutas; el manejador de errores (`server.js` líneas **313–318**) devuelve el error al cliente pero **no lo registra** en servidor.
- **Pasos de explotación / evidencia:**
  1. Realice varios logins fallidos, un bypass por SQLi y accesos IDOR.
  2. Revise la salida del servidor: no existe registro alguno de estos eventos, imposibilitando la detección y respuesta.

---

### A10 — Server-Side Request Forgery (SSRF)
- **Descripción:** La función "importar imagen desde URL" del panel admin hace una petición `fetch` del lado del servidor a **cualquier URL** que indique el usuario, sin lista blanca ni validación. Permite alcanzar servicios internos (loopback, red interna, endpoints de metadata en la nube) a los que el atacante no tendría acceso directo.
- **Ubicación:** `server.js` líneas **288–299** (ruta `POST /admin/import-image`); formulario en `views/admin.ejs`.
- **Pasos de explotación:**
  1. En `/admin`, sección "Importar imagen desde URL", envíe `http://127.0.0.1:3000/files` o cualquier recurso interno.
  2. El servidor realiza la petición y devuelve el contenido en la respuesta, demostrando acceso a recursos internos. En un entorno cloud, una URL como `http://169.254.169.254/latest/meta-data/` expondría credenciales de instancia.

---

### Resumen de cobertura OWASP Top 10 (2021)

| Categoría | Implementada | Ubicación principal |
|-----------|:---:|---------------------|
| A01 Broken Access Control | ✅ (×3) | `server.js` 212, 267, 280 |
| A02 Cryptographic Failures | ✅ | `db/database.js` 17; `server.js` 42 |
| A03 Injection (SQLi + XSS) | ✅ (×2) | `server.js` 85, 142; `views/product.ejs` 25 |
| A04 Insecure Design | ✅ | `server.js` 169 |
| A05 Security Misconfiguration | ✅ | `server.js` 302, 313 |
| A06 Vulnerable/Outdated Components | ✅ | `package.json`; `server.js` 225 |
| A07 Auth Failures | ✅ | `server.js` 126, 142 |
| A08 Data Integrity Failures | ✅ | `server.js` 65 |
| A09 Logging Failures | ✅ | (ausencia global) |
| A10 SSRF | ✅ | `server.js` 288 |

---

## 4. Contribuciones del equipo

### Distribución de tareas

| Integrante | Responsabilidades |
|------------|-------------------|
| **Daniel Saborio** | Autenticación y recuperación de contraseña (A04, A07), inyección SQL (A03), carrito y pedidos, vulnerabilidades A02 (criptografía) y A09 (logging), documentación del catálogo. |
| **Alejandro Cordero** | Catálogo, comentarios y XSS almacenado (A03), control de acceso / IDOR y panel admin (A01), SSRF (A10), subida de archivos (A08), componentes desactualizados (A06), configuración y estilos, despliegue. |

> Ambos integrantes revisaron en conjunto la integración final, el README y la preparación de la defensa.

### Estadísticas de commits por integrante
Para generar las estadísticas reales desde el repositorio:
```bash
git shortlog -sne --all
```
La contribución está balanceada entre ambos integrantes mediante commits frecuentes y descriptivos a lo largo del desarrollo.

---

## Guion sugerido para la defensa

1. **Funcionamiento normal (5 min):** registro, login, navegación del catálogo, agregar al carrito, checkout, ver pedidos y perfil.
2. **Explotación en vivo (10 min):** SQLi (dump + bypass) → XSS almacenado → IDOR de perfil/pedidos → acceso al panel admin → SSRF → subida de archivo malicioso → token de reset predecible.
3. **Preguntas y respuestas (0–3 min).**

## Cómo mitigar (contexto académico)
Cada vulnerabilidad se corregiría con: consultas parametrizadas (ya usadas en el resto del código como contraste), escape de salida en vistas, verificación de propiedad y rol en cada acceso, hashing con bcrypt/argon2 y salt, cifrado de datos sensibles, secreto de sesión aleatorio desde variables de entorno, validación de tipo/tamaño/nombre en subidas, listas blancas para peticiones salientes, dependencias actualizadas, registro de eventos de seguridad y tokens anti-CSRF.
