# VulnShop — Aplicación web deliberadamente vulnerable

> **Equipo:** The Codefockers — Daniel Saborio · Alejandro Cordero  
> **Curso:** ITI-922, Seguridad de TI II · Ingeniería del Software · Universidad Técnica Nacional  
> **Profesor:** Misael Matamoros Soto  
> **Proyecto 1 (20%)** · OWASP Top 10 — Ediciones 2021 / 2025  

> ⚠️ **ADVERTENCIA:** Esta aplicación contiene vulnerabilidades de seguridad **intencionales** con fines **exclusivamente educativos**. **No** debe desplegarse en producción ni exponerse a Internet. Ejecútela únicamente en un entorno local y aislado.

---

## 1. Descripción del proyecto

### Propósito de la aplicación
**VulnShop** es una plataforma de comercio electrónico (*e-commerce*) desarrollada para el curso **Seguridad de TI II**. Permite navegar un catálogo de componentes y periféricos de hardware, registrarse e iniciar sesión, comentar productos, gestionar un carrito de compras, realizar pedidos, consultar el perfil de usuario y acceder a un panel administrativo.

La aplicación incorpora un conjunto diverso de **10 vulnerabilidades intencionales** que cubren las categorías críticas del **OWASP Top 10** (versiones 2021 y 2025), permitiendo analizar en profundidad cómo se originan los fallos de seguridad en el código y cómo se explotan de forma práctica.

### Tecnologías utilizadas
| Capa | Tecnología | Licencia / Tipo |
|------|------------|-----------------|
| Lenguaje servidor | Node.js (JavaScript) | Open Source (MIT) |
| Framework web | Express | Open Source (MIT) |
| Motor de plantillas | EJS (Embedded JavaScript) | Open Source (Apache 2.0) |
| Base de datos | SQLite (vía módulo nativo `node:sqlite`) | Dominio Público / Embebido |
| Gestión de subidas | Multer | Open Source (MIT) |
| Frontend | HTML5, CSS3 (Cinematic Design System), JS | Estándares W3C |

Todas las tecnologías empleadas son de software libre / código abierto y la aplicación es completamente **multiplataforma** (probada y funcional en Linux y Windows).

### Arquitectura general
La aplicación sigue una arquitectura monolítica con **renderizado del lado del servidor (SSR)**:

```
[ Navegador Web ]
       │
   (HTTP/S)
       ▼
[ Express Router (server.js) ] ──► [ Vistas EJS (/views) ]
       │
       ├──► [ Capa de Datos (db/database.js) ] ──► [ SQLite (data/vulnshop.db) ]
       │
       └──► [ Almacenamiento Estático ] ────────► [ /public/css y /uploads ]
```

---

## 2. Instrucciones de despliegue

### Requisitos previos
- **Node.js ≥ 22.5** (incluye el motor nativo `node:sqlite`). Verifique su versión con: `node -v`.
- **npm** (incluido con Node.js).
- **No requiere instalar servidores de bases de datos externos** (SQLite es embebido y se autogestiona localmente).

### Pasos detallados de instalación y ejecución

**Linux / macOS:**
```bash
git clone https://github.com/JaimeCordero26/vulnshop-seguridad-ii.git
cd vulnshop-seguridad-ii
npm install
npm start
```

**Windows (PowerShell o CMD):**
```powershell
git clone https://github.com/JaimeCordero26/vulnshop-seguridad-ii.git
cd vulnshop-seguridad-ii
npm install
npm start
```

Una vez iniciado el servidor, abra su navegador en: **`http://localhost:3000`**.

### Configuración y reinicio de la base de datos
La base de datos SQLite se crea y se siembra de forma automática al iniciar la aplicación en `data/vulnshop.db`.  
Para reiniciar la base de datos a su estado limpio inicial en cualquier momento (recomendado antes de una demostración):
```bash
npm run seed
```

### Credenciales predeterminadas de prueba
| Usuario | Contraseña | Rol | Propósito |
|---------|-----------|-----|-----------|
| `admin` | `admin123` | admin | Administrador del sistema |
| `daniel` | `password` | user | Usuario estándar de pruebas |
| `alejandro` | `qwerty` | user | Usuario estándar secundario |

---

## 3. Catálogo de vulnerabilidades (10 implementadas — Nivel Excelente)

Para alcanzar el nivel **Excelente** según la rúbrica de calificación (8 a 10 vulnerabilidades diversas), se implementaron las siguientes 10 vulnerabilidades documentadas:

| # | Vulnerabilidad | Clasificación OWASP (2021) | Clasificación OWASP (2025) | Ubicación en código |
|---|----------------|----------------------------|----------------------------|---------------------|
| 1 | SQL Injection en Login (Bypass de autenticación) | A03: Injection | A05: Injection | `server.js` (L147–160) |
| 2 | Escalada vertical al Panel de Administración | A01: Broken Access Control | A01: Broken Access Control | `server.js` (L280–288) |
| 3 | Insecure Direct Object Reference (IDOR en Perfil) | A01: Broken Access Control | A01: Broken Access Control | `server.js` (L220–228) |
| 4 | Insecure Direct Object Reference (IDOR en Pedidos) | A01: Broken Access Control | A01: Broken Access Control | `server.js` (L260–274) |
| 5 | Exposición de Tarjetas en Texto Plano y Hashes | A02: Cryptographic Failures | A04: Cryptographic Failures | `db/database.js` (L33, L67–76) |
| 6 | Stored XSS en Comentarios de Productos | A03: Injection | A05: Injection | `server.js` (L107–113); `views/product.ejs` (L25) |
| 7 | Recuperación de clave con Token Predecible | A04: Insecure Design | A06: Insecure Design | `server.js` (L176–204) |
| 8 | Registro con contraseñas débiles sin política | A07: Auth Failures | A07: Auth Failures | `server.js` (L120–135) |
| 9 | Subida de archivos sin validación (RCE/XSS) | A08: Data Integrity Failures | A08: Data Integrity Failures | `server.js` (L58–66) |
| 10 | Server-Side Request Forgery (SSRF en Importación) | A10: SSRF | A01: Broken Access Control | `server.js` (L290–305) |

---

### Detalle técnico y explotación de las vulnerabilidades

#### 1. SQL Injection en Login (Bypass de autenticación)
* **Clasificación:** A03:2021 / A05:2025 — Injection
* **Descripción técnica:** El endpoint `POST /login` concatena el campo `username` del usuario directamente dentro de la sentencia SQL sin utilizar consultas preparadas.
* **Ubicación:** [`server.js` (L147–160)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. Ir a `/login`.
  2. En **Usuario** ingresar: `admin' -- ` *(con un espacio al final)*.
  3. En **Contraseña** ingresar cualquier texto arbitrario (ej. `123`).
  4. Presionar **Entrar**. Se accede inmediatamente como `admin` porque `--` comenta la cláusula `AND password = ...`.

#### 2. Escalada vertical de privilegios al Panel Admin
* **Clasificación:** A01:2021 / A01:2025 — Broken Access Control
* **Descripción técnica:** La ruta `GET /admin` solo valida que el usuario esté autenticado (`requireLogin`), pero omite verificar que `req.session.user.role === 'admin'`. El frontend intenta ocultar el enlace a usuarios normales, pero no existe validación en el backend (*Forced Browsing*).
* **Ubicación:** [`server.js` (L280–288)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js) y [`views/partials/header.ejs`](file:///home/sabo/Projects/vulnshop-seguridad-ii/views/partials/header.ejs)
* **Pasos de explotación:**
  1. Iniciar sesión como usuario común (`daniel` / `password`).
  2. Escribir directamente en la URL: `http://localhost:3000/admin`.
  3. Se despliega el panel administrativo con la lista completa de usuarios y datos del sistema.

#### 3. IDOR en Perfil de Usuario
* **Clasificación:** A01:2021 / A01:2025 — Broken Access Control
* **Descripción técnica:** `GET /profile/:id` recibe el identificador del usuario como parámetro de ruta y consulta la base de datos sin comprobar si el `:id` coincide con `req.session.user.id`.
* **Ubicación:** [`server.js` (L220–228)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. Autenticado como `daniel` (ID 2), navegar a su perfil `/profile/2`.
  2. Modificar la URL a `/profile/1`.
  3. Se expone la información privada del Administrador (dirección y tarjeta de crédito).

#### 4. IDOR en Consulta de Pedidos
* **Clasificación:** A01:2021 / A01:2025 — Broken Access Control
* **Descripción técnica:** `GET /orders/:id` consulta pedidos por ID numérico secuencial. La ruta carece de verificación estricta de pertenencia en versiones de prueba previas o parámetros manipulados.
* **Ubicación:** [`server.js` (L260–274)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. Con cualquier usuario autenticado, acceder a `/orders/1`.
  2. Permite inspeccionar los detalles de compra y montos de otros clientes.

#### 5. Exposición y Almacenamiento de Tarjetas en Texto Plano
* **Clasificación:** A02:2021 / A04:2025 — Cryptographic Failures
* **Descripción técnica:** Los números de tarjeta de crédito se guardan en la base de datos SQLite y se renderizan en el HTML en texto claro sin cifrado en reposo ni enmascaramiento (`****`).
* **Ubicación:** [`db/database.js` (L33, L67–76)](file:///home/sabo/Projects/vulnshop-seguridad-ii/db/database.js) y [`views/profile.ejs`](file:///home/sabo/Projects/vulnshop-seguridad-ii/views/profile.ejs)
* **Pasos de explotación:**
  1. Acceder a cualquier perfil (`/profile/1` o `/profile/2`).
  2. Observar el campo de tarjeta expuesto en su totalidad (`4111-1111-1111-1111`).

#### 6. Stored XSS en Comentarios de Productos
* **Clasificación:** A03:2021 / A05:2025 — Injection
* **Descripción técnica:** Los comentarios enviados en `POST /product/:id/comment` se almacenan sin sanitizar y la plantilla `views/product.ejs` los imprime usando `<%- c.body %>` (sin escape HTML).
* **Ubicación:** [`server.js` (L107–113)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js) y [`views/product.ejs` (L25)](file:///home/sabo/Projects/vulnshop-seguridad-ii/views/product.ejs)
* **Pasos de explotación:**
  1. Abrir cualquier producto del catálogo.
  2. Publicar el comentario: `<script>alert('XSS Demostrado: ' + document.domain)</script>`.
  3. El script se ejecuta en el navegador de cualquier usuario que visite el producto.

#### 7. Recuperación de Contraseña con Token Predecible
* **Clasificación:** A04:2021 / A06:2025 — Insecure Design
* **Descripción técnica:** El token de restablecimiento se genera mediante un cálculo determinista de baja entropía: `token = 1000 + user.id`.
* **Ubicación:** [`server.js` (L176–204)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. La víctima deseada es `admin` (ID 1), por lo que su token es `1001`.
  2. Ir directamente a: `http://localhost:3000/reset?token=1001`.
  3. Ingresar una nueva contraseña (ej. `nuevaClave123`) y enviar.
  4. Se toma control total de la cuenta sin acceso al correo electrónico de la víctima.

#### 8. Registro con Contraseñas Débiles sin Política
* **Clasificación:** A07:2021 / A07:2025 — Identification and Authentication Failures
* **Descripción técnica:** El formulario de registro `POST /register` no exige longitud mínima, mayúsculas, números ni caracteres especiales, y no hay limitador de tasa contra fuerza bruta.
* **Ubicación:** [`server.js` (L120–135)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. Ir a `/register`.
  2. Registrar usuario `debil` con contraseña `1`. El sistema lo acepta inmediatamente.

#### 9. Subida de Archivos Sin Validación (Integridad Comprometida)
* **Clasificación:** A08:2021 / A08:2025 — Software and Data Integrity Failures
* **Descripción técnica:** Multer no valida tipo MIME ni extensión, conserva el nombre original del archivo y lo sirve directamente desde el directorio estático `/uploads/`.
* **Ubicación:** [`server.js` (L58–66)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. En `/profile`, subir un archivo con extensión `.html` (ej. `demo.html`).
  2. Abrir en el navegador: `http://localhost:3000/uploads/demo.html`.
  3. El servidor entrega el archivo ejecutable en el contexto del dominio.

#### 10. Server-Side Request Forgery (SSRF en Importación)
* **Clasificación:** A10:2021 (SSRF) / A01:2025 (Broken Access Control)
* **Descripción técnica:** `POST /admin/import-image` invoca `fetch(req.body.url)` sin lista blanca ni filtrado de rangos privados o loopback.
* **Ubicación:** [`server.js` (L290–305)](file:///home/sabo/Projects/vulnshop-seguridad-ii/server.js)
* **Pasos de explotación:**
  1. En `/admin`, en "Importar imagen desde URL", ingresar: `http://127.0.0.1:3000/`.
  2. Presionar **Traer**. El servidor realiza la petición hacia sí mismo y devuelve el HTML de su respuesta interna.

---

## 4. Contribuciones del equipo

### Distribución de tareas
| Integrante | Tareas y Responsabilidades Principales |
|------------|-----------------------------------------|
| **Daniel Saborio** | Arquitectura del servidor Express (`server.js`), módulo y esquema de base de datos SQLite (`db/database.js`), vulnerabilidades de autenticación y SQLi (`[VULN-A05]`), token predecible (`[VULN-A06]`), contraseñas débiles (`[VULN-A07]`), Cockpit de defensa interactivo (`defensa.html`). |
| **Alejandro Cordero** | Vistas e interfaz EJS (`views/`), estilos Cinematic Dark Mode (`public/css/style.css`), XSS almacenado (`[VULN-A03]`), escalada vertical al panel admin (`[VULN-A01]`), IDOR en perfiles, SSRF en importación (`[VULN-A10]`), subida de archivos arbitrarios (`[VULN-A08]`). |

### Estadísticas de commits por integrante
Ambos integrantes han participado activamente a lo largo de todo el ciclo de vida del repositorio.  
Salida del comando oficial `git shortlog -sne --all`:

```text
    13  Daniel Saborio <danisabo8713@gmail.com>
     7  Alejandro Cordero <alecordero2610@gmail.com>
```

---

## 5. Guion para la defensa presencial (18 minutos)

```
[0:00 - 5:00]  Demostración de funcionamiento normal:
               Catálogo, registro, login legítimo, carrito de compras, checkout y perfiles.

[5:00 - 15:00] Explotación en vivo (6 vulnerabilidades más ágiles y visuales):
               1. SQL Injection en Login (Bypass hacia admin)         [A05:2025] -> ~1.5 min
               2. Escalada vertical al panel admin por URL             [A01:2025] -> ~1.5 min
               3. SSRF en importación de imagen                        [A01:2025] -> ~2 min
               4. Exposición de tarjetas en texto plano en perfil      [A04:2025] -> ~1 min
               5. Subida de archivo HTML malicioso (demo.html)         [A08:2025] -> ~2 min
               6. Reset de clave con token predecible (1001)           [A06:2025] -> ~2 min

[15:00 - 18:00] Preguntas, respuestas y explicación de mitigaciones.
```
