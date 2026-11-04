# VulnShop — Aplicación web deliberadamente vulnerable

> **Equipo:** The Codefockers — Daniel Saborio · Alejandro Cordero  
> **Curso:** ITI-922, Seguridad de TI II · Ingeniería del Software · Universidad Técnica Nacional  
> **Profesor:** Misael Matamoros Soto  
> **Proyecto 1 (20%)** · OWASP Top 10 — 2021  

> ⚠️ **ADVERTENCIA:** Esta aplicación contiene vulnerabilidades de seguridad **intencionales** con fines **exclusivamente educativos**. **No** debe desplegarse en producción ni exponerse a Internet. Ejecútela únicamente en un entorno local y aislado.

---

## 1. Descripción del proyecto

### Propósito de la aplicación
**VulnShop** es una tienda en línea (*e-commerce*) desarrollada para el curso **Seguridad de TI II**. Permite navegar un catálogo de productos, registrarse, iniciar sesión, comentar productos, gestionar un carrito de compras, realizar pedidos y acceder al perfil de usuario y a un panel de administración.

El proyecto implementa un conjunto seleccionado de **6 vulnerabilidades clave del OWASP Top 10 (2021)**, optimizadas para una **demostración en vivo ágil, clara y de alto impacto visual** durante la defensa técnica ante el docente.

### Tecnologías utilizadas
| Capa | Tecnología |
|------|------------|
| Lenguaje servidor | Node.js (JavaScript) |
| Framework web | Express |
| Motor de vistas | EJS |
| Base de datos | SQLite (módulo nativo `node:sqlite`) |
| Subida de archivos | Multer |
| Frontend | HTML5, CSS3, JavaScript |

---

## 2. Instrucciones de despliegue

### Requisitos previos
- **Node.js ≥ 22.5** (incluye el módulo nativo `node:sqlite`).
- **npm** (incluido con Node.js).
- No requiere servidor externo de base de datos (SQLite embebido).

### Pasos de instalación y ejecución

**Linux / macOS:**
```bash
git clone https://github.com/JaimeCordero26/vulnshop-seguridad-ii
cd vulnshop-seguridad-ii
npm install
npm start
```

**Windows (PowerShell o CMD):**
```powershell
git clone https://github.com/JaimeCordero26/vulnshop-seguridad-ii
cd vulnshop-seguridad-ii
npm install
npm start
```

Luego abra **http://localhost:3000** en el navegador.

### Semilla y reinicio de la base de datos
La base de datos SQLite se genera automáticamente en `data/vulnshop.db`. Para reiniciar los datos a su estado inicial antes de la defensa:
```bash
npm run seed
```

### Credenciales predeterminadas de prueba
| Usuario | Contraseña | Rol | Propósito |
|---------|-----------|-----|-----------|
| `admin` | `admin123` | admin | Administrador del sistema |
| `daniel` | `password` | user | Usuario estándar para pruebas |
| `alejandro` | `qwerty` | user | Usuario estándar adicional |

---

## 3. Catálogo de las 6 vulnerabilidades para la defensa en vivo

Todas las vulnerabilidades están marcadas en el código con la etiqueta `[VULN-01]` a `[VULN-06]`.

| # | Código | Categoría OWASP Top 10 | Vulnerabilidad | Ubicación en código |
|---|--------|------------------------|----------------|---------------------|
| 1 | `[VULN-01]` | **A03: Injection** | SQL Injection: Bypass de autenticación en Login | `server.js` (L137–152) |
| 2 | `[VULN-02]` | **A01: Broken Access Control** | Escalada vertical al Panel de Administración | `server.js` (L238–246) |
| 3 | `[VULN-03]` | **A01: Broken Access Control** | Insecure Direct Object Reference (IDOR) en Perfil | `server.js` (L188–198) |
| 4 | `[VULN-04]` | **A03: Injection** | Stored XSS en Comentarios de Producto | `server.js` (L103–115); `views/product.ejs` (L25) |
| 5 | `[VULN-05]` | **A04: Insecure Design** | Recuperación de contraseña con token predecible | `server.js` (L160–182) |
| 6 | `[VULN-06]` | **A10: Server-Side Request Forgery** | SSRF en Importación de imagen | `server.js` (L248–261); `views/admin.ejs` (L22–33) |

---

## 4. Guía detallada de demostración y explotación en vivo

### 1. SQL Injection: Bypass de autenticación en Login `[VULN-01]`
* **Categoría OWASP:** A03:2021 — Injection
* **Descripción:** La ruta `POST /login` concatena directamente la entrada del usuario (`username`) en la sentencia SQL sin parametrización.
* **Pasos de demostración en vivo:**
  1. Diríjase a la página de inicio de sesión (`/login`).
  2. En el campo **Usuario**, escriba: `admin' -- ` *(con un espacio al final)*.
  3. En el campo **Contraseña**, escriba cualquier texto arbitrario.
  4. Presione **Entrar**.
* **Resultado visible:** Se inicia sesión como `admin`, evadiendo la verificación de contraseña debido a que la secuencia `--` comenta el resto de la consulta SQL.
* **Mitigación:** Usar prepared statements con marcadores de posición (`?`).

---

### 2. Broken Access Control: Escalada vertical al Panel Admin `[VULN-02]`
* **Categoría OWASP:** A01:2021 — Broken Access Control
* **Descripción:** La ruta `GET /admin` solo verifica que el usuario esté autenticado (`requireLogin`), pero **no** verifica que cuente con el rol `admin`.
* **Pasos de demostración en vivo:**
  1. Inicie sesión con un usuario regular (`daniel` / `password`).
  2. En la barra de direcciones del navegador navegue directamente a: `http://localhost:3000/admin`.
* **Resultado visible:** El usuario estándar obtiene acceso completo al panel administrativo, visualizando la lista de todos los usuarios registrados y sus datos confidenciales.
* **Mitigación:** Implementar un middleware de autorización que verifique explícitamente `req.session.user.role === 'admin'`.

---

### 3. Broken Access Control: IDOR en Perfil de Usuario `[VULN-03]`
* **Categoría OWASP:** A01:2021 — Broken Access Control
* **Descripción:** La ruta `GET /profile/:id` toma el identificador de usuario desde la URL sin comprobar si coincide con el usuario autenticado en la sesión.
* **Pasos de demostración en vivo:**
  1. Estando autenticado como `daniel` (ID 2), ingrese a su perfil (`/profile`).
  2. Modifique la URL en el navegador a: `http://localhost:3000/profile/1`.
* **Resultado visible:** Se muestra en pantalla el perfil del usuario administrador (ID 1), incluyendo su dirección física y número de tarjeta.
* **Mitigación:** Comprobar en el controlador que `req.params.id === String(req.session.user.id)` o servir el perfil directamente desde `req.session.user.id` sin parámetro de ruta.

---

### 4. Stored XSS: Inyección en Comentarios de Producto `[VULN-04]`
* **Categoría OWASP:** A03:2021 — Injection
* **Descripción:** Los comentarios enviados mediante `POST /product/:id/comment` se almacenan sin sanitizar y la vista `views/product.ejs` los renderiza con `<%- c.body %>` (salida sin escapar).
* **Pasos de demostración en vivo:**
  1. Seleccione cualquier producto del catálogo (ej. Teclado mecánico).
  2. En la caja de comentarios escriba una etiqueta HTML de script:
     ```html
     <script>alert('XSS Demostrado: ' + document.domain)</script>
     ```
  3. Envíe el comentario.
* **Resultado visible:** Al renderizarse la página, el navegador interpreta el script y muestra la ventana emergente, demostrando la ejecución de código en el contexto del usuario.
* **Mitigación:** Renderizar usando escape automático en EJS (`<%= c.body %>` en lugar de `<%- %>`) y aplicar Content Security Policy (CSP).

---

### 5. Insecure Design: Recuperación de Contraseña con Token Predecible `[VULN-05]`
* **Categoría OWASP:** A04:2021 — Insecure Design
* **Descripción:** El mecanismo de recuperación calcula el token sumando un número fijo al identificador de la cuenta (`token = 1000 + user.id`).
* **Pasos de demostración en vivo:**
  1. Identifique que la víctima deseada (`admin`) tiene `id = 1`, por lo que su token correspondiente es `1001`.
  2. Ingrese directamente en el navegador a: `http://localhost:3000/reset?token=1001`.
  3. Ingrese una nueva contraseña (ej. `nuevaClave123`) y guarde los cambios.
  4. Inicie sesión en `/login` con el usuario `admin` y la nueva contraseña.
* **Resultado visible:** Se toma el control de la cuenta del administrador sin necesidad de acceso a su correo electrónico.
* **Mitigación:** Generar tokens aleatorios criptográficamente seguros (`crypto.randomBytes`), con caducidad temporal (ej. 15 minutos) y de un único uso.

---

### 6. Server-Side Request Forgery (SSRF) en Importación `[VULN-06]`
* **Categoría OWASP:** A10:2021 — Server-Side Request Forgery
* **Descripción:** La función "Importar imagen desde URL" en el panel administrativo invoca `fetch(req.body.url)` sin validar el destino ni el esquema de red.
* **Pasos de demostración en vivo:**
  1. Ingrese al panel administrativo (`/admin`).
  2. En la sección "Importar imagen desde URL", ingrese una dirección de loopback local:
     `http://127.0.0.1:3000/`
  3. Presione el botón **Traer**.
* **Resultado visible:** El servidor realiza una petición hacia sí mismo y devuelve el código HTML de la respuesta dentro del panel, evidenciando la capacidad de consultar recursos internos y servicios locales no accesibles externamente.
* **Mitigación:** Implementar una lista blanca de dominios e IPs permitidas, rechazando esquemas no HTTP/HTTPS y bloqueando rangos privados (RFC 1918) y loopback (`127.0.0.1`).

---

## 5. Guion sugerido para la defensa (18 minutos)

```
[0:00 - 5:00]  Funcionamiento normal de la plataforma:
               Navegación del catálogo, registro de usuario, login legítimo, carrito y checkout.

[5:00 - 15:00] Explotación en vivo (Orden ágil recomendado):
               1. SQLi Login (Bypass hacia admin)                     -> ~1.5 min
               2. Escalada vertical a /admin con usuario normal        -> ~1.5 min
               3. SSRF desde el panel administrativo                   -> ~2 min
               4. IDOR en perfiles (/profile/1)                        -> ~1.5 min
               5. Stored XSS en comentarios de producto                -> ~2 min
               6. Recuperación predecible (/reset?token=1001)          -> ~1.5 min

[15:00 - 18:00] Preguntas, respuestas y explicación de mitigaciones.
```

---

## 6. Contribuciones del equipo

| Integrante | Responsabilidades |
|------------|-------------------|
| **Daniel Saborio** | Implementación de autenticación, SQL Injection en login (`[VULN-01]`), token predecible de recuperación (`[VULN-05]`), base de datos SQLite y guion de defensa. |
| **Alejandro Cordero** | Implementación del catálogo, XSS almacenado en comentarios (`[VULN-04]`), IDOR en perfiles (`[VULN-03]`), escalada en panel admin (`[VULN-02]`), SSRF (`[VULN-06]`) y vistas EJS. |

Ambos integrantes participaron conjuntamente en la integración, pruebas en vivo, mitigaciones y documentación técnica.
