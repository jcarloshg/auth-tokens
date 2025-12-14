## Mejores Prácticas para Implementar un Login con Tokens en una API REST

Implementar un sistema de autenticación basado en tokens es crucial para la seguridad y escalabilidad de una API REST moderna. La práctica estándar es usar **JSON Web Tokens (JWT)**.

Aquí están las mejores prácticas divididas en tres áreas: **Generación y Estructura**, **Manejo del Token** y **Seguridad (Revocación y Almacenamiento)**.

---

### 1. Generación y Estructura del Token (JWT)

Asegurar la integridad y el contenido del token es el primer paso crítico.

- **Usar JWT (JSON Web Tokens):** Es el estándar _de facto_. Un JWT es una cadena compacta que incluye el _Header_, el _Payload_ (datos del usuario/permisos), y la _Signature_ (firma criptográfica).
- **Header y Firma Segura:**
  - Utilice algoritmos de firma robustos como **HS256** (HMAC con SHA-256) o, preferiblemente, **RS256** (RSA con SHA-256) si la API se consume por múltiples servicios (debe ser asimétrico).
  - Mantenga el **secreto de firma (Secret Key)** **extremadamente confidencial** en el servidor. Nunca debe ser expuesto al cliente.
- **Payload (Claims) Mínimo:** Solo incluya la información esencial en el _payload_ (Claims) del token. Un _payload_ estándar debe incluir:

  - `sub` (Subject): Identificador único del usuario (ID de la base de datos).
  - `iat` (Issued At): Momento de emisión del token.
  - `exp` (Expiration Time): **Tiempo de expiración.**

- **Tiempo de Expiración Corto (Access Token):** El token principal (Access Token) debe tener una vida útil corta (ej. 5 a 15 minutos). Esto reduce el riesgo si el token es interceptado.

---

### 2. Manejo de Tokens: Acceso y Refresco

Para lograr seguridad con una buena experiencia de usuario, se utiliza un sistema de doble token.

- **Sistema de Doble Token:**
  1.  **Access Token:** Token de corta duración. Se usa en **cada solicitud** para acceder a los recursos protegidos de la API.
  2.  **Refresh Token:** Token de larga duración (ej. 7 días, 30 días). Se usa **únicamente** para solicitar un nuevo Access Token cuando el actual expira, sin obligar al usuario a iniciar sesión de nuevo.
- **Almacenamiento del Refresh Token (Backend):** El Refresh Token **debe ser almacenado en la base de datos** (o caché segura) y vinculado al usuario. Esto permite **revocación inmediata** (ver sección 3).
- **Manejo de la Expiración (Frontend):**
  - Cuando el Access Token expira (la API responde con un 401 Unauthorized), el cliente debe intentar usar el Refresh Token para obtener un nuevo Access Token.
  - Si el Refresh Token también expira, el usuario es redirigido a la página de login.

---

### 3. Seguridad, Almacenamiento y Revocación 🔒

Estas son las prácticas que protegen contra ataques comunes como XSS y CSRF, y permiten la gestión de sesiones.

| Práctica                                       | Explicación                                                                                                                                                                        | Riesgos que mitiga                                                                                    |
| :--------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------- |
| **Transmisión de Tokens por HTTPS/SSL**        | **Todas** las comunicaciones de la API deben ser a través de HTTPS para asegurar que el token se transmita encriptado y no sea capturado.                                          | Sniffing de red (Man-in-the-middle).                                                                  |
| **Almacenamiento del Access Token (Frontend)** | Almacenar el Access Token en **Memoria** (una variable JS). Evitar `localStorage` ya que es vulnerable a ataques **XSS** (Cross-Site Scripting).                                   | XSS (Cross-Site Scripting).                                                                           |
| **Almacenamiento del Refresh Token (Cliente)** | Almacenar el Refresh Token en una **Cookie HTTP-Only y Secure**.                                                                                                                   | XSS, permitiendo que el navegador lo envíe automáticamente, pero haciéndolo inaccesible a JavaScript. |
| **Revocación del Refresh Token**               | Si un usuario cierra sesión o si detecta actividad sospechosa, el Refresh Token debe ser **eliminado de la base de datos** del servidor, invalidando todas las sesiones asociadas. | Secuestro de sesión a largo plazo.                                                                    |
| **Validación en el Servidor**                  | **Siempre** validar la firma del token (JWT Signature) y el tiempo de expiración (`exp` claim) **en el servidor** en cada solicitud protegida.                                     | Alteración de tokens (Tampering).                                                                     |

---

### 4. Protección contra Ataques Comunes

- **CSRF (Cross-Site Request Forgery):**
  - Utilizar la `SameSite` attribute en las cookies (como la del Refresh Token), configurándola a `Strict` o `Lax`.
  - Asegurar que las operaciones sensibles usen verbos HTTP seguros (POST, PUT, DELETE).
- **Protección de Rutas:** Todas las rutas que requieren autenticación deben tener un _middleware_ que verifique la validez del Access Token antes de ejecutar el _handler_ de la ruta.
- **Rate Limiting:** Implementar limitación de peticiones (Rate Limiting) en el _endpoint_ de `/login` para mitigar ataques de fuerza bruta.
