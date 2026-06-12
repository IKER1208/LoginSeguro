# 🔒 LoginSeguro

Sistema de autenticación seguro con **MFA escalonado** (Multi-Factor Authentication) construido con Laravel 10, Breeze y Spatie Permission.

## Descripción

LoginSeguro implementa un pipeline de autenticación progresiva basado en roles con múltiples factores de seguridad:

| Rol | 1FA (Password) | 2FA (TOTP) | 3FA (PIN Email) | Dashboard |
|-----|:-:|:-:|:-:|-----------|
| **Invitado** | ✅ | — | — | `/guest-dashboard` |
| **Usuario** | ✅ | ✅ | — | `/user-dashboard` |
| **Admin** | ✅ | ✅ | ✅ | `/admin-dashboard` |

## Stack Tecnológico

- **Framework**: Laravel 10.x + PHP 8.1+
- **Autenticación Base**: Laravel Breeze
- **Roles y Permisos**: Spatie Laravel Permission
- **2FA (TOTP)**: PragmaRX Google2FA + SimpleSoftwareIO QR Code
- **Hashing**: Argon2id (OWASP recomendado)
- **Logs de Desarrollo**: Laravel Telescope (solo `--dev`)

## Características de Seguridad

- ✅ Validación estricta de contraseñas (min 12 chars + HIBP)
- ✅ reCAPTCHA v2 en login, registro y recuperación de contraseña
- ✅ Sanitización global de inputs (`strip_tags`) vía middleware
- ✅ Rate Limiting en login (5/min), 2FA (3/min), 3FA (3/min)
- ✅ Prevención de enumeración de usuarios (mensajes genéricos)
- ✅ Headers HTTP de seguridad (CSP, HSTS, COOP, CORP, X-Frame-Options)
- ✅ Cifrado de sesiones (AES-256-CBC) con SameSite=strict
- ✅ Logs de auditoría dedicados (canal `security`, retención 90 días)
- ✅ Session Fixation prevention (regeneración en cada paso MFA)
- ✅ Sesiones concurrentes restringidas (un dispositivo activo)

## Estándar de Documentación

> **El proyecto sigue el estándar de documentación [PHPDoc](https://docs.phpdoc.org/guide/references/phpdoc/index.html) para todas las clases y métodos.**

Todas las clases, métodos y funciones del proyecto están documentados utilizando el estándar **PHPDoc (PSR-5 Draft)**, que incluye:

- **Docblocks de clase** (`/** ... */`): Describen el propósito, la referencia OWASP aplicable y el contexto de seguridad.
- **Docblocks de método**: Incluyen `@param`, `@return`, `@throws` y descripción funcional.
- **Comentarios de bloque** (`// ===...`): Separan secciones lógicas con explicación del "por qué", no solo del "qué".
- **Referencias OWASP**: Cada medida de seguridad referencia la categoría OWASP Top 10 2021 que mitiga (ej: A03:2021, A07:2021, A09:2021).

### Ejemplo de formato utilizado:

```php
/**
 * SEGURIDAD - PUNTO 2: Prevención de Enumeración de Usuarios
 * ============================================================
 * Mitiga: OWASP A07:2021 - Identification and Authentication Failures
 *
 * @param  \Illuminate\Http\Request  $request
 * @return \Illuminate\Http\RedirectResponse
 * @throws \Illuminate\Validation\ValidationException
 */
```

## Herramientas de Desarrollo

### Laravel Telescope

Herramienta de debugging disponible **solo en entorno local** (`--dev`):

```
http://localhost:8000/telescope
```

Monitorea: Requests, Queries SQL, Excepciones, Logs, Cache, Mail, Jobs, Eventos.

> **Nota**: Los datos sensibles (contraseñas, tokens, PINs) se enmascaran automáticamente en Telescope.

## Instalación

```bash
# Clonar el repositorio
git clone <repo-url> LoginSeguro
cd LoginSeguro

# Instalar dependencias
composer install
npm install && npm run build

# Configurar entorno
cp .env.example .env
php artisan key:generate

# Ejecutar migraciones y seeders
php artisan migrate --seed
```

## Usuarios de Prueba

| Rol | Email | Contraseña |
|-----|-------|------------|
| Invitado | `invitado@test.com` | `f33_K4Na%/VG` |
| Usuario | `usuario@test.com` | `f33_K4Na%/VG` |
| Admin | `admin@test.com` | `f33_K4Na%/VG` |

## Documentación Adicional

- [`SECURITY.md`](SECURITY.md) — Políticas de seguridad y reporte de vulnerabilidades
- [`EXPLICACION_HARDENING_COMPLETA.md`](EXPLICACION_HARDENING_COMPLETA.md) — Explicación detallada de cada medida de seguridad
- [`TESTING.md`](TESTING.md) — Metodología y documentación de pruebas

## Licencia

Este proyecto es software de código abierto bajo la licencia [MIT](https://opensource.org/licenses/MIT).

