# 🔒 LoginSeguro — Documentación de Seguridad

## Visión General

LoginSeguro es un sistema de autenticación multi-factor progresivo construido sobre **Laravel 10 + Breeze**, endurecido siguiendo las mejores prácticas de **OWASP Top 10**, **Defense in Depth** y **Secure by Default**.

---

## Arquitectura de Autenticación

### Pipeline MFA Progresivo

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   1FA        │    │   2FA        │    │   3FA        │    │  Dashboard   │
│ Email+Pass   │───▶│ TOTP Code    │───▶│ PIN Email    │───▶│  Protegido   │
│ (Todos)      │    │ (Usuario/    │    │ (Solo Admin) │    │  por Rol     │
│              │    │  Admin)      │    │              │    │              │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
     │                    │                    │
     ▼                    ▼                    ▼
 auth_level=1        auth_level=2        auth_level=3
```

### Requisitos por Rol

| Rol | 1FA (Email+Pass) | 2FA (TOTP) | 3FA (PIN Email) | Dashboard |
|-----|:-:|:-:|:-:|-----|
| **Invitado** | ✅ | — | — | `/guest-dashboard` |
| **Usuario** | ✅ | ✅ | — | `/user-dashboard` |
| **Admin** | ✅ | ✅ | ✅ | `/admin-dashboard` |

---

## Protecciones Implementadas

### 1. Autenticación y Contraseñas (OWASP A07:2021)

| Protección | Implementación | Archivo |
|-----------|---------------|---------|
| Hashing Argon2id | `config/hashing.php` driver `argon2id` | `config/hashing.php` |
| Política passwords | min(12) + letras + números + símbolos + HIBP | `AppServiceProvider.php` |
| Anti-enumeración login | Mensaje genérico idéntico | `LoginRequest.php` |
| Anti-enumeración reset | Siempre mismo mensaje de éxito | `PasswordResetLinkController.php` |
| Rate limiting login | 5 intentos/min por email+IP | `LoginRequest.php` + `RouteServiceProvider.php` |
| Rate limiting 2FA/3FA | 3 intentos/min por usuario | `RouteServiceProvider.php` |
| reCAPTCHA v2 | Registro con verificación Google | `Recaptcha.php` |
| Session regeneration | En cada paso MFA (1FA, 2FA, 3FA) | Controladores Auth |
| Concurrent sessions | `logoutOtherDevices()` + `AuthenticateSession` | `AuthenticatedSessionController.php` |

### 2. Sesiones (OWASP A07:2021)

| Protección | Valor | Detalle |
|-----------|-------|---------|
| Driver | `database` | Soporta `logoutOtherDevices()` |
| Lifetime | 15 min | Balance seguridad/UX |
| Encrypt | `true` | Datos cifrados AES-256-CBC |
| HttpOnly | `true` | No accesible via JavaScript |
| SameSite | `strict` | Máxima protección CSRF |
| Secure Cookie | `false` local / `true` prod | HTTPS required en producción |
| Regeneration | Cada paso MFA | Previene Session Fixation |

### 3. Headers HTTP de Seguridad (OWASP A05:2021)

| Header | Valor | Mitiga |
|--------|-------|--------|
| `Content-Security-Policy` | Restrictivo con nonce | XSS, data injection |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Strict-Transport-Security` | 1 año + subdomains (prod) | Downgrade attacks |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Info leaks |
| `Permissions-Policy` | camera, mic, geo, payment denied | API abuse |
| `Cache-Control` | `no-store` (auth pages) | Back-button data leak |
| `Cross-Origin-Opener-Policy` | `same-origin` | Spectre, window.opener |
| `Cross-Origin-Resource-Policy` | `same-origin` | Cross-origin data leak |
| `X-Permitted-Cross-Domain-Policies` | `none` | Flash/PDF plugin abuse |

### 4. CSRF (OWASP A01:2021)

- ✅ `VerifyCsrfToken` middleware en todas las rutas web
- ✅ `@csrf` en todos los formularios Blade
- ✅ `SameSite=strict` cookies
- ✅ Sin exclusiones en `$except`
- ✅ Token regenerado en logout

### 5. XSS (OWASP A03:2021)

- ✅ Blade auto-escaping `{{ }}`
- ✅ CSP con nonce para scripts (`Vite::cspNonce()`)
- ✅ `X-Content-Type-Options: nosniff`
- ✅ `TrimStrings` middleware
- ✅ Validación backend estricta

### 6. SQL Injection (OWASP A03:2021)

- ✅ Eloquent ORM exclusivamente (no raw queries)
- ✅ MySQL strict mode habilitado
- ✅ Mass assignment protection (`$fillable`)

### 7. RBAC y Autorización (OWASP A01:2021)

- ✅ Spatie Laravel Permission
- ✅ Middleware order: `auth → role → 2fa → 3fa`
- ✅ Fallback a login si no hay rol asignado

### 8. MFA / 2FA / 3FA

- ✅ TOTP (RFC 6238) via `pragmarx/google2fa`
- ✅ QR code generado localmente (SVG, sin APIs externas)
- ✅ Secreto TOTP cifrado en reposo (cast `encrypted`)
- ✅ Replay protection (`forbid_old_passwords = true`)
- ✅ PIN 3FA hasheado (bcrypt), one-time use
- ✅ PIN 3FA con expiración de 5 minutos
- ✅ PIN generado con CSPRNG (`random_int`)

---

## Logging y Auditoría (OWASP A09:2021)

### Canal de Seguridad Dedicado

Todos los eventos de seguridad se registran en `storage/logs/security.log` con rotación diaria y retención de 90 días.

### Eventos Monitoreados

| Evento | Emoji | Nivel | Listener/Controller |
|--------|-------|-------|-------------------|
| Login exitoso | ✅ | info | `LogSuccessfulLogin` |
| Login fallido | 🔒 | warning | `LogAuthenticationFailure` |
| Rate limit (lockout) | 🚨 | warning | `LogLockoutEvent` |
| Password changed | 🔑 | warning | `LogPasswordChange` |
| Registro exitoso | ✅ | info | `RegisteredUserController` |
| 2FA verificado | ✅ | info | `TwoFactorController` |
| 2FA fallido | ❌ | warning | `TwoFactorController` |
| 3FA PIN enviado | 📧 | info | `ThreeFactorController` |
| 3FA verificado | ✅ | info | `ThreeFactorController` |
| 3FA fallido | ❌ | warning | `ThreeFactorController` |
| 3FA PIN expirado | ⏰ | warning | `ThreeFactorController` |
| Logout | 🚪 | info | `AuthenticatedSessionController` |
| Acceso no autenticado | 🔐 | warning | `Handler.php` |
| HTTP 403/419/429 | ⚠️ | warning | `Handler.php` |

### Formato de Log

```json
{
  "message": "✅ [SEGURIDAD] Login exitoso",
  "context": {
    "user_id": 1,
    "email": "admin@example.com",
    "ip": "127.0.0.1",
    "user_agent": "Mozilla/5.0 ...",
    "timestamp": "2026-06-03T12:00:00+00:00"
  }
}
```

---

## Configuración para Producción

### Checklist de Despliegue

```bash
# 1. Variables de entorno OBLIGATORIAS
APP_ENV=production
APP_DEBUG=false
SESSION_SECURE_COOKIE=true
SESSION_DRIVER=database

# 2. Generar nueva APP_KEY (si es primera vez)
php artisan key:generate

# 3. Ejecutar migraciones
php artisan migrate --force

# 4. Cachear configuración
php artisan config:cache
php artisan route:cache
php artisan view:cache

# 5. Auditar dependencias
composer audit

# 6. Permisos del filesystem
chmod -R 755 storage bootstrap/cache
chown -R www-data:www-data storage bootstrap/cache
chmod 600 .env
```

### Variables de Producción

| Variable | Local | Producción |
|----------|-------|-----------|
| `APP_ENV` | `local` | `production` |
| `APP_DEBUG` | `true` | **`false`** |
| `SESSION_SECURE_COOKIE` | `false` | **`true`** |
| `SESSION_DRIVER` | `database` | `database` |
| `LOG_LEVEL` | `debug` | `warning` |
| `DB_USERNAME` | `root` | **usuario dedicado** |
| `CORS_ALLOWED_ORIGINS` | `localhost` | **dominio real** |

---

## Rotación de Secretos

### APP_KEY

```bash
# 1. Hacer backup de la key actual
echo $APP_KEY > /secure/backup/app_key_$(date +%Y%m%d).bak

# 2. Generar nueva key
php artisan key:generate

# ADVERTENCIA: Cambiar la APP_KEY invalida:
# - Todas las sesiones activas
# - Todos los datos cifrados con la key anterior
# - Incluyendo two_factor_secret en la tabla users
```

### Credenciales de BD

1. Crear nuevo usuario MySQL con mínimos privilegios
2. Actualizar `.env` con nuevas credenciales
3. Revocar permisos del usuario anterior
4. Ejecutar `php artisan config:cache`

### reCAPTCHA Keys

1. Generar nuevas keys en [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin)
2. Actualizar `RECAPTCHA_SITE_KEY` y `RECAPTCHA_SECRET_KEY` en `.env`
3. Ejecutar `php artisan config:cache`

---

## Riesgos Residuales

| Riesgo | Severidad | Mitigación |
|--------|-----------|-----------|
| `unsafe-eval` en CSP | Media | Requerido por Alpine.js; migrar a Alpine CSP build en futuro |
| `unsafe-inline` en style-src | Baja | Requerido por Tailwind; usar nonces en futuro |
| Session driver `file` en dev | Baja | `logoutOtherDevices()` no funciona con file; usar database |
| SMS como canal MFA | N/A | No implementado; se usa TOTP + Email (más seguro) |
| No hay WAF | Media | Implementar en infraestructura (CloudFlare, AWS WAF) |
| No hay CI/CD security scanning | Media | Implementar `composer audit` en pipeline CI |

---

## Referencias

- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) — Digital Identity Guidelines
- [Laravel Security Best Practices](https://laravel.com/docs/10.x/security)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [RFC 6238 — TOTP](https://tools.ietf.org/html/rfc6238)
