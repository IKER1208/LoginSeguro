# 🧪 TESTING.md — Documentación de Pruebas de Seguridad

## Índice

1. [Metodología de Pruebas](#1-metodología-de-pruebas)
2. [Pruebas de Factores de Autenticación](#2-pruebas-de-factores-de-autenticación)
3. [Pruebas de Rate Limiting](#3-pruebas-de-rate-limiting)
4. [Pruebas de Cabeceras de Seguridad](#4-pruebas-de-cabeceras-de-seguridad)
5. [Pruebas de Sanitización de Inputs](#5-pruebas-de-sanitización-de-inputs)
6. [Pruebas de Sesión Segura](#6-pruebas-de-sesión-segura)
7. [Ejecución de las Pruebas](#7-ejecución-de-las-pruebas)
8. [Resultados Esperados](#8-resultados-esperados)

---

## 1. Metodología de Pruebas

### Enfoque

Se utiliza una combinación de **pruebas automatizadas** (PHPUnit Feature Tests) y **verificación manual** para validar los controles de seguridad del sistema.

### Herramientas

| Herramienta | Propósito |
|-------------|-----------|
| **PHPUnit 10.x** | Tests automatizados de Feature (HTTP) |
| **Laravel HTTP Tests** | Simulación de requests con `$this->get()`, `$this->post()` |
| **RefreshDatabase** | Base de datos limpia en cada test |
| **Laravel Telescope** | Inspección visual de requests, queries, logs |

### Estándar de Documentación

Las pruebas siguen el estándar **PHPDoc** con nombres descriptivos en formato `test_<componente>_<comportamiento_esperado>`.

### Archivos de Test

| Archivo | Cobertura |
|---------|-----------|
| `tests/Feature/SecurityFeaturesTest.php` | Cabeceras HTTP, Rate Limiting, Sanitización, Sesión |
| `tests/Feature/Auth/AuthenticationTest.php` | Login, Logout (Breeze default) |
| `tests/Feature/Auth/RegistrationTest.php` | Registro (Breeze default) |
| `tests/Feature/Auth/PasswordResetTest.php` | Reset de contraseña (Breeze default) |
| `tests/Feature/Auth/PasswordUpdateTest.php` | Cambio de contraseña (Breeze default) |
| `tests/Feature/Auth/PasswordConfirmationTest.php` | Confirmación de contraseña (Breeze default) |
| `tests/Feature/Auth/EmailVerificationTest.php` | Verificación de email (Breeze default) |

---

## 2. Pruebas de Factores de Autenticación

### 2.1. Primer Factor (1FA) — Email + Password

| # | Caso de Prueba | Resultado Esperado | Método |
|---|---------------|-------------------|--------|
| 1 | Login con credenciales válidas | Redirect a `/redirect`, `auth_level=1` | Automatizado |
| 2 | Login con contraseña incorrecta | Error genérico, no revela si email existe | Automatizado |
| 3 | Login con email inexistente | Mismo error genérico que caso 2 | Automatizado |
| 4 | Login sin completar reCAPTCHA | Error de validación en `g-recaptcha-response` | Manual |
| 5 | Logout | Sesión invalidada, redirect a `/` | Automatizado |

### 2.2. Segundo Factor (2FA) — TOTP

| # | Caso de Prueba | Resultado Esperado | Método |
|---|---------------|-------------------|--------|
| 6 | Acceso a `/user-dashboard` sin 2FA | Redirect a `/verify/2fa` | Manual |
| 7 | Código TOTP válido | `auth_level=2`, redirect a dashboard | Manual |
| 8 | Código TOTP inválido | Error "código incorrecto o expirado" | Manual |
| 9 | Usuario sin `two_factor_secret` | Redirect a `/2fa-setup` | Manual |
| 10 | Setup 2FA: escanear QR + código válido | Secreto guardado cifrado en BD | Manual |

### 2.3. Tercer Factor (3FA) — PIN por Email

| # | Caso de Prueba | Resultado Esperado | Método |
|---|---------------|-------------------|--------|
| 11 | Acceso a `/admin-dashboard` sin 3FA | Redirect a `/verify/3fa` | Manual |
| 12 | PIN correcto | `auth_level=3`, PIN invalidado (one-time) | Manual |
| 13 | PIN incorrecto | Error "PIN incorrecto o expirado" | Manual |
| 14 | PIN expirado (>5 min) | Error de expiración, PIN regenerado | Manual |
| 15 | Reenvío de PIN | Nuevo PIN generado y enviado por email | Manual |

---

## 3. Pruebas de Rate Limiting

| # | Caso de Prueba | Límite | Resultado Esperado | Método |
|---|---------------|--------|-------------------|--------|
| 16 | 6+ intentos de login fallidos | 5/min | HTTP 422 con mensaje de espera | Automatizado |
| 17 | 4+ intentos de 2FA fallidos | 3/min | HTTP 429, error en formulario | Manual |
| 18 | 4+ intentos de 3FA fallidos | 3/min | HTTP 429, error en formulario | Manual |
| 19 | Rate limit se resetea tras tiempo | 60 seg | Login permitido nuevamente | Manual |

### Test automatizado: `test_rate_limiting_blocks_after_max_login_attempts`

Simula 6 intentos consecutivos de login con contraseña incorrecta y verifica que el 6to intento reciba un error de rate limiting.

---

## 4. Pruebas de Cabeceras de Seguridad

| # | Header | Valor Esperado | Método |
|---|--------|---------------|--------|
| 20 | `X-Frame-Options` | `DENY` | Automatizado |
| 21 | `X-Content-Type-Options` | `nosniff` | Automatizado |
| 22 | `Content-Security-Policy` | Contiene `default-src 'self'` | Automatizado |
| 23 | `Referrer-Policy` | `strict-origin-when-cross-origin` | Automatizado |
| 24 | `Permissions-Policy` | Contiene `camera=()` | Automatizado |
| 25 | `Cross-Origin-Opener-Policy` | `same-origin` | Automatizado |
| 26 | `Cross-Origin-Resource-Policy` | `same-origin` | Automatizado |
| 27 | `X-Permitted-Cross-Domain-Policies` | `none` | Automatizado |
| 28 | `Strict-Transport-Security` | Solo en producción | Manual |

### Test automatizado: `test_security_headers_are_present_on_responses`

Realiza un GET a la página principal y verifica la presencia y valor correcto de cada header de seguridad.

---

## 5. Pruebas de Sanitización de Inputs

| # | Caso de Prueba | Resultado Esperado | Método |
|---|---------------|-------------------|--------|
| 29 | Input con `<script>alert('xss')</script>` | Tags eliminados, solo texto plano | Automatizado |
| 30 | Input con `<b>texto</b>` | Solo "texto" sin tags HTML | Automatizado |
| 31 | Input de password con `<>` | Caracteres preservados (excluido) | Automatizado |
| 32 | Input normal sin HTML | Sin cambios | Automatizado |

### Test automatizado: `test_sanitize_middleware_strips_html_tags`

Envía un POST con tags HTML inyectados y verifica que el middleware `SanitizeInput` los elimine antes de llegar al controlador.

---

## 6. Pruebas de Sesión Segura

| # | Caso de Prueba | Resultado Esperado | Método |
|---|---------------|-------------------|--------|
| 33 | Session regeneration tras login | Nuevo session ID después de auth | Automatizado |
| 34 | Session encryption habilitado | `SESSION_ENCRYPT=true` en config | Automatizado |
| 35 | Cookie SameSite=strict | Atributo `same_site` es `strict` | Automatizado |
| 36 | Cookie HttpOnly=true | `http_only` es `true` | Automatizado |
| 37 | Sesión invalidada tras logout | `auth_level` eliminado, session ID regenerado | Manual |
| 38 | `Cache-Control: no-store` en páginas auth | Header presente para usuarios autenticados | Manual |

---

## 7. Ejecución de las Pruebas

### Ejecutar todas las pruebas

```bash
php artisan test
```

### Ejecutar solo las pruebas de seguridad

```bash
php artisan test --filter=SecurityFeaturesTest
```

### Ejecutar un test específico

```bash
php artisan test --filter=test_security_headers_are_present_on_responses
```

### Ejecutar con cobertura detallada

```bash
php artisan test --filter=SecurityFeaturesTest -v
```

---

## 8. Resultados Esperados

Al ejecutar `php artisan test --filter=SecurityFeaturesTest`, todos los tests deben pasar:

```
PASS  Tests\Feature\SecurityFeaturesTest
✓ security headers are present on responses
✓ csp header contains required directives
✓ rate limiting blocks after max login attempts
✓ login returns generic error for wrong credentials
✓ sanitize middleware strips html tags
✓ sanitize middleware preserves password characters
✓ session config enforces encryption
✓ session config enforces strict samesite
✓ session config enforces httponly

Tests:    9 passed (30 assertions)
Duration: X.XXs
```

> **Nota**: Los tests de reCAPTCHA y MFA (2FA/3FA) se realizan manualmente porque requieren interacción con servicios externos (API de Google reCAPTCHA, Google Authenticator, servidor SMTP).
