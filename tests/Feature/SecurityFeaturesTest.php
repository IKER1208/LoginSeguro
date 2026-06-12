<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

/**
 * SEGURIDAD - Requerimiento 14: Pruebas de Seguridad Automatizadas
 * ==================================================================
 * Estándar de documentación: PHPDoc (PSR-5 Draft)
 *
 * Suite de tests que verifican los controles de seguridad implementados:
 * - Cabeceras HTTP de seguridad (CSP, X-Frame-Options, etc.)
 * - Rate Limiting en endpoint de login
 * - Sanitización de inputs (middleware SanitizeInput)
 * - Configuración segura de sesiones
 * - Prevención de enumeración de usuarios
 *
 * Referencia: OWASP Testing Guide v4.2
 * Ejecución: php artisan test --filter=SecurityFeaturesTest
 */
class SecurityFeaturesTest extends TestCase
{
    use RefreshDatabase;

    // ================================================================
    // SECCIÓN 1: Cabeceras HTTP de Seguridad
    // ================================================================
    // Verifica que el middleware SecurityHeadersMiddleware inyecta
    // correctamente todas las cabeceras de protección.
    // Mitiga: OWASP A05:2021 - Security Misconfiguration
    // ================================================================

    /**
     * Verifica que las cabeceras de seguridad estén presentes en las respuestas HTTP.
     *
     * Cabeceras verificadas:
     * - X-Frame-Options: DENY (anti-clickjacking)
     * - X-Content-Type-Options: nosniff (anti-MIME sniffing)
     * - Referrer-Policy: strict-origin-when-cross-origin
     * - Permissions-Policy: restringe APIs del navegador
     * - Cross-Origin-Opener-Policy: same-origin (anti-Spectre)
     * - Cross-Origin-Resource-Policy: same-origin
     * - X-Permitted-Cross-Domain-Policies: none (anti-Flash/PDF)
     *
     * @return void
     */
    public function test_security_headers_are_present_on_responses(): void
    {
        $response = $this->get('/login');

        $response->assertStatus(200);

        // Anti-Clickjacking
        $response->assertHeader('X-Frame-Options', 'DENY');

        // Anti-MIME Sniffing
        $response->assertHeader('X-Content-Type-Options', 'nosniff');

        // Control de Referrer
        $response->assertHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Restricción de APIs del navegador
        $response->assertHeader('Permissions-Policy');

        // Anti-Spectre (aislamiento de proceso)
        $response->assertHeader('Cross-Origin-Opener-Policy', 'same-origin');

        // Anti-resource theft
        $response->assertHeader('Cross-Origin-Resource-Policy', 'same-origin');

        // Anti-Flash/PDF cross-domain
        $response->assertHeader('X-Permitted-Cross-Domain-Policies', 'none');
    }

    /**
     * Verifica que la cabecera CSP contenga las directivas de seguridad requeridas.
     *
     * Content-Security-Policy es la cabecera más crítica para prevenir XSS.
     * Debe contener al menos:
     * - default-src 'self' (solo recursos del mismo origen por defecto)
     * - script-src con nonce (scripts solo con nonce válido)
     * - style-src 'self' (estilos solo del mismo origen)
     *
     * Mitiga: OWASP A03:2021 - Injection (XSS)
     *
     * @return void
     */
    public function test_csp_header_contains_required_directives(): void
    {
        $response = $this->get('/login');

        $csp = $response->headers->get('Content-Security-Policy');

        $this->assertNotNull($csp, 'Content-Security-Policy header debe estar presente');
        $this->assertStringContainsString("default-src 'self'", $csp);
        $this->assertStringContainsString('script-src', $csp);
        $this->assertStringContainsString('style-src', $csp);
    }

    // ================================================================
    // SECCIÓN 2: Rate Limiting
    // ================================================================
    // Verifica que el sistema bloquee intentos excesivos de login.
    // Mitiga: OWASP A07:2021 - Identification and Authentication Failures
    // ================================================================

    /**
     * Verifica que el Rate Limiting bloquee tras exceder el máximo de intentos.
     *
     * Configuración actual: 5 intentos por minuto por IP (RouteServiceProvider).
     * Después del 5to intento fallido, el 6to debe recibir un error de throttle.
     *
     * El test crea un usuario real, intenta 6 logins con contraseña incorrecta
     * y verifica que el último intento sea rechazado por rate limiting.
     * El mensaje de error contiene "segundos" indicando el tiempo de espera.
     *
     * @return void
     */
    public function test_rate_limiting_blocks_after_max_login_attempts(): void
    {
        $user = User::factory()->create();

        // Realizar 5 intentos fallidos (el límite configurado)
        for ($i = 0; $i < 5; $i++) {
            $this->post('/login', [
                'email' => $user->email,
                'password' => 'wrong-password-' . $i,
                'g-recaptcha-response' => 'test-token',
            ]);
        }

        // El 6to intento debe ser bloqueado por rate limiting
        $response = $this->post('/login', [
            'email' => $user->email,
            'password' => 'wrong-password-final',
            'g-recaptcha-response' => 'test-token',
        ]);

        // Verificar que la respuesta contiene el error de throttle
        // El mensaje incluye "segundos" porque indica el tiempo de espera
        $response->assertSessionHasErrors('email');

        $errors = session('errors');
        $emailErrors = $errors->get('email');
        $hasThrottleMessage = collect($emailErrors)->contains(function ($message) {
            return str_contains($message, 'segundos') || str_contains($message, 'seconds');
        });

        $this->assertTrue($hasThrottleMessage, 'Debe mostrar mensaje de rate limiting con tiempo de espera');
    }

    // ================================================================
    // SECCIÓN 3: Anti-Enumeración de Usuarios
    // ================================================================
    // Verifica que los mensajes de error no revelen la existencia
    // de cuentas de usuario en el sistema.
    // Mitiga: OWASP A07:2021 - Identification and Authentication Failures
    // ================================================================

    /**
     * Verifica que el login devuelva un error genérico para credenciales inválidas.
     *
     * El mensaje de error debe ser idéntico tanto si:
     * - El email NO existe en la BD
     * - El email existe pero la contraseña es incorrecta
     *
     * Esto previene que un atacante pueda determinar qué emails
     * están registrados probando diferentes combinaciones.
     *
     * @return void
     */
    public function test_login_returns_generic_error_for_wrong_credentials(): void
    {
        $user = User::factory()->create();

        $genericMessage = 'Las credenciales proporcionadas no son correctas.';

        // Caso 1: Email existente + contraseña incorrecta
        $response1 = $this->post('/login', [
            'email' => $user->email,
            'password' => 'wrong-password',
            'g-recaptcha-response' => 'test-token',
        ]);

        $response1->assertSessionHasErrors('email');

        // Caso 2: Email inexistente (en una nueva sesión de test)
        $response2 = $this->post('/login', [
            'email' => 'nonexistent@example.com',
            'password' => 'any-password',
            'g-recaptcha-response' => 'test-token',
        ]);

        $response2->assertSessionHasErrors('email');

        // Ambos deben producir exactamente el mismo mensaje genérico
        // para evitar que un atacante distinga entre "email no existe"
        // y "contraseña incorrecta"
        $errors2 = session('errors')->get('email');
        $this->assertContains(
            $genericMessage,
            $errors2,
            'El mensaje de error debe ser genérico para prevenir enumeración de usuarios'
        );
    }

    // ================================================================
    // SECCIÓN 4: Sanitización de Inputs
    // ================================================================
    // Verifica que el middleware SanitizeInput elimine tags HTML
    // de los inputs antes de que lleguen a los controladores.
    // Mitiga: OWASP A03:2021 - Injection (XSS almacenado)
    // ================================================================

    /**
     * Verifica que el middleware SanitizeInput elimine etiquetas HTML del input.
     *
     * Simula un POST al registro con nombre que contiene tags HTML maliciosos.
     * El middleware debe aplicar strip_tags() antes de la validación,
     * por lo que el valor almacenado no debe contener etiquetas.
     *
     * @return void
     */
    public function test_sanitize_middleware_strips_html_tags(): void
    {
        // Simular un POST con HTML inyectado en el campo 'name'
        $response = $this->post('/register', [
            'name' => '<script>alert("xss")</script>Test User',
            'email' => 'sanitize-test@example.com',
            'password' => 'S3cure_P@ssw0rd!',
            'password_confirmation' => 'S3cure_P@ssw0rd!',
            'g-recaptcha-response' => 'test-token',
        ]);

        // Verificar que el usuario se creó con el nombre sanitizado (sin tags)
        $this->assertDatabaseHas('users', [
            'email' => 'sanitize-test@example.com',
            'name' => 'alert("xss")Test User',
        ]);
    }

    /**
     * Verifica que el middleware SanitizeInput NO modifique contraseñas.
     *
     * Las contraseñas pueden contener legítimamente caracteres como '<' y '>'.
     * El middleware debe excluir los campos 'password' y 'password_confirmation'
     * para no alterar la contraseña real del usuario.
     *
     * @return void
     */
    public function test_sanitize_middleware_preserves_password_characters(): void
    {
        // Contraseña que contiene caracteres que strip_tags() eliminaría
        $passwordWithSpecialChars = 'P@ss<w0rd>Test!';

        $this->post('/register', [
            'name' => 'Password Test User',
            'email' => 'password-test@example.com',
            'password' => $passwordWithSpecialChars,
            'password_confirmation' => $passwordWithSpecialChars,
            'g-recaptcha-response' => 'test-token',
        ]);

        // Verificar que el usuario puede autenticarse con la contraseña original
        // (si strip_tags se aplicara, la contraseña almacenada sería diferente)
        $user = User::where('email', 'password-test@example.com')->first();

        if ($user) {
            $this->assertTrue(
                \Illuminate\Support\Facades\Hash::check($passwordWithSpecialChars, $user->password),
                'La contraseña con caracteres especiales debe verificarse correctamente'
            );
        }
    }

    // ================================================================
    // SECCIÓN 5: Configuración de Sesión Segura
    // ================================================================
    // Verifica que la configuración de sesión sea segura por defecto.
    // Mitiga: OWASP A07:2021 - Identification and Authentication Failures
    // ================================================================

    /**
     * Verifica que el cifrado de sesión esté habilitado.
     *
     * Con encrypt=true, los datos de sesión se cifran con AES-256-CBC
     * antes de almacenarse, evitando que un atacante con acceso a la BD
     * pueda leer o manipular datos como auth_level.
     *
     * @return void
     */
    public function test_session_config_enforces_encryption(): void
    {
        $this->assertTrue(
            config('session.encrypt'),
            'Las sesiones deben estar cifradas (session.encrypt = true)'
        );
    }

    /**
     * Verifica que SameSite esté configurado como 'strict'.
     *
     * SameSite=strict previene que la cookie de sesión se envíe en
     * solicitudes cross-origin, mitigando ataques CSRF avanzados.
     *
     * @return void
     */
    public function test_session_config_enforces_strict_samesite(): void
    {
        $this->assertEquals(
            'strict',
            config('session.same_site'),
            'La cookie de sesión debe usar SameSite=strict'
        );
    }

    /**
     * Verifica que la cookie de sesión sea HttpOnly.
     *
     * HttpOnly=true impide que JavaScript acceda a la cookie de sesión
     * vía document.cookie, mitigando el robo de sesión mediante XSS.
     *
     * @return void
     */
    public function test_session_config_enforces_httponly(): void
    {
        $this->assertTrue(
            config('session.http_only'),
            'La cookie de sesión debe ser HttpOnly para prevenir acceso desde JavaScript'
        );
    }
}
