<?php

namespace App\Providers;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Foundation\Support\Providers\EventServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Event;

/**
 * SEGURIDAD - PUNTO 4: Registro de Event Listeners de Auditoría
 * ================================================================
 * Vincula los eventos nativos de Laravel con los listeners de auditoría.
 *
 * Eventos monitoreados:
 * - Login: Cada login exitoso (IP, UA, email)
 * - Failed: Cada intento de login con credenciales incorrectas
 * - Lockout: Cada bloqueo por exceso de intentos (rate limiting)
 * - PasswordReset: Cada cambio/reset de contraseña
 * - Registered: Verificación de email + log de registro
 */
class EventServiceProvider extends ServiceProvider
{
    /**
     * Mapeo de eventos a sus respectivos listeners.
     *
     * @var array<class-string, array<int, class-string>>
     */
    protected $listen = [
        // Listener original de Breeze para verificación de email
        Registered::class => [
            SendEmailVerificationNotification::class,
        ],

        // ============================================================
        // SEGURIDAD: Listener para login exitoso
        // Registra IP, User-Agent y email en cada login exitoso.
        // Permite detectar accesos no autorizados y cumplimiento PCI-DSS.
        // Mitiga: OWASP A09:2021 - Security Logging and Monitoring Failures
        // ============================================================
        Login::class => [
            \App\Listeners\LogSuccessfulLogin::class,
        ],

        // ============================================================
        // SEGURIDAD: Listener para intentos de login fallidos
        // Registra IP, User-Agent y email en cada intento fallido.
        // Mitiga: OWASP A09:2021 - Security Logging and Monitoring Failures
        // ============================================================
        Failed::class => [
            \App\Listeners\LogAuthenticationFailure::class,
        ],

        // ============================================================
        // SEGURIDAD: Listener para bloqueos por rate limiting
        // Registra cuando se activa el lockout por exceso de intentos.
        // Señal de un posible ataque de fuerza bruta ACTIVO.
        // Mitiga: OWASP A09:2021 - Security Logging and Monitoring Failures
        // ============================================================
        Lockout::class => [
            \App\Listeners\LogLockoutEvent::class,
        ],

        // ============================================================
        // SEGURIDAD: Listener para cambios/reset de contraseña
        // Evento de alta sensibilidad: podría indicar account takeover.
        // Mitiga: OWASP A09:2021 - Security Logging and Monitoring Failures
        // ============================================================
        PasswordReset::class => [
            \App\Listeners\LogPasswordChange::class,
        ],
    ];

    /**
     * Register any events for your application.
     */
    public function boot(): void
    {
        //
    }

    /**
     * Determine if events and listeners should be automatically discovered.
     */
    public function shouldDiscoverEvents(): bool
    {
        return false;
    }
}
