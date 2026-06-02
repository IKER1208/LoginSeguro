<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider as ServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;

class RouteServiceProvider extends ServiceProvider
{
    /**
     * Ruta de redirección post-autenticación.
     *
     * NOTA: En este sistema MFA, no se usa HOME directamente.
     * La redirección se maneja a través del RoleRedirectController.
     *
     * @var string
     */
    public const HOME = '/redirect';

    /**
     * Define your route model bindings, pattern filters, and other route configuration.
     */
    public function boot(): void
    {
        // ============================================================
        // RATE LIMITING - Protección contra ataques de fuerza bruta
        // ============================================================

        // Rate Limiter para la API (default de Laravel)
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });

        // ============================================================
        // RATE LIMITER: LOGIN (1FA)
        // 5 intentos por minuto, identificado por IP.
        // SEGURIDAD: Limita ataques de fuerza bruta al formulario de login.
        // Se usa la IP como identificador porque el usuario aún no está autenticado.
        // ============================================================
        RateLimiter::for('login', function (Request $request) {
            return Limit::perMinute(5)->by($request->ip())
                ->response(function () {
                    return back()->withErrors([
                        'email' => 'Demasiados intentos de inicio de sesión. Por favor, inténtalo de nuevo en un minuto.',
                    ]);
                });
        });

        // ============================================================
        // RATE LIMITER: 2FA (TOTP)
        // 3 intentos por minuto, identificado por usuario autenticado.
        // SEGURIDAD: Limita ataques de fuerza bruta al código TOTP.
        // Se usa el ID del usuario porque ya pasó 1FA.
        // ============================================================
        RateLimiter::for('2fa-verify', function (Request $request) {
            return Limit::perMinute(3)->by($request->user()?->id ?: $request->ip())
                ->response(function () {
                    return back()->withErrors([
                        'code' => 'Demasiados intentos de verificación. Espera un minuto antes de intentar de nuevo.',
                    ]);
                });
        });

        // ============================================================
        // RATE LIMITER: 3FA (PIN por correo)
        // 3 intentos por minuto, identificado por usuario autenticado.
        // SEGURIDAD CRÍTICA: Devuelve error HTTP 429 personalizado.
        // Limita ataques de fuerza bruta al PIN de seguridad del Admin.
        // ============================================================
        RateLimiter::for('3fa-pin', function (Request $request) {
            return Limit::perMinute(3)->by($request->user()?->id ?: $request->ip())
                ->response(function () {
                    // SEGURIDAD: Respuesta 429 personalizada para 3FA
                    // Incluye tanto el error en el formulario como el código HTTP 429
                    return back()->withErrors([
                        'pin' => 'Has excedido el límite de intentos para el PIN de seguridad. Espera un minuto.',
                    ])->setStatusCode(429);
                });
        });

        $this->routes(function () {
            Route::middleware('api')
                ->prefix('api')
                ->group(base_path('routes/api.php'));

            Route::middleware('web')
                ->group(base_path('routes/web.php'));
        });
    }
}
