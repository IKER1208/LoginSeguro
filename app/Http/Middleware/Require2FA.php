<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware Require2FA
 *
 * PROTECCIÓN DE RUTAS - NIVEL 2:
 * Verifica que el usuario haya completado la verificación TOTP (2FA).
 * Lee la variable de sesión 'auth_level' y redirige al formulario
 * de verificación 2FA si el nivel es insuficiente.
 *
 * Uso en rutas: ->middleware('2fa')
 */
class Require2FA
{
    public function handle(Request $request, Closure $next): Response
    {
        // SEGURIDAD: Verificar que auth_level sea al menos 2 (TOTP verificado).
        // Si el usuario solo completó 1FA (email/password), se le redirige
        // al formulario de verificación TOTP antes de continuar.
        $authLevel = session('auth_level', 0);

        if ($authLevel < 2) {
            return redirect()->route('verify.2fa');
        }

        return $next($request);
    }
}
