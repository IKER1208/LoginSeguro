<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Middleware Require3FA
 *
 * PROTECCIÓN DE RUTAS - NIVEL 3:
 * Verifica que el usuario haya completado la verificación del PIN
 * de seguridad enviado por correo electrónico (3FA).
 * Lee la variable de sesión 'auth_level' y redirige al formulario
 * de verificación 3FA si el nivel es insuficiente.
 *
 * Uso en rutas: ->middleware('3fa')
 */
class Require3FA
{
    public function handle(Request $request, Closure $next): Response
    {
        // SEGURIDAD: Verificar que auth_level sea al menos 3 (PIN verificado).
        // El usuario debe haber completado 1FA + 2FA + 3FA para acceder
        // a las rutas protegidas con este middleware.
        $authLevel = session('auth_level', 0);

        if ($authLevel < 3) {
            return redirect()->route('verify.3fa');
        }

        return $next($request);
    }
}
