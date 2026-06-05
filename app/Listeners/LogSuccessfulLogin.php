<?php

namespace App\Listeners;

use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Log;

/**
 * SEGURIDAD - PUNTO 4: Auditoría y Monitoreo (Evento: Login)
 * ==============================================================
 * Mitiga: Falta de monitoreo y logging (OWASP A09:2021 - Security Logging and Monitoring Failures).
 *
 * Registra cada login exitoso con información forense:
 * - ID y email del usuario
 * - Dirección IP
 * - User-Agent del navegador
 * - Guard de autenticación utilizado
 *
 * Esta información es crítica para:
 * 1. Detectar accesos no autorizados (login desde IPs/dispositivos inusuales)
 * 2. Auditoría de cumplimiento (PCI-DSS, ISO 27001)
 * 3. Análisis forense post-incidente
 * 4. Correlación con eventos de fallo para detectar credential stuffing exitoso
 */
class LogSuccessfulLogin
{
    /**
     * Maneja el evento de login exitoso.
     *
     * Se dispara cada vez que Auth::attempt() o Auth::login() tiene éxito.
     *
     * @param  \Illuminate\Auth\Events\Login  $event
     * @return void
     */
    public function handle(Login $event): void
    {
        $request = request();

        Log::channel('security')->info('✅ [SEGURIDAD] Login exitoso', [
            'user_id'    => $event->user->id,
            'email'      => $event->user->email,
            'guard'      => $event->guard,
            'remember'   => $event->remember,
            'ip'         => $request->ip(),
            'user_agent' => $request->userAgent(),
            'timestamp'  => now()->toIso8601String(),
        ]);
    }
}
