<?php

namespace App\Listeners;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Log;

/**
 * SEGURIDAD - PUNTO 4: Auditoría y Monitoreo (Evento: Lockout)
 * ==============================================================
 * Mitiga: Falta de monitoreo y logging (OWASP A09:2021 - Security Logging and Monitoring Failures).
 *
 * Registra cada evento de bloqueo por rate limiting con nivel ALTO de alerta.
 * Un lockout indica que un usuario (o atacante) ha excedido el número máximo
 * de intentos de autenticación permitidos.
 *
 * Este evento es especialmente importante porque:
 * 1. Indica un posible ataque de fuerza bruta ACTIVO
 * 2. Puede señalar un ataque de credential stuffing
 * 3. Requiere atención inmediata del equipo de seguridad
 *
 * Se usa Log::warning con nivel alto para que los sistemas de monitoreo
 * (SIEM, ELK, etc.) puedan generar alertas automáticas.
 */
class LogLockoutEvent
{
    /**
     * Maneja el evento de bloqueo por exceso de intentos.
     *
     * Se dispara cuando RateLimiter detecta que se han excedido
     * los intentos máximos configurados (ej: 5 intentos/minuto para login).
     *
     * @param  \Illuminate\Auth\Events\Lockout  $event
     * @return void
     */
    public function handle(Lockout $event): void
    {
        // El evento Lockout recibe el Request completo
        $request = $event->request;

        Log::channel('security')->warning('🚨 [SEGURIDAD] Cuenta bloqueada por exceso de intentos (Rate Limit)', [
            'email'      => $request->input('email', 'N/A'),
            'ip'         => $request->ip(),
            'user_agent' => $request->userAgent(),
            'timestamp'  => now()->toIso8601String(),
            // URL que desencadenó el lockout (login, 2fa, 3fa, etc.)
            'url'        => $request->fullUrl(),
            'method'     => $request->method(),
        ]);
    }
}
