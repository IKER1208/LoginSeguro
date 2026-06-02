<?php

namespace App\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Log;

/**
 * SEGURIDAD - PUNTO 4: Auditoría y Monitoreo (Evento: Failed)
 * ==============================================================
 * Mitiga: Falta de monitoreo y logging (OWASP A09:2021 - Security Logging and Monitoring Failures).
 *
 * Registra cada intento de autenticación fallido con información forense:
 * - Dirección IP del atacante
 * - User-Agent del navegador/bot
 * - Email intentado
 *
 * Esta información es crítica para:
 * 1. Detectar ataques de fuerza bruta en tiempo real
 * 2. Identificar patrones de enumeración de usuarios
 * 3. Cumplimiento de estándares de auditoría (PCI-DSS, ISO 27001)
 * 4. Análisis forense post-incidente
 */
class LogAuthenticationFailure
{
    /**
     * Maneja el evento de autenticación fallida.
     *
     * Se dispara cada vez que Auth::attempt() falla, independientemente
     * de si el usuario existe o no en la base de datos.
     *
     * @param  \Illuminate\Auth\Events\Failed  $event
     * @return void
     */
    public function handle(Failed $event): void
    {
        // Obtener información de la solicitud HTTP actual
        $request = request();

        Log::warning('🔒 [SEGURIDAD] Intento de autenticación fallido', [
            'email'      => $event->credentials['email'] ?? 'N/A',
            'ip'         => $request->ip(),
            'user_agent' => $request->userAgent(),
            'timestamp'  => now()->toIso8601String(),
            // Indica si el usuario existe en la BD (útil para detectar enumeración)
            'user_found' => $event->user !== null,
        ]);
    }
}
