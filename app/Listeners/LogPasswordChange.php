<?php

namespace App\Listeners;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Log;

/**
 * SEGURIDAD - PUNTO 4: Auditoría y Monitoreo (Evento: PasswordReset)
 * ==============================================================
 * Mitiga: Falta de monitoreo y logging (OWASP A09:2021 - Security Logging and Monitoring Failures).
 *
 * Registra cada cambio o reset de contraseña con información forense.
 * Los cambios de contraseña son eventos de alta sensibilidad porque:
 *
 * 1. Si son legítimos: confirman que el usuario actualizó sus credenciales
 * 2. Si son maliciosos: indican compromiso de cuenta (account takeover)
 * 3. Permiten correlacionar con solicitudes de reset (timing, IP)
 * 4. Son requeridos para cumplimiento PCI-DSS Req. 10.2.5
 */
class LogPasswordChange
{
    /**
     * Maneja el evento de reset/cambio de contraseña.
     *
     * Se dispara después de que Password::reset() completa exitosamente
     * el cambio de contraseña de un usuario.
     *
     * @param  \Illuminate\Auth\Events\PasswordReset  $event
     * @return void
     */
    public function handle(PasswordReset $event): void
    {
        $request = request();

        Log::channel('security')->warning('🔑 [SEGURIDAD] Contraseña cambiada/reseteada', [
            'user_id'    => $event->user->id,
            'email'      => $event->user->email,
            'ip'         => $request->ip(),
            'user_agent' => $request->userAgent(),
            'url'        => $request->fullUrl(),
            'timestamp'  => now()->toIso8601String(),
        ]);
    }
}
