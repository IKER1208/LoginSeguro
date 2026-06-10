<?php

namespace App\Traits;

use Illuminate\Support\Facades\Log;

/**
 * Trait LogsSecurityEvents
 *
 * Centraliza el patrón de logging de seguridad repetido en los controladores.
 * Elimina la duplicación de código (DRY) al construir el contexto de log
 * con datos comunes: user_id, email, ip, user_agent, timestamp.
 *
 * Uso:
 *   use App\Traits\LogsSecurityEvents;
 *   $this->logSecurity('info', '✅ Evento exitoso');
 *   $this->logSecurity('warning', '❌ Evento fallido', ['extra' => 'data']);
 */
trait LogsSecurityEvents
{
    /**
     * Registra un evento en el canal de seguridad con contexto estándar.
     *
     * @param  string  $level    Nivel de log: 'info', 'warning', 'error', 'critical'
     * @param  string  $message  Mensaje descriptivo del evento
     * @param  array   $extra    Datos adicionales específicos del evento
     * @return void
     */
    protected function logSecurity(string $level, string $message, array $extra = []): void
    {
        $request = request();
        $user = $request->user();

        $context = array_filter(array_merge([
            'user_id'    => $user?->id,
            'email'      => $user?->email,
            'ip'         => $request->ip(),
            'user_agent' => $request->userAgent(),
            'timestamp'  => now()->toIso8601String(),
        ], $extra));

        Log::channel('security')->{$level}($message, $context);
    }
}
