<?php

namespace App\Exceptions;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Throwable;

class Handler extends ExceptionHandler
{
    /**
     * The list of the inputs that are never flashed to the session on validation exceptions.
     *
     * SEGURIDAD: Previene que datos sensibles se almacenen en la sesión
     * al redirigir de vuelta después de un error de validación.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
        'pin',
        'code',
        'two_factor_secret',
        'three_factor_pin',
    ];

    /**
     * Register the exception handling callbacks for the application.
     *
     * SEGURIDAD: Registra logging específico para excepciones de seguridad.
     * Las excepciones de autenticación y autorización se registran en el
     * canal de seguridad dedicado para correlación con otros eventos.
     */
    public function register(): void
    {
        $this->reportable(function (Throwable $e) {
            //
        });

        // ============================================================
        // SEGURIDAD: Log de excepciones de autenticación
        // ============================================================
        // Se dispara cuando un usuario no autenticado intenta acceder
        // a una ruta protegida por el middleware 'auth'.
        $this->reportable(function (AuthenticationException $e) {
            $request = request();
            Log::channel('security')->warning('🔐 [SEGURIDAD] Acceso no autenticado rechazado', [
                'url'        => $request->fullUrl(),
                'method'     => $request->method(),
                'ip'         => $request->ip(),
                'user_agent' => $request->userAgent(),
                'guard'      => implode(', ', $e->guards()),
                'timestamp'  => now()->toIso8601String(),
            ]);
        })->stop();

        // ============================================================
        // SEGURIDAD: Log de errores HTTP de seguridad (403, 419, 429)
        // ============================================================
        // 403: Acceso denegado (RBAC, policies)
        // 419: Token CSRF expirado/inválido
        // 429: Rate limit excedido
        $this->reportable(function (HttpException $e) {
            $securityCodes = [403, 419, 429];
            if (in_array($e->getStatusCode(), $securityCodes)) {
                $request = request();
                Log::channel('security')->warning('⚠️ [SEGURIDAD] Error HTTP de seguridad', [
                    'status_code' => $e->getStatusCode(),
                    'message'     => $e->getMessage(),
                    'url'         => $request->fullUrl(),
                    'method'      => $request->method(),
                    'ip'          => $request->ip(),
                    'user_id'     => $request->user()?->id,
                    'user_agent'  => $request->userAgent(),
                    'timestamp'   => now()->toIso8601String(),
                ]);
            }
        })->stop();
    }
}
