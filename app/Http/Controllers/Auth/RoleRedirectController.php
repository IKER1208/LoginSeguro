<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * RoleRedirectController - Enrutador de Autenticación Progresiva
 *
 * Controlador invocable (__invoke) que actúa como punto central de decisión
 * en el pipeline MFA. Después de cada paso exitoso de autenticación,
 * el usuario es redirigido aquí para determinar el siguiente paso.
 *
 * LÓGICA DE DECISIÓN (expresión match de PHP 8):
 * - Invitado (auth_level 1): → /guest-dashboard (no requiere más pasos)
 * - Usuario (auth_level 1): → verificar 2FA (TOTP)
 * - Usuario (auth_level 2): → /user-dashboard
 * - Admin (auth_level 1): → verificar 2FA (TOTP)
 * - Admin (auth_level 2): → verificar 3FA (PIN por correo)
 * - Admin (auth_level 3): → /admin-dashboard
 */
class RoleRedirectController extends Controller
{
    /**
     * Redirige al usuario según su rol y nivel de autenticación actual.
     *
     * SEGURIDAD: Este controlador no eleva el auth_level, solo lee
     * el estado actual y redirige al siguiente paso necesario.
     * La elevación del auth_level ocurre SOLO en los controladores
     * de verificación (TwoFactorController, ThreeFactorController).
     */
    public function __invoke(Request $request): RedirectResponse
    {
        $user = Auth::user();
        $authLevel = session('auth_level', 0);

        // ============================================================
        // EXPRESIÓN MATCH (PHP 8) - Decisión de redirección
        // ============================================================
        // Se evalúa true para poder usar condiciones booleanas complejas
        // en cada rama del match. El orden de evaluación es importante:
        // las condiciones más específicas (Admin) van primero.

        return match (true) {
            // ---- ROL ADMIN: Requiere 3FA completo ----
            // Admin que completó solo 1FA → necesita verificar TOTP
            $user->hasRole('Admin') && $authLevel < 2
                => redirect()->route('verify.2fa'),

            // Admin que completó 2FA → necesita verificar PIN por correo
            $user->hasRole('Admin') && $authLevel < 3
                => redirect()->route('verify.3fa'),

            // Admin con 3FA completo → acceso al panel de Admin
            $user->hasRole('Admin')
                => redirect()->route('admin.dashboard'),

            // ---- ROL USUARIO: Requiere 2FA ----
            // Usuario que completó solo 1FA → necesita verificar TOTP
            $user->hasRole('Usuario') && $authLevel < 2
                => redirect()->route('verify.2fa'),

            // Usuario con 2FA completo → acceso al panel de Usuario
            $user->hasRole('Usuario')
                => redirect()->route('user.dashboard'),

            // ---- ROL INVITADO: Solo requiere 1FA ----
            // Invitado con 1FA completo → acceso directo al panel
            $user->hasRole('Invitado')
                => redirect()->route('guest.dashboard'),

            // ---- FALLBACK: Sin rol asignado ----
            // SEGURIDAD: Si el usuario no tiene rol, redirigir al login
            // para prevenir acceso no autorizado.
            default => redirect()->route('login'),
        };
    }
}
