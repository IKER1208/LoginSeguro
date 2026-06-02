<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class AuthenticatedSessionController extends Controller
{
    /**
     * Muestra el formulario de login (1FA: Email + Password).
     */
    public function create(): View
    {
        return view('auth.login');
    }

    /**
     * Procesa el login (1FA).
     *
     * PIPELINE DE AUTENTICACIÓN:
     * 1. Valida credenciales (email + password) mediante LoginRequest.
     * 2. Establece auth_level = 1 en la sesión.
     * 3. Regenera el ID de sesión (prevención de Session Fixation).
     * 4. Invalida sesiones en otros dispositivos (un solo dispositivo activo).
     * 5. Redirige al RoleRedirectController para decidir el siguiente paso.
     *
     * SEGURIDAD - SESSION FIXATION (OWASP A07:2021):
     * session()->regenerate() crea un nuevo ID de sesión tras el login exitoso.
     * Esto previene que un atacante que conozca el ID de sesión previo
     * pueda secuestrar la sesión autenticada del usuario.
     *
     * SEGURIDAD - PUNTO 3: SESIONES CONCURRENTES (OWASP A07:2021):
     * Auth::logoutOtherDevices() invalida todas las sesiones activas del
     * usuario en otros navegadores/dispositivos, permitiendo solo UN
     * dispositivo activo a la vez. Esto mitiga:
     * - Secuestro de sesión desde otro dispositivo
     * - Uso de credenciales robadas simultáneamente
     * - Acceso no autorizado desde sesiones olvidadas
     *
     * REQUISITO: Para que logoutOtherDevices funcione, el middleware
     * AuthenticateSession debe estar habilitado en el grupo 'web' del Kernel.
     * Además, el driver de sesión debe soportar invalidación (database, redis).
     */
    public function store(LoginRequest $request): RedirectResponse
    {
        // Autenticar con email + password (1FA)
        $request->authenticate();

        // SEGURIDAD: Regenerar sesión para prevenir Session Fixation.
        // Esto invalida el session ID anterior y genera uno nuevo,
        // manteniendo los datos de sesión pero con un nuevo identificador.
        $request->session()->regenerate();

        // ============================================================
        // SEGURIDAD - PUNTO 3: Invalidar sesiones en otros dispositivos
        // ============================================================
        // Auth::logoutOtherDevices() cierra todas las demás sesiones activas
        // del usuario, asegurando que solo el dispositivo actual tenga acceso.
        //
        // Parámetro: La contraseña en texto plano del usuario (requerida para
        // re-hashear el password_hash en la tabla sessions y así invalidar
        // las sesiones anteriores).
        //
        // NOTA: Requiere que AuthenticateSession esté en el middleware group 'web'
        // y que el driver de sesión sea 'database' o similar.
        try {
            Auth::logoutOtherDevices($request->input('password'));
        } catch (\Exception $e) {
            // Si falla (ej: driver de sesión no soportado), no bloquear el login.
            // Registrar el error para revisión.
            \Illuminate\Support\Facades\Log::warning(
                '⚠️ [SEGURIDAD] No se pudieron invalidar otras sesiones: ' . $e->getMessage()
            );
        }

        // Establecer el nivel de autenticación inicial (1FA completado)
        session(['auth_level' => 1]);

        // Redirigir al controlador que decide el siguiente paso
        // basándose en el rol del usuario
        return redirect()->route('role.redirect');
    }

    /**
     * Cierra la sesión del usuario.
     *
     * SEGURIDAD: Se invalida completamente la sesión y se regenera
     * el token CSRF para prevenir ataques de reutilización de sesión.
     */
    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        // Invalidar toda la sesión (elimina auth_level y demás datos)
        $request->session()->invalidate();

        // Regenerar token CSRF
        $request->session()->regenerateToken();

        return redirect('/');
    }
}
