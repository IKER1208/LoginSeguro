<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Traits\LogsSecurityEvents;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class AuthenticatedSessionController extends Controller
{
    use LogsSecurityEvents;

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
     * 2. Regenera el ID de sesión (prevención de Session Fixation).
     * 3. Invalida sesiones en otros dispositivos.
     * 4. Establece auth_level = 1 en la sesión.
     * 5. Redirige al RoleRedirectController para el siguiente paso MFA.
     *
     * CLEAN CODE — MANEJO DE EXCEPCIONES:
     * - LoginRequest::authenticate() lanza ValidationException si falla → Laravel lo maneja nativamente.
     * - logoutOtherDevices() NO usa try/catch: es una operación interna de Laravel
     *   (no un servicio externo). Con SESSION_DRIVER=database (ya configurado),
     *   funciona correctamente. Si la BD falla, es un error real de infraestructura
     *   que debe propagarse al Handler centralizado, no ser silenciado.
     */
    public function store(LoginRequest $request): RedirectResponse
    {
        $request->authenticate();

        $request->session()->regenerate();

        // SEGURIDAD: Invalidar sesiones en otros dispositivos.
        // Requiere SESSION_DRIVER=database (configurado en .env).
        Auth::logoutOtherDevices($request->input('password'));

        session(['auth_level' => 1]);

        $this->logSecurity('info', '✅ [SEGURIDAD] Login 1FA exitoso, pipeline MFA iniciado');

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
        $userId = Auth::id();
        $userEmail = Auth::user()?->email;

        Auth::guard('web')->logout();

        $this->logSecurity('info', '🚪 [SEGURIDAD] Logout realizado', [
            'user_id' => $userId,
            'email'   => $userEmail,
        ]);

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/');
    }
}
