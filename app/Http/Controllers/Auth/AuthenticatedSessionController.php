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
     * 4. Redirige al RoleRedirectController para decidir el siguiente paso.
     *
     * SEGURIDAD - SESSION FIXATION:
     * session()->regenerate() crea un nuevo ID de sesión tras el login exitoso.
     * Esto previene que un atacante que conozca el ID de sesión previo
     * pueda secuestrar la sesión autenticada del usuario.
     */
    public function store(LoginRequest $request): RedirectResponse
    {
        // Autenticar con email + password (1FA)
        $request->authenticate();

        // SEGURIDAD: Regenerar sesión para prevenir Session Fixation.
        // Esto invalida el session ID anterior y genera uno nuevo,
        // manteniendo los datos de sesión pero con un nuevo identificador.
        $request->session()->regenerate();

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
