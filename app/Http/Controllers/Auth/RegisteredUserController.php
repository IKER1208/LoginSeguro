<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use App\Rules\Recaptcha; // Regla de validación personalizada para reCAPTCHA
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): View
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * SEGURIDAD: La contraseña se asigna en texto plano porque el cast
     * 'hashed' en el modelo User se encarga automáticamente del hashing.
     * NO usar Hash::make() aquí, ya que causaría double-hashing.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:'.User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
            // Validación de reCAPTCHA: required asegura que el campo no esté vacío,
            // y la regla Recaptcha verifica el token con la API de Google
            'g-recaptcha-response' => ['required', new Recaptcha],
        ]);

        // SEGURIDAD: El cast 'hashed' en User cifra automáticamente.
        // NO usar Hash::make() para evitar double-hashing.
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => $request->password,
        ]);

        // ============================================================
        // ASIGNACIÓN DE ROL: Invitado (por defecto)
        // ============================================================
        // Todo usuario registrado desde el formulario público recibe
        // el rol "Invitado", que solo requiere 1FA (email + password).
        // La promoción a "Usuario" o "Admin" se hace manualmente
        // por un administrador del sistema.
        $user->assignRole('Invitado');

        // SEGURIDAD: Log de registro exitoso para auditoría
        Log::channel('security')->info('✅ [SEGURIDAD] Nuevo usuario registrado', [
            'user_id'   => $user->id,
            'email'     => $user->email,
            'role'      => 'Invitado',
            'ip'        => $request->ip(),
            'user_agent' => $request->userAgent(),
            'timestamp' => now()->toIso8601String(),
        ]);

        event(new Registered($user));

        Auth::login($user);

        // SEGURIDAD: Regenerar sesión para prevenir Session Fixation.
        $request->session()->regenerate();

        // Establecer el nivel de autenticación (1FA completado tras registro)
        session(['auth_level' => 1]);

        return redirect(RouteServiceProvider::HOME);
    }
}

