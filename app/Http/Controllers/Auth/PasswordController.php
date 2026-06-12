<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Traits\LogsSecurityEvents;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rules\Password;

class PasswordController extends Controller
{
    use LogsSecurityEvents;

    /**
     * Update the user's password.
     *
     * SEGURIDAD: La contraseña se asigna en texto plano porque el cast
     * 'hashed' en el modelo User se encarga automáticamente del hashing.
     * NO usar Hash::make() aquí, ya que causaría double-hashing.
     *
     * CLEAN CODE:
     * - Usa validación nativa de Laravel (validateWithBag).
     * - La regla 'current_password' verifica la contraseña actual automáticamente.
     * - Password::defaults() aplica las reglas definidas en AppServiceProvider.
     * - NO se necesita try/catch: son operaciones locales (BD + validación).
     */
    public function update(Request $request): RedirectResponse
    {
        $validated = $request->validateWithBag('updatePassword', [
            'current_password' => ['required', 'current_password'],
            'password' => ['required', Password::defaults(), 'confirmed'],
        ]);

        // El cast 'hashed' en User hashea automáticamente.
        // NO usar Hash::make() para evitar double-hashing.
        $request->user()->update([
            'password' => $validated['password'],
        ]);

        $this->logSecurity('info', '🔑 [SEGURIDAD] Contraseña actualizada desde perfil');

        return back()->with('status', 'password-updated');
    }
}
