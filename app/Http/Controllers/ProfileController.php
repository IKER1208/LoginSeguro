<?php

namespace App\Http\Controllers;

use App\Http\Requests\ProfileUpdateRequest;
use App\Traits\LogsSecurityEvents;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Redirect;
use Illuminate\View\View;

class ProfileController extends Controller
{
    use LogsSecurityEvents;

    /**
     * Display the user's profile form.
     */
    public function edit(Request $request): View
    {
        return view('profile.edit', [
            'user' => $request->user(),
        ]);
    }

    /**
     * Update the user's profile information.
     *
     * CLEAN CODE:
     * - Validación delegada a ProfileUpdateRequest (Form Request nativo de Breeze).
     * - NO se necesita try/catch: User::save() es operación Eloquent local.
     *   Errores de BD (constraint violations) se manejan centralizadamente en Handler.
     */
    public function update(ProfileUpdateRequest $request): RedirectResponse
    {
        $request->user()->fill($request->validated());

        if ($request->user()->isDirty('email')) {
            $request->user()->email_verified_at = null;
        }

        $request->user()->save();

        return Redirect::route('profile.edit')->with('status', 'profile-updated');
    }

    /**
     * Delete the user's account.
     *
     * SEGURIDAD:
     * - Requiere confirmación de contraseña (regla 'current_password').
     * - Se loguea el evento ANTES de eliminar al usuario.
     * - La sesión se invalida completamente post-eliminación.
     *
     * CLEAN CODE:
     * - Usa validación nativa (validateWithBag) — no necesita Form Request
     *   dedicado porque es una sola regla simple.
     * - NO se necesita try/catch: validación + Eloquent delete son operaciones
     *   locales. Errores de BD se manejan en Handler centralizado.
     */
    public function destroy(Request $request): RedirectResponse
    {
        $request->validateWithBag('userDeletion', [
            'password' => ['required', 'current_password'],
        ]);

        $user = $request->user();

        // Loguear ANTES del logout (después Auth::user() es null)
        $this->logSecurity('warning', '🗑️ [SEGURIDAD] Cuenta de usuario eliminada', [
            'user_id' => $user->id,
            'email'   => $user->email,
        ]);

        Auth::logout();

        $user->delete();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return Redirect::to('/');
    }
}
