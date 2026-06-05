<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\View\View;
use PragmaRX\Google2FA\Google2FA;

/**
 * TwoFactorController - Verificación 2FA (TOTP)
 *
 * Gestiona el segundo factor de autenticación basado en
 * Time-based One-Time Password (TOTP) usando Google Authenticator
 * u otras aplicaciones compatibles con RFC 6238.
 *
 * Aplica a roles: Usuario y Admin.
 * Sube auth_level de 1 a 2.
 */
class TwoFactorController extends Controller
{
    /**
     * Muestra el formulario de verificación TOTP.
     *
     * SEGURIDAD: Solo accesible si el usuario está autenticado (1FA)
     * pero aún no ha completado 2FA (auth_level < 2).
     */
    public function show(Request $request): View|RedirectResponse
    {
        $user = Auth::user();

        // Si el usuario no tiene secreto 2FA configurado,
        // redirigir al setup de 2FA
        if (empty($user->two_factor_secret)) {
            return redirect()->route('2fa.setup');
        }

        return view('auth.two-factor-challenge');
    }

    /**
     * Verifica el código TOTP ingresado por el usuario.
     *
     * SEGURIDAD CRÍTICA:
     * - Valida el código TOTP contra el secreto almacenado (cifrado) del usuario.
     * - Regenera la sesión tras verificación exitosa (prevención Session Fixation).
     * - Rate limited: 3 intentos por minuto (configurado en RouteServiceProvider).
     * - El código TOTP tiene una ventana de validez limitada (~30 segundos).
     */
    public function verify(Request $request): RedirectResponse
    {
        $request->validate([
            'code' => ['required', 'string', 'size:6'],
        ]);

        $user = Auth::user();
        $google2fa = new Google2FA();

        // SEGURIDAD: verifyKey compara el código TOTP ingresado con
        // el secreto del usuario. El cast 'encrypted' en el modelo
        // descifra automáticamente el secreto al accederlo.
        $valid = $google2fa->verifyKey(
            $user->two_factor_secret,
            $request->input('code')
        );

        if (! $valid) {
            // SEGURIDAD: Log de intento fallido de 2FA
            Log::channel('security')->warning('❌ [SEGURIDAD] Verificación 2FA fallida (código TOTP incorrecto)', [
                'user_id'   => $user->id,
                'email'     => $user->email,
                'ip'        => $request->ip(),
                'user_agent' => $request->userAgent(),
                'timestamp' => now()->toIso8601String(),
            ]);

            return back()->withErrors([
                'code' => 'El código de verificación es incorrecto o ha expirado.',
            ]);
        }

        // SEGURIDAD: Regenerar sesión para prevenir Session Fixation
        // en cada paso exitoso de verificación MFA.
        $request->session()->regenerate();

        // Elevar el nivel de autenticación a 2 (2FA completado)
        session(['auth_level' => 2]);

        // SEGURIDAD: Log de verificación 2FA exitosa
        Log::channel('security')->info('✅ [SEGURIDAD] Verificación 2FA exitosa', [
            'user_id'   => $user->id,
            'email'     => $user->email,
            'ip'        => $request->ip(),
            'timestamp' => now()->toIso8601String(),
        ]);

        return redirect()->route('role.redirect');
    }
}
