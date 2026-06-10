<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\Verify2FARequest;
use App\Traits\LogsSecurityEvents;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
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
    use LogsSecurityEvents;

    /**
     * Muestra el formulario de verificación TOTP.
     *
     * SEGURIDAD: Solo accesible si el usuario está autenticado (1FA)
     * pero aún no ha completado 2FA (auth_level < 2).
     */
    public function show(Request $request): View|RedirectResponse
    {
        $user = Auth::user();

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
     *
     * CLEAN CODE:
     * - Validación delegada a Verify2FARequest (Form Request).
     * - NO usa try/catch: verifyKey() no accede a servicios externos,
     *   trabaja con datos locales. Cualquier excepción sería un bug real
     *   que debe propagarse al Handler.
     */
    public function verify(Verify2FARequest $request): RedirectResponse
    {
        $user = Auth::user();
        $google2fa = new Google2FA();

        $valid = $google2fa->verifyKey(
            $user->two_factor_secret,
            $request->validated('code')
        );

        if (! $valid) {
            $this->logSecurity('warning', '❌ [SEGURIDAD] Verificación 2FA fallida (código TOTP incorrecto)');

            return back()->withErrors([
                'code' => 'El código de verificación es incorrecto o ha expirado.',
            ]);
        }

        $request->session()->regenerate();
        session(['auth_level' => 2]);

        $this->logSecurity('info', '✅ [SEGURIDAD] Verificación 2FA exitosa');

        return redirect()->route('role.redirect');
    }
}
