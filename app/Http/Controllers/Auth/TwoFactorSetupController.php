<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\Verify2FARequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;
use PragmaRX\Google2FA\Google2FA;
use SimpleSoftwareIO\QrCode\Facades\QrCode;

/**
 * TwoFactorSetupController - Configuración inicial de 2FA (TOTP)
 *
 * Permite a los usuarios (roles Usuario y Admin) configurar su
 * autenticador TOTP (Google Authenticator, Authy, etc.) por primera vez.
 *
 * FLUJO:
 * 1. Se genera un secreto TOTP aleatorio.
 * 2. Se muestra un QR code para escanearlo con la app autenticadora.
 * 3. El usuario confirma ingresando un código TOTP válido.
 * 4. El secreto se almacena cifrado (AES-256-CBC) en la BD.
 */
class TwoFactorSetupController extends Controller
{
    /**
     * Muestra la página de configuración 2FA con el QR code.
     *
     * SEGURIDAD: El secreto se genera y almacena temporalmente en la sesión
     * hasta que el usuario lo confirme con un código válido. No se guarda
     * en la BD hasta la confirmación.
     */
    public function show(Request $request): View
    {
        $user = Auth::user();
        $google2fa = new Google2FA();

        $secret = $google2fa->generateSecretKey();

        session(['2fa_setup_secret' => $secret]);

        $qrCodeUrl = $google2fa->getQRCodeUrl(
            config('app.name', 'LoginSeguro'),
            $user->email,
            $secret
        );

        // SEGURIDAD: Generar el QR localmente como SVG.
        // Evitamos enviar el secreto a APIs externas.
        $qrCodeSvg = QrCode::size(200)
            ->margin(1)
            ->generate($qrCodeUrl);

        return view('auth.two-factor-setup', [
            'secret' => $secret,
            'qrCodeSvg' => $qrCodeSvg,
        ]);
    }

    /**
     * Confirma y habilita 2FA verificando un código TOTP.
     *
     * SEGURIDAD:
     * - Verifica que el código ingresado sea válido contra el secreto temporal.
     * - Solo después de verificación exitosa se guarda el secreto en la BD.
     * - El cast 'encrypted' en el modelo User cifra automáticamente al guardar.
     *
     * CLEAN CODE:
     * - Validación delegada a Verify2FARequest (reutilizada con TwoFactorController).
     * - NO usa try/catch: verifyKey() trabaja con datos locales, no servicios externos.
     */
    public function enable(Verify2FARequest $request): RedirectResponse
    {
        $secret = session('2fa_setup_secret');

        if (! $secret) {
            return redirect()->route('2fa.setup')
                ->withErrors(['code' => 'La sesión de configuración ha expirado. Inténtalo de nuevo.']);
        }

        $google2fa = new Google2FA();

        $valid = $google2fa->verifyKey($secret, $request->validated('code'));

        if (! $valid) {
            return back()->withErrors([
                'code' => 'El código de verificación es incorrecto. Asegúrate de escanear el QR correctamente.',
            ]);
        }

        $user = Auth::user();
        $user->update(['two_factor_secret' => $secret]);

        session()->forget('2fa_setup_secret');

        return redirect()->route('verify.2fa')
            ->with('status', '2FA configurado exitosamente. Ahora ingresa un código para verificar.');
    }
}
