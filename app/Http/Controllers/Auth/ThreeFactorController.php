<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\Verify3FARequest;
use App\Mail\ThreeFactorPinMail;
use App\Traits\LogsSecurityEvents;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\View\View;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;

/**
 * ThreeFactorController - Verificación 3FA (PIN por correo)
 *
 * Gestiona el tercer factor de autenticación mediante un PIN
 * de 6 dígitos enviado al correo electrónico del Admin.
 *
 * Aplica SOLO al rol: Admin.
 * Sube auth_level de 2 a 3.
 *
 * SEGURIDAD:
 * - El PIN se genera aleatoriamente en cada solicitud.
 * - Se almacena hasheado (bcrypt/argon2id) en la BD, nunca en texto plano.
 * - Rate limited: 3 intentos por minuto con respuesta 429 personalizada.
 * - El PIN expira después de 5 minutos (configurable).
 */
class ThreeFactorController extends Controller
{
    use LogsSecurityEvents;

    /**
     * Tiempo de expiración del PIN en segundos (5 minutos).
     */
    private const PIN_EXPIRATION_SECONDS = 300;

    /**
     * Muestra el formulario de verificación del PIN y envía el PIN por correo.
     *
     * SEGURIDAD: Genera un PIN criptográficamente aleatorio de 6 dígitos,
     * lo hashea antes de guardarlo en la BD, y envía el PIN en texto plano
     * únicamente por correo electrónico al Admin.
     *
     * CLEAN CODE — try/catch JUSTIFICADO:
     * Mail::send() es un servicio externo (SMTP) que puede fallar por:
     * - SMTP server down
     * - DNS resolution failure
     * - Network timeout
     * - Authentication failure
     * Se captura TransportExceptionInterface (excepción específica de Symfony Mailer)
     * para manejar el fallo sin exponer detalles internos al usuario.
     */
    public function show(Request $request): View|RedirectResponse
    {
        $user = Auth::user();

        $pin = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        $user->update([
            'three_factor_pin' => Hash::make($pin),
        ]);

        session(['3fa_pin_generated_at' => now()->timestamp]);

        // try/catch JUSTIFICADO: Envío de correo es un servicio externo (SMTP).
        // Si falla, debemos invalidar el PIN y notificar al usuario.
        try {
            Mail::to($user->email)->send(new ThreeFactorPinMail($pin));
        } catch (TransportExceptionInterface $e) {
            // Invalidar el PIN — si el email no llegó, el PIN no debe ser válido
            $user->update(['three_factor_pin' => null]);
            session()->forget('3fa_pin_generated_at');

            $this->logSecurity('error', '🚨 [SEGURIDAD] Error al enviar PIN 3FA por correo', [
                'exception' => $e->getMessage(),
            ]);

            return redirect()->route('verify.3fa')
                ->withErrors(['pin' => 'No se pudo enviar el PIN de seguridad. Inténtalo de nuevo.']);
        }

        $this->logSecurity('info', '📧 [SEGURIDAD] PIN 3FA enviado por correo');

        return view('auth.three-factor-challenge');
    }

    /**
     * Verifica el PIN ingresado por el Admin.
     *
     * SEGURIDAD CRÍTICA:
     * - Verifica expiración temporal del PIN (5 minutos).
     * - Compara el PIN ingresado contra el hash almacenado en la BD.
     * - Invalida el PIN tras verificación exitosa (one-time use).
     * - Regenera la sesión (prevención Session Fixation).
     * - Rate limited: 3 intentos por minuto (error 429 personalizado).
     *
     * CLEAN CODE:
     * - Validación delegada a Verify3FARequest (Form Request).
     * - NO usa try/catch: Hash::check() y session() son operaciones locales
     *   que no acceden a servicios externos. Cualquier excepción sería un
     *   bug real que debe propagarse al Handler centralizado.
     */
    public function verify(Verify3FARequest $request): RedirectResponse
    {
        $user = Auth::user();

        // Verificar expiración del PIN (5 minutos)
        $pinGeneratedAt = session('3fa_pin_generated_at');
        if (!$pinGeneratedAt || (now()->timestamp - $pinGeneratedAt) > self::PIN_EXPIRATION_SECONDS) {
            $this->logSecurity('warning', '⏰ [SEGURIDAD] Intento de verificación 3FA con PIN expirado');

            $user->update(['three_factor_pin' => null]);
            session()->forget('3fa_pin_generated_at');

            return redirect()->route('verify.3fa')
                ->withErrors(['pin' => 'El PIN de seguridad ha expirado. Se ha enviado uno nuevo a tu correo.']);
        }

        if (! Hash::check($request->validated('pin'), $user->three_factor_pin)) {
            $this->logSecurity('warning', '❌ [SEGURIDAD] Verificación 3FA fallida (PIN incorrecto)');

            return back()->withErrors([
                'pin' => 'El PIN de seguridad es incorrecto o ha expirado.',
            ]);
        }

        // Invalidar PIN (one-time use)
        $user->update(['three_factor_pin' => null]);
        session()->forget('3fa_pin_generated_at');

        $request->session()->regenerate();
        session(['auth_level' => 3]);

        $this->logSecurity('info', '✅ [SEGURIDAD] Verificación 3FA exitosa (Admin)');

        return redirect()->route('role.redirect');
    }
}
