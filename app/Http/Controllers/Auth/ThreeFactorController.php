<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Mail\ThreeFactorPinMail;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\View\View;

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
 * - Se almacena hasheado (bcrypt) en la BD, nunca en texto plano.
 * - Rate limited: 3 intentos por minuto con respuesta 429 personalizada.
 * - MEJORA: El PIN expira después de 5 minutos (configurable).
 */
class ThreeFactorController extends Controller
{
    /**
     * Tiempo de expiración del PIN en segundos (5 minutos).
     */
    private const PIN_EXPIRATION_SECONDS = 300;

    /**
     * Muestra el formulario de verificación del PIN y envía el PIN por correo.
     *
     * SEGURIDAD: Genera un PIN criptográficamente aleatorio de 6 dígitos,
     * lo hashea con bcrypt antes de guardarlo en la BD, y envía el PIN
     * en texto plano únicamente por correo electrónico al Admin.
     *
     * MEJORA: Se almacena el timestamp de generación en la sesión para
     * implementar expiración temporal del PIN (5 minutos).
     */
    public function show(Request $request): View
    {
        $user = Auth::user();

        // SEGURIDAD: Generar PIN aleatorio de 6 dígitos usando
        // random_int() que es criptográficamente seguro (CSPRNG).
        $pin = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);

        // SEGURIDAD: Almacenar el PIN hasheado con bcrypt.
        // Nunca se guarda el PIN en texto plano en la base de datos.
        $user->update([
            'three_factor_pin' => Hash::make($pin),
        ]);

        // MEJORA: Almacenar timestamp de generación para expiración
        session(['3fa_pin_generated_at' => now()->timestamp]);

        // Enviar el PIN en texto plano por correo al Admin
        Mail::to($user->email)->send(new ThreeFactorPinMail($pin));

        // SEGURIDAD: Log de envío de PIN 3FA
        Log::channel('security')->info('📧 [SEGURIDAD] PIN 3FA enviado por correo', [
            'user_id'   => $user->id,
            'email'     => $user->email,
            'ip'        => $request->ip(),
            'timestamp' => now()->toIso8601String(),
        ]);

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
     */
    public function verify(Request $request): RedirectResponse
    {
        $request->validate([
            'pin' => ['required', 'string', 'size:6'],
        ]);

        $user = Auth::user();

        // MEJORA: Verificar expiración del PIN (5 minutos)
        $pinGeneratedAt = session('3fa_pin_generated_at');
        if (!$pinGeneratedAt || (now()->timestamp - $pinGeneratedAt) > self::PIN_EXPIRATION_SECONDS) {
            // SEGURIDAD: Log de intento con PIN expirado
            Log::channel('security')->warning('⏰ [SEGURIDAD] Intento de verificación 3FA con PIN expirado', [
                'user_id'   => $user->id,
                'email'     => $user->email,
                'ip'        => $request->ip(),
                'timestamp' => now()->toIso8601String(),
            ]);

            // Invalidar el PIN expirado
            $user->update(['three_factor_pin' => null]);
            session()->forget('3fa_pin_generated_at');

            return redirect()->route('verify.3fa')
                ->withErrors(['pin' => 'El PIN de seguridad ha expirado. Se ha enviado uno nuevo a tu correo.']);
        }

        // SEGURIDAD: Hash::check compara el PIN en texto plano
        // con el hash bcrypt almacenado en la BD.
        if (! Hash::check($request->input('pin'), $user->three_factor_pin)) {
            // SEGURIDAD: Log de intento fallido de 3FA
            Log::channel('security')->warning('❌ [SEGURIDAD] Verificación 3FA fallida (PIN incorrecto)', [
                'user_id'   => $user->id,
                'email'     => $user->email,
                'ip'        => $request->ip(),
                'user_agent' => $request->userAgent(),
                'timestamp' => now()->toIso8601String(),
            ]);

            return back()->withErrors([
                'pin' => 'El PIN de seguridad es incorrecto o ha expirado.',
            ]);
        }

        // SEGURIDAD: Invalidar el PIN después de uso exitoso (one-time use).
        // Esto previene la reutilización del PIN en caso de intercepción.
        $user->update(['three_factor_pin' => null]);
        session()->forget('3fa_pin_generated_at');

        // SEGURIDAD: Regenerar sesión para prevenir Session Fixation
        // en cada paso exitoso de verificación MFA.
        $request->session()->regenerate();

        // Elevar el nivel de autenticación a 3 (3FA completado)
        session(['auth_level' => 3]);

        // SEGURIDAD: Log de verificación 3FA exitosa
        Log::channel('security')->info('✅ [SEGURIDAD] Verificación 3FA exitosa (Admin)', [
            'user_id'   => $user->id,
            'email'     => $user->email,
            'ip'        => $request->ip(),
            'timestamp' => now()->toIso8601String(),
        ]);

        return redirect()->route('role.redirect');
    }
}
