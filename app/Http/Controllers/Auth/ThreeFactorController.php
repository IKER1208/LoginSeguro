<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Mail\ThreeFactorPinMail;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
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
 */
class ThreeFactorController extends Controller
{
    /**
     * Muestra el formulario de verificación del PIN y envía el PIN por correo.
     *
     * SEGURIDAD: Genera un PIN criptográficamente aleatorio de 6 dígitos,
     * lo hashea con bcrypt antes de guardarlo en la BD, y envía el PIN
     * en texto plano únicamente por correo electrónico al Admin.
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

        // Enviar el PIN en texto plano por correo al Admin
        Mail::to($user->email)->send(new ThreeFactorPinMail($pin));

        return view('auth.three-factor-challenge');
    }

    /**
     * Verifica el PIN ingresado por el Admin.
     *
     * SEGURIDAD CRÍTICA:
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

        // SEGURIDAD: Hash::check compara el PIN en texto plano
        // con el hash bcrypt almacenado en la BD.
        if (! Hash::check($request->input('pin'), $user->three_factor_pin)) {
            return back()->withErrors([
                'pin' => 'El PIN de seguridad es incorrecto o ha expirado.',
            ]);
        }

        // SEGURIDAD: Invalidar el PIN después de uso exitoso (one-time use).
        // Esto previene la reutilización del PIN en caso de intercepción.
        $user->update(['three_factor_pin' => null]);

        // SEGURIDAD: Regenerar sesión para prevenir Session Fixation
        // en cada paso exitoso de verificación MFA.
        $request->session()->regenerate();

        // Elevar el nivel de autenticación a 3 (3FA completado)
        session(['auth_level' => 3]);

        return redirect()->route('role.redirect');
    }
}
