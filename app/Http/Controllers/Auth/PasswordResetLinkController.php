<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Password;
use Illuminate\View\View;

/**
 * SEGURIDAD - PUNTO 2: Prevención de Enumeración de Usuarios (Password Reset)
 * ==============================================================================
 * Mitiga: OWASP A07:2021 - Identification and Authentication Failures
 *
 * El flujo de "olvidé mi contraseña" es un vector clásico de enumeración:
 * - "No encontramos un usuario con ese email" → revela que el email NO existe
 * - "Te hemos enviado un enlace de recuperación" → revela que el email SÍ existe
 *
 * SOLUCIÓN: Siempre mostrar el MISMO mensaje de éxito, independientemente de
 * si el email existe o no en la base de datos. Si el email no existe,
 * simplemente no se envía ningún correo, pero el usuario ve el mismo mensaje.
 */
class PasswordResetLinkController extends Controller
{
    /**
     * Display the password reset link request view.
     */
    public function create(): View
    {
        return view('auth.forgot-password');
    }

    /**
     * Procesa la solicitud de enlace de recuperación de contraseña.
     *
     * SEGURIDAD - Respuesta genérica constante:
     * Sin importar si el email existe o no en la base de datos,
     * SIEMPRE se devuelve el mismo mensaje de éxito.
     * Esto previene la enumeración de usuarios a través del formulario
     * de "olvidé mi contraseña".
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $request->validate([
            'email' => ['required', 'email'],
        ]);

        // Intentar enviar el enlace de recuperación.
        // Si el email no existe, Password::sendResetLink() retornará
        // Password::INVALID_USER, pero NO le revelaremos eso al usuario.
        Password::sendResetLink(
            $request->only('email')
        );

        // SEGURIDAD: Siempre retornar el mismo mensaje de éxito.
        // Mensaje genérico que no confirma ni niega la existencia del email.
        // Si el email existe → se envía el correo y se muestra este mensaje.
        // Si el email NO existe → NO se envía correo pero se muestra el MISMO mensaje.
        return back()->with(
            'status',
            'Si tu correo electrónico está registrado en nuestro sistema, recibirás un enlace de recuperación en breve.'
        );
    }
}
