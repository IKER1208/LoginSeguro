<?php

namespace App\Http\Requests\Auth;

use App\Models\User;
use App\Rules\Recaptcha;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rules;

/**
 * Form Request para registro de nuevos usuarios.
 *
 * Extrae la validación del controlador para cumplir SRP.
 * Incluye validación de reCAPTCHA como servicio externo.
 *
 * Uso: RegisteredUserController::store(RegisterRequest $request)
 */
class RegisterRequest extends FormRequest
{
    /**
     * Determina si el usuario está autorizado para esta solicitud.
     *
     * Siempre true porque el registro es público (guest).
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Reglas de validación para el registro.
     *
     * @return array<string, \Illuminate\Contracts\Validation\Rule|array|string>
     */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:' . User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
            'g-recaptcha-response' => ['required', new Recaptcha],
        ];
    }

    /**
     * Mensajes de validación personalizados.
     *
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'g-recaptcha-response.required' => 'Por favor, completa el captcha para verificar que no eres un robot.',
        ];
    }
}
