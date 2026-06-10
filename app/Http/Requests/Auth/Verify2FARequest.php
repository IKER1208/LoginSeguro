<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Form Request para verificación de código TOTP (2FA).
 *
 * Reutilizable en TwoFactorController::verify y TwoFactorSetupController::enable.
 * Valida que el código sea exactamente 6 dígitos.
 *
 * Uso: TwoFactorController::verify(Verify2FARequest $request)
 */
class Verify2FARequest extends FormRequest
{
    /**
     * Determina si el usuario está autorizado.
     *
     * Requiere autenticación (ya garantizada por middleware 'auth' en rutas).
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Reglas de validación para el código TOTP.
     *
     * @return array<string, \Illuminate\Contracts\Validation\Rule|array|string>
     */
    public function rules(): array
    {
        return [
            'code' => ['required', 'string', 'size:6'],
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
            'code.required' => 'El código de verificación es obligatorio.',
            'code.size' => 'El código de verificación debe tener exactamente 6 dígitos.',
        ];
    }
}
