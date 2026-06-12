<?php

namespace App\Http\Requests\Auth;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Form Request para verificación de PIN 3FA.
 *
 * Valida que el PIN sea exactamente 6 caracteres.
 *
 * Uso: ThreeFactorController::verify(Verify3FARequest $request)
 */
class Verify3FARequest extends FormRequest
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
     * Reglas de validación para el PIN de seguridad.
     *
     * @return array<string, \Illuminate\Contracts\Validation\Rule|array|string>
     */
    public function rules(): array
    {
        return [
            'pin' => ['required', 'string', 'size:6'],
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
            'pin.required' => 'El PIN de seguridad es obligatorio.',
            'pin.size' => 'El PIN de seguridad debe tener exactamente 6 dígitos.',
        ];
    }
}
