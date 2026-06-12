<?php

namespace App\Http\Requests\Auth;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use App\Rules\Recaptcha;

/**
 * SEGURIDAD - PUNTO 2: Prevención de Enumeración de Usuarios
 * ============================================================
 * Mitiga: OWASP A07:2021 - Identification and Authentication Failures
 *
 * La enumeración de usuarios ocurre cuando un atacante puede determinar
 * si un email/usuario existe en el sistema basándose en las diferencias
 * en los mensajes de error de autenticación.
 *
 * Ejemplo de vulnerabilidad:
 * - "El email no existe" → el atacante sabe que el email NO está registrado
 * - "La contraseña es incorrecta" → el atacante sabe que el email SÍ existe
 *
 * SOLUCIÓN: Usar un mensaje GENÉRICO idéntico independientemente de si
 * el email existe o no: "Las credenciales proporcionadas no son correctas."
 */
class LoginRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\Rule|array|string>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
            // Validación de reCAPTCHA: previene ataques automatizados de fuerza bruta
            // antes de que el rate limiting entre en acción.
            'g-recaptcha-response' => ['required', new Recaptcha],
        ];
    }

    /**
     * Intenta autenticar las credenciales de la solicitud.
     *
     * SEGURIDAD - Mensajes Genéricos:
     * El mensaje de error 'Las credenciales proporcionadas no son correctas.'
     * se muestra siempre que la autenticación falle, sin importar la causa:
     * - Email no registrado → mismo mensaje genérico
     * - Contraseña incorrecta → mismo mensaje genérico
     * - Cuenta deshabilitada → mismo mensaje genérico
     *
     * Esto previene que un atacante pueda enumerar usuarios válidos
     * mediante análisis diferencial de respuestas.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function authenticate(): void
    {
        $this->ensureIsNotRateLimited();

        if (! Auth::attempt($this->only('email', 'password'), $this->boolean('remember'))) {
            RateLimiter::hit($this->throttleKey());

            // SEGURIDAD: Mensaje genérico que NO revela si el email existe o no.
            // Se usa una cadena fija en español en lugar de trans('auth.failed')
            // para garantizar que el mensaje sea siempre el mismo.
            throw ValidationException::withMessages([
                'email' => 'Las credenciales proporcionadas no son correctas.',
            ]);
        }

        RateLimiter::clear($this->throttleKey());
    }

    /**
     * Verifica que la solicitud de login no esté bloqueada por rate limiting.
     *
     * SEGURIDAD: Protección contra fuerza bruta.
     * Limita a 5 intentos por minuto usando la combinación email+IP
     * como identificador para evitar bloqueos masivos por IP compartida.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function ensureIsNotRateLimited(): void
    {
        if (! RateLimiter::tooManyAttempts($this->throttleKey(), 5)) {
            return;
        }

        event(new Lockout($this));

        $seconds = RateLimiter::availableIn($this->throttleKey());

        throw ValidationException::withMessages([
            'email' => 'Demasiados intentos de inicio de sesión. Por favor, inténtalo de nuevo en ' . $seconds . ' segundos.',
        ]);
    }

    /**
     * Clave de throttling para rate limiting.
     *
     * SEGURIDAD: Combina email + IP para el rate limiting.
     * Esto asegura que:
     * - Un atacante no pueda probar infinitas contraseñas para un email
     * - Usuarios legítimos en la misma red no se bloqueen entre sí
     */
    public function throttleKey(): string
    {
        return Str::transliterate(Str::lower($this->string('email')).'|'.$this->ip());
    }
}
