<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Regla de validación personalizada para Google reCAPTCHA v2.
 *
 * Verifica el token g-recaptcha-response enviado desde el formulario
 * contra la API de Google para confirmar que el usuario es humano.
 *
 * Uso: new \App\Rules\Recaptcha()
 */
class Recaptcha implements ValidationRule
{
    /**
     * Ejecuta la regla de validación.
     *
     * @param  string  $attribute  El nombre del campo (g-recaptcha-response)
     * @param  mixed   $value      El token de reCAPTCHA enviado por el formulario
     * @param  Closure $fail       Closure para reportar el fallo de validación
     */
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        // Si el token está vacío, el usuario no completó el captcha
        if (empty($value)) {
            $fail('Por favor, completa el captcha para verificar que no eres un robot.');
            return;
        }

        // TESTING: En entorno de testing, aceptar el token de prueba
        // para permitir la ejecución de tests automatizados sin depender
        // de la API externa de Google reCAPTCHA.
        if (app()->environment('testing') && $value === 'test-token') {
            return;
        }

        try {
            // Enviar solicitud POST a la API de verificación de Google
            $response = Http::asForm()->post(
                config('services.recaptcha.verify_url'),
                [
                    'secret'   => config('services.recaptcha.secret_key'),
                    'response' => $value,
                    'remoteip' => request()->ip(), // IP del usuario para mayor seguridad
                ]
            );

            // Decodificar la respuesta JSON de Google
            $body = $response->json();

            // Verificar si la validación fue exitosa
            if (!$response->successful() || !($body['success'] ?? false)) {
                // Registrar los errores en el log para debugging
                Log::warning('reCAPTCHA validation failed', [
                    'error-codes' => $body['error-codes'] ?? [],
                    'ip' => request()->ip(),
                ]);

                $fail('La verificación del captcha falló. Por favor, inténtalo de nuevo.');
            }
        } catch (\Illuminate\Http\Client\ConnectionException $e) {
            // try/catch JUSTIFICADO: reCAPTCHA es un servicio externo (API de Google).
            // ConnectionException cubre: DNS failure, timeout, red caída.
            Log::error('reCAPTCHA verification error: ' . $e->getMessage());

            $fail('No se pudo verificar el captcha. Por favor, inténtalo de nuevo.');
        }
    }
}
