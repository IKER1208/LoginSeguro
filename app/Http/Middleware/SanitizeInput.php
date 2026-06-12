<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * SEGURIDAD - Requerimiento 4: Sanitización de Datos (Frontend y Backend)
 * ========================================================================
 * Estándar de documentación: PHPDoc (PSR-5 Draft)
 * Mitiga: OWASP A03:2021 - Injection (XSS almacenado/reflejado)
 *
 * Middleware global que intercepta TODOS los valores de tipo string
 * del request y les aplica strip_tags() para eliminar etiquetas HTML/PHP
 * antes de que lleguen a la capa de validación o a los controladores.
 *
 * Esto implementa el principio de "sanitización en la entrada" como
 * complemento a la sanitización de salida que Blade ya realiza con {{ }}.
 *
 * IMPORTANTE: Este middleware se registra en el stack global del Kernel
 * DESPUÉS de TrimStrings y ConvertEmptyStringsToNull, para que opere
 * sobre valores ya limpios de espacios y nulls.
 *
 * Campos excluidos: 'password', 'password_confirmation', 'current_password'
 * porque strip_tags() podría alterar contraseñas que contienen caracteres
 * como '<' o '>' que son válidos en passwords (ej: "p@ss<w0rd>").
 */
class SanitizeInput
{
    /**
     * Campos que NO deben ser sanitizados.
     *
     * Las contraseñas se excluyen porque pueden contener legítimamente
     * caracteres como '<' y '>' que strip_tags() eliminaría,
     * potencialmente impidiendo que el usuario use su contraseña real.
     *
     * @var array<int, string>
     */
    protected array $except = [
        'password',
        'password_confirmation',
        'current_password',
    ];

    /**
     * Intercepta la solicitud HTTP y sanitiza todos los inputs de tipo string.
     *
     * Recorre recursivamente todos los valores del request (incluyendo arrays
     * anidados como los de formularios con notación de array) y aplica:
     * - strip_tags(): Elimina etiquetas HTML y PHP (<script>, <img>, etc.)
     *
     * @param  \Illuminate\Http\Request  $request  La solicitud HTTP entrante
     * @param  \Closure  $next  El siguiente middleware en la cadena
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        $input = $request->all();

        $sanitized = $this->sanitizeArray($input);

        $request->merge($sanitized);

        return $next($request);
    }

    /**
     * Sanitiza recursivamente un array de valores.
     *
     * Soporta arrays anidados (ej: formularios con campos como
     * 'address[city]', 'items[0][name]', etc.).
     *
     * @param  array<string, mixed>  $data  Array de datos del request
     * @return array<string, mixed>  Array con los valores sanitizados
     */
    protected function sanitizeArray(array $data): array
    {
        foreach ($data as $key => $value) {
            // Saltar campos excluidos (contraseñas)
            if (in_array($key, $this->except, true)) {
                continue;
            }

            if (is_array($value)) {
                // Recursión para arrays anidados
                $data[$key] = $this->sanitizeArray($value);
            } elseif (is_string($value)) {
                // strip_tags() elimina todas las etiquetas HTML y PHP
                // Ejemplos:
                //   "<script>alert('xss')</script>"  → "alert('xss')"
                //   "<b>texto</b>"                    → "texto"
                //   "texto normal"                    → "texto normal"
                $data[$key] = strip_tags($value);
            }
        }

        return $data;
    }
}
