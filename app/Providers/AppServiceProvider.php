<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * SEGURIDAD - PUNTO 1: Políticas de Contraseñas Estrictas
     * =========================================================
     * Mitiga: Uso de credenciales débiles o comprometidas (OWASP A07:2021 - Identification and Authentication Failures).
     *
     * Password::defaults() establece las reglas mínimas que se aplican
     * automáticamente en cualquier lugar donde se use Password::defaults()
     * (registro, cambio de contraseña, reset de contraseña).
     *
     * - min(12): Contraseñas de al menos 12 caracteres (NIST SP 800-63B recomienda mínimo 8).
     * - letters(): Requiere al menos una letra.
     * - numbers(): Requiere al menos un número.
     * - symbols(): Requiere al menos un carácter especial.
     * - uncompromised(): Valida contra la API de "Have I Been Pwned" (HIBP)
     *   usando k-Anonymity para no enviar la contraseña completa.
     *   Rechaza contraseñas que hayan aparecido en filtraciones de datos conocidas.
     */
    public function boot(): void
    {
        Password::defaults(function () {
            return Password::min(12)   // Mínimo 12 caracteres
                ->letters()            // Requiere letras (a-z, A-Z)
                ->numbers()            // Requiere números (0-9)
                ->symbols()            // Requiere símbolos (!@#$%^&*, etc.)
                ->uncompromised();     // Verifica contra la base de datos de HIBP
        });
    }
}
