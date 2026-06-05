<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    |
    | SEGURIDAD: CORS restringido a orígenes específicos.
    | ANTES: allowed_origins => ['*'] (CRÍTICO — cualquier sitio podía hacer requests)
    | AHORA: Solo orígenes locales de desarrollo. En producción, reemplazar con el dominio real.
    |
    | OWASP A01:2021 – Broken Access Control
    |
    */

    'paths' => ['api/*', 'sanctum/csrf-cookie'],

    'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],

    'allowed_origins' => explode(',', env('CORS_ALLOWED_ORIGINS', 'http://localhost,http://localhost:8000,http://127.0.0.1:8000')),

    'allowed_origins_patterns' => [],

    'allowed_headers' => ['Content-Type', 'X-Requested-With', 'Authorization', 'Accept', 'X-CSRF-TOKEN', 'X-XSRF-TOKEN'],

    'exposed_headers' => [],

    'max_age' => 7200,

    'supports_credentials' => true,

];
