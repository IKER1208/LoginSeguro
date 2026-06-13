<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Vite;
use Symfony\Component\HttpFoundation\Response;

/**
 * SEGURIDAD - PUNTO 5: Headers HTTP de Seguridad
 * =================================================
 * Mitiga: XSS, Clickjacking, MIME-type sniffing, downgrade attacks.
 *
 * Este middleware inyecta cabeceras de seguridad HTTP en TODAS las respuestas
 * de la aplicación. Debe registrarse como middleware global en Kernel.php.
 *
 * Referencias OWASP:
 * - A05:2021 – Security Misconfiguration (falta de headers de seguridad)
 * - A03:2021 – Injection (CSP mitiga XSS reflejado/almacenado)
 *
 * MEJORAS APLICADAS (Hardening):
 * - Cache-Control seguro para páginas autenticadas
 * - HSTS condicional (solo producción)
 * - Cross-Origin-Opener-Policy (COOP)
 * - Cross-Origin-Resource-Policy (CORP)
 * - X-Permitted-Cross-Domain-Policies
 */
class SecurityHeadersMiddleware
{
    /**
     * Procesa la solicitud HTTP e inyecta headers de seguridad en la respuesta.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Excepción para Laravel Telescope
        // Telescope usa scripts y estilos inline que chocan con el CSP estricto.
        // Como es una herramienta de desarrollo/admin, relajamos las cabeceras aquí.
        if ($request->is('telescope', 'telescope/*')) {
            /** @var \Symfony\Component\HttpFoundation\Response $response */
            $response = $next($request);
            $response->headers->set('X-Frame-Options', 'SAMEORIGIN');
            $response->headers->set('X-Content-Type-Options', 'nosniff');
            return $response;
        }

        /** @var \Symfony\Component\HttpFoundation\Response $response */
        $response = $next($request);

        // ============================================================
        // X-Frame-Options: DENY
        // ============================================================
        // Mitiga: Clickjacking (OWASP - UI Redressing)
        // Impide que la página sea embebida en un <iframe>, <frame>,
        // <embed> u <object> de cualquier origen.
        // Esto previene ataques donde un sitio malicioso superpone
        // elementos invisibles sobre nuestra interfaz para engañar
        // al usuario y que haga clic en acciones no deseadas.
        $response->headers->set('X-Frame-Options', 'DENY');

        // ============================================================
        // X-Content-Type-Options: nosniff
        // ============================================================
        // Mitiga: MIME-type sniffing / Content-type confusion attacks
        // Evita que el navegador intente "adivinar" el tipo MIME de un
        // recurso. Sin este header, un archivo .txt con contenido HTML/JS
        // podría ser interpretado como ejecutable, permitiendo ataques XSS.
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // ============================================================
        // Strict-Transport-Security (HSTS) — CONDICIONAL
        // ============================================================
        // Mitiga: Ataques de downgrade HTTP y Man-in-the-Middle (MITM)
        // Fuerza al navegador a usar HTTPS exclusivamente durante 1 año
        // (31536000 segundos). includeSubDomains aplica la política a
        // todos los subdominios para prevenir ataques en subdominios.
        //
        // MEJORA: Solo se activa en producción con certificado SSL válido.
        // En local con HTTP, HSTS puede causar problemas de conectividad
        // al forzar HTTPS donde no existe.
        if (app()->environment('production', 'staging')) {
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains'
            );
        }

        // ============================================================
        // Content-Security-Policy (CSP)
        // ============================================================
        // Mitiga: XSS (Cross-Site Scripting), inyección de datos, Clickjacking
        // Define una política de seguridad de contenido que restringe
        // las fuentes permitidas para scripts, estilos, imágenes, etc.
        //
        // Directivas:
        // - default-src 'self': Solo permite recursos del mismo origen por defecto.
        // - script-src 'self': Solo permite scripts del mismo origen (bloquea inline y eval).
        // - script-src: 'self' + 'unsafe-inline' para que Alpine.js funcione
        //   (Alpine usa atributos inline como x-data, @click, x-show, etc.
        //   y los componentes Breeze usan onclick handlers para logout).
        // - style-src 'self' 'unsafe-inline' + fonts.bunny.net: Permite estilos
        //   inline (Tailwind) y la hoja de estilos de fuentes externas.
        // - img-src 'self' data: + api.qrserver.com: Para QR codes del 2FA.
        // - font-src 'self' + fonts.bunny.net: Fuentes Figtree desde CDN.
        // - connect-src 'self': Solo conexiones AJAX/fetch al mismo origen.
        //   En desarrollo se añade ws://localhost:* para Vite HMR.
        // - frame-ancestors 'none': Anti-clickjacking (refuerza X-Frame-Options).
        // - base-uri 'self': Previene inyección de <base> tags maliciosos.
        // - form-action 'self': Solo permite enviar formularios al mismo origen.
        //
        // NOTA: Ajustar 'unsafe-inline' en style-src según las necesidades del frontend.
        // En un entorno ideal, se usarían nonces o hashes en lugar de 'unsafe-inline'.
        //
        // reCAPTCHA v2 requiere los dominios de Google para:
        // - script-src: cargar api.js y gstatic.com/recaptcha
        // - frame-src: renderizar el iframe del widget
        //
        // Alpine.js (usado por Laravel Breeze) requiere 'unsafe-eval' porque
        // evalúa expresiones JS en atributos como x-data, @click, x-show
        // usando new Function(). Sin esto, los dropdowns y menús no funcionan.
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-eval' 'nonce-" . Vite::cspNonce() . "' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self' https://fonts.bunny.net https://fonts.gstatic.com",
            "connect-src 'self'",
            "frame-src https://www.google.com/recaptcha/",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]);

        $response->headers->set('Content-Security-Policy', $csp);

        // ============================================================
        // Referrer-Policy: strict-origin-when-cross-origin
        // ============================================================
        // Mitiga: Filtración de información sensible en URLs
        // Controla qué información de referencia se envía con las solicitudes.
        // 'strict-origin-when-cross-origin' envía el origen completo para
        // solicitudes del mismo origen, solo el origen para cross-origin
        // sobre HTTPS, y nada si se degrada de HTTPS a HTTP.
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // ============================================================
        // Permissions-Policy (anteriormente Feature-Policy)
        // ============================================================
        // Mitiga: Uso no autorizado de APIs del navegador
        // Deshabilita el acceso a cámara, micrófono y geolocalización
        // para prevenir que scripts maliciosos inyectados accedan a
        // estos recursos del dispositivo del usuario.
        $response->headers->set(
            'Permissions-Policy',
            'camera=(), microphone=(), geolocation=(), payment=()'
        );

        // ============================================================
        // MEJORA: Cache-Control seguro para páginas autenticadas
        // ============================================================
        // Mitiga: Exposición de datos sensibles en caché del navegador
        // Previene que el botón "Atrás" del navegador muestre páginas
        // autenticadas después de cerrar sesión. También evita que
        // proxies intermedios almacenen respuestas con datos sensibles.
        //
        // Solo se aplica a páginas HTML autenticadas, no a assets estáticos.
        if ($request->user() && !$request->is('build/*', 'assets/*', '*.css', '*.js', '*.ico')) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Expires', '0');
        }

        // ============================================================
        // MEJORA: Cross-Origin-Opener-Policy (COOP)
        // ============================================================
        // Mitiga: Ataques cross-origin via window.opener
        // Aísla el contexto de navegación impidiendo que ventanas
        // abiertas desde otros orígenes interactúen con nuestra aplicación.
        // Previene ataques de tipo Spectre y cross-origin data leaks.
        $response->headers->set('Cross-Origin-Opener-Policy', 'same-origin');

        // ============================================================
        // MEJORA: Cross-Origin-Resource-Policy (CORP)
        // ============================================================
        // Mitiga: Carga no autorizada de recursos desde otros orígenes
        // Solo permite que recursos de nuestra aplicación sean cargados
        // desde el mismo origen. Previene data leaks via <img>, <script>, etc.
        $response->headers->set('Cross-Origin-Resource-Policy', 'same-origin');

        // ============================================================
        // MEJORA: X-Permitted-Cross-Domain-Policies
        // ============================================================
        // Mitiga: Acceso a recursos via Adobe Flash/PDF plugins
        // Previene que archivos crossdomain.xml sean interpretados
        // por plugins como Flash o Acrobat Reader, bloqueando
        // solicitudes cross-domain desde estos vectores legacy.
        $response->headers->set('X-Permitted-Cross-Domain-Policies', 'none');

        return $response;
    }
}
