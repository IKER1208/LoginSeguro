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
        // Strict-Transport-Security (HSTS)
        // ============================================================
        // Mitiga: Ataques de downgrade HTTP y Man-in-the-Middle (MITM)
        // Fuerza al navegador a usar HTTPS exclusivamente durante 1 año
        // (31536000 segundos). includeSubDomains aplica la política a
        // todos los subdominios para prevenir ataques en subdominios.
        // NOTA: Solo activar en producción con certificado SSL válido.
        $response->headers->set(
            'Strict-Transport-Security',
            'max-age=31536000; includeSubDomains'
        );

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
        // - style-src 'self' 'unsafe-inline': Permite estilos del mismo origen + inline
        //   (necesario para algunos frameworks CSS como Blade/Tailwind).
        // - img-src 'self' data:: Permite imágenes propias y data URIs (para QR codes del 2FA).
        // - font-src 'self': Solo fuentes del mismo origen.
        // - connect-src 'self': Solo conexiones AJAX/fetch al mismo origen.
        // - frame-ancestors 'none': Equivalente moderno a X-Frame-Options: DENY
        //   (redundancia defensiva contra clickjacking).
        // - base-uri 'self': Previene inyección de <base> tags maliciosos.
        // - form-action 'self': Solo permite enviar formularios al mismo origen.
        //
        // NOTA: Ajustar 'unsafe-inline' en style-src según las necesidades del frontend.
        // En un entorno ideal, se usarían nonces o hashes en lugar de 'unsafe-inline'.
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'nonce-" . Vite::cspNonce() . "'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
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
            'camera=(), microphone=(), geolocation=()'
        );

        return $response;
    }
}
