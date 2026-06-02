<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Queue\SerializesModels;

/**
 * ThreeFactorPinMail - Correo de PIN para 3FA
 *
 * Envía el PIN de seguridad de 6 dígitos al correo del Admin
 * como tercer factor de autenticación.
 *
 * SEGURIDAD:
 * - El PIN se envía en texto plano SOLO por correo.
 * - En la BD se almacena únicamente el hash bcrypt del PIN.
 * - El PIN es de un solo uso (se invalida tras verificación exitosa).
 */
class ThreeFactorPinMail extends Mailable
{
    use Queueable, SerializesModels;

    /**
     * El PIN de 6 dígitos en texto plano (solo para el correo).
     */
    public string $pin;

    public function __construct(string $pin)
    {
        $this->pin = $pin;
    }

    /**
     * Sobre del correo.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'PIN de Seguridad - Verificación 3FA',
        );
    }

    /**
     * Contenido del correo.
     */
    public function content(): Content
    {
        return new Content(
            view: 'emails.three-factor-pin',
        );
    }

    /**
     * Adjuntos del correo.
     */
    public function attachments(): array
    {
        return [];
    }
}
