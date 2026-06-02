<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PIN de Seguridad - 3FA</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f3f4f6;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 500px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            padding: 32px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        h1 {
            color: #1f2937;
            font-size: 20px;
            margin-bottom: 16px;
        }
        .pin-box {
            background-color: #eff6ff;
            border: 2px solid #3b82f6;
            border-radius: 8px;
            padding: 24px;
            text-align: center;
            margin: 24px 0;
        }
        .pin-code {
            font-size: 36px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #1e40af;
            font-family: 'Courier New', monospace;
        }
        .warning {
            background-color: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 12px;
            font-size: 13px;
            color: #92400e;
            margin-top: 16px;
        }
        .footer {
            margin-top: 24px;
            font-size: 12px;
            color: #9ca3af;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 PIN de Seguridad - Verificación 3FA</h1>

        <p style="color: #4b5563; font-size: 14px;">
            Se ha solicitado una verificación de tercer factor para tu cuenta de administrador.
            Usa el siguiente PIN para completar el inicio de sesión:
        </p>

        <div class="pin-box">
            <p style="margin: 0 0 8px 0; color: #6b7280; font-size: 13px;">Tu PIN de seguridad es:</p>
            <div class="pin-code">{{ $pin }}</div>
        </div>

        <div class="warning">
            <strong>⚠️ Importante:</strong>
            <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                <li>Este PIN es de un solo uso.</li>
                <li>No compartas este PIN con nadie.</li>
                <li>Si no solicitaste este PIN, cambia tu contraseña inmediatamente.</li>
            </ul>
        </div>

        <div class="footer">
            <p>Este correo fue enviado automáticamente por {{ config('app.name', 'LoginSeguro') }}.</p>
            <p>No respondas a este correo.</p>
        </div>
    </div>
</body>
</html>
