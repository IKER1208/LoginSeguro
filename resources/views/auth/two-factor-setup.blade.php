<x-guest-layout>
    <div class="mb-4 text-sm text-gray-600">
        {{ __('Configuración de Autenticación de Dos Factores (2FA)') }}
    </div>

    <p class="mb-4 text-sm text-gray-500">
        Escanea el siguiente código QR con tu aplicación autenticadora
        (Google Authenticator, Authy, Microsoft Authenticator, etc.) y luego
        ingresa el código de verificación generado para confirmar la configuración.
    </p>

    <!-- QR Code -->
    <div class="mb-4 flex flex-col items-center">
        <div class="p-4 bg-white border rounded-lg shadow-sm">
            {{-- Generar QR code usando una API pública --}}
            <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={{ urlencode($qrCodeUrl) }}"
                 alt="QR Code para 2FA" width="200" height="200" />
        </div>
    </div>

    <!-- Clave manual (por si no puede escanear el QR) -->
    <div class="mb-4 p-3 bg-gray-50 border border-gray-200 rounded-md">
        <p class="text-xs text-gray-500 mb-1">
            {{ __('Si no puedes escanear el QR, ingresa esta clave manualmente:') }}
        </p>
        <p class="font-mono text-sm text-gray-800 break-all select-all">
            {{ $secret }}
        </p>
    </div>

    <form method="POST" action="{{ route('2fa.setup.enable') }}">
        @csrf

        <!-- Código de confirmación -->
        <div>
            <x-input-label for="code" :value="__('Código de verificación')" />
            <x-text-input id="code" class="block mt-1 w-full" type="text"
                          name="code" required autofocus autocomplete="one-time-code"
                          maxlength="6" pattern="[0-9]{6}"
                          placeholder="000000" />
            <x-input-error :messages="$errors->get('code')" class="mt-2" />
        </div>

        <div class="flex items-center justify-end mt-4">
            <x-primary-button>
                {{ __('Activar 2FA') }}
            </x-primary-button>
        </div>
    </form>
</x-guest-layout>
