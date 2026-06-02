<x-guest-layout>
    <!-- Session Status -->
    <x-auth-session-status class="mb-4" :status="session('status')" />

    <div class="mb-4 text-sm text-gray-600">
        {{ __('Verificación de Dos Factores (2FA)') }}
    </div>

    <p class="mb-4 text-sm text-gray-500">
        Ingresa el código de 6 dígitos generado por tu aplicación autenticadora
        (Google Authenticator, Authy, etc.).
    </p>

    <form method="POST" action="{{ route('verify.2fa') }}">
        @csrf

        <!-- Código TOTP -->
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
                {{ __('Verificar Código') }}
            </x-primary-button>
        </div>
    </form>
</x-guest-layout>
