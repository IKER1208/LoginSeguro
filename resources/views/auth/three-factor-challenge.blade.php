<x-guest-layout>
    <div class="mb-4 text-sm text-gray-600">
        {{ __('Verificación de Tres Factores (3FA)') }}
    </div>

    <p class="mb-4 text-sm text-gray-500">
        Se ha enviado un PIN de seguridad de 6 dígitos a tu correo electrónico.
        Ingresa el PIN para completar la verificación.
    </p>

    <div class="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-md">
        <p class="text-sm text-yellow-700">
            <strong>Importante:</strong> El PIN es de un solo uso y expirará cuando se genere uno nuevo.
            Revisa tu bandeja de entrada (y spam) si no lo ves.
        </p>
    </div>

    <form method="POST" action="{{ route('verify.3fa') }}">
        @csrf

        <!-- PIN de Seguridad -->
        <div>
            <x-input-label for="pin" :value="__('PIN de Seguridad')" />
            <x-text-input id="pin" class="block mt-1 w-full" type="text"
                          name="pin" required autofocus autocomplete="one-time-code"
                          maxlength="6" pattern="[0-9]{6}"
                          placeholder="000000" />
            <x-input-error :messages="$errors->get('pin')" class="mt-2" />
        </div>

        <div class="flex items-center justify-between mt-4">
            <!-- Enlace para reenviar PIN -->
            <a href="{{ route('verify.3fa') }}"
               class="underline text-sm text-gray-600 hover:text-gray-900 rounded-md focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
                {{ __('Reenviar PIN') }}
            </a>

            <x-primary-button>
                {{ __('Verificar PIN') }}
            </x-primary-button>
        </div>
    </form>
</x-guest-layout>
