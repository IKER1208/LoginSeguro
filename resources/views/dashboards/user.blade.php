<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 leading-tight">
            {{ __('Panel de Usuario') }}
        </h2>
    </x-slot>

    <div class="py-12">
        <div class="max-w-7xl mx-auto sm:px-6 lg:px-8">
            <div class="bg-white overflow-hidden shadow-sm sm:rounded-lg">
                <div class="p-6 text-gray-900">
                    <h3 class="text-lg font-semibold mb-2">
                        ¡Bienvenido, {{ Auth::user()->name }}!
                    </h3>
                    <p class="text-gray-600 mb-4">
                        Has iniciado sesión como <strong>Usuario</strong> con autenticación de dos factores (2FA).
                    </p>

                    <div class="mt-4 p-4 bg-green-50 border border-green-200 rounded-md">
                        <p class="text-sm text-green-700">
                            <strong>Nivel de autenticación:</strong> 2FA (Email + Contraseña + TOTP)
                        </p>
                        <p class="text-sm text-green-700">
                            <strong>Rol:</strong> Usuario
                        </p>
                        <p class="text-sm text-green-700">
                            <strong>Auth Level:</strong> {{ session('auth_level', 0) }}
                        </p>
                    </div>

                    <div class="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-md">
                        <p class="text-sm text-gray-600">
                            ✅ Tu cuenta está protegida con autenticación TOTP.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
