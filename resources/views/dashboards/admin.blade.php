<x-app-layout>
    <x-slot name="header">
        <h2 class="font-semibold text-xl text-gray-800 leading-tight">
            {{ __('Panel de Administración') }}
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
                        Has iniciado sesión como <strong>Admin</strong> con autenticación de tres factores (3FA).
                    </p>

                    <div class="mt-4 p-4 bg-purple-50 border border-purple-200 rounded-md">
                        <p class="text-sm text-purple-700">
                            <strong>Nivel de autenticación:</strong> 3FA (Email + Contraseña + TOTP + PIN)
                        </p>
                        <p class="text-sm text-purple-700">
                            <strong>Rol:</strong> Admin
                        </p>
                        <p class="text-sm text-purple-700">
                            <strong>Auth Level:</strong> {{ session('auth_level', 0) }}
                        </p>
                    </div>

                    <div class="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-md">
                        <p class="text-sm text-gray-600">
                            🔒 Tu cuenta tiene el nivel máximo de seguridad con autenticación de 3 factores.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</x-app-layout>
