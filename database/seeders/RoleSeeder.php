<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;

/**
 * RoleSeeder - Seeder de roles y usuarios de prueba
 *
 * Crea los 3 roles del sistema MFA escalonado y usuarios de prueba
 * para cada rol, facilitando el testing del pipeline de autenticación.
 */
class RoleSeeder extends Seeder
{
    public function run(): void
    {
        // ============================================================
        // CREAR ROLES (Spatie Laravel Permission)
        // ============================================================
        // Los roles definen el nivel de MFA requerido para cada usuario:
        // - Invitado: Solo 1FA (email + password)
        // - Usuario:  2FA (email + password + TOTP)
        // - Admin:    3FA (email + password + TOTP + PIN por correo)

        $invitado = Role::create(['name' => 'Invitado']);
        $usuario  = Role::create(['name' => 'Usuario']);
        $admin    = Role::create(['name' => 'Admin']);

        // ============================================================
        // USUARIOS DE PRUEBA
        // ============================================================
        // Contraseña común para testing: password
        // IMPORTANTE: Cambiar las contraseñas en producción.

        // --- Usuario Invitado (1FA) ---
        $userInvitado = User::create([
            'name'     => 'Invitado Demo',
            'email'    => 'invitado@test.com',
            'password' => 'password',
        ]);
        $userInvitado->assignRole($invitado);

        // --- Usuario Regular (2FA) ---
        // NOTA: El two_factor_secret se configurará la primera vez
        // que el usuario acceda al setup de 2FA.
        $userUsuario = User::create([
            'name'     => 'Usuario Demo',
            'email'    => 'usuario@test.com',
            'password' => 'password',
        ]);
        $userUsuario->assignRole($usuario);

        // --- Usuario Admin (3FA) ---
        // NOTA: El two_factor_secret se configurará en el setup de 2FA.
        // El three_factor_pin se genera dinámicamente en cada login.
        $userAdmin = User::create([
            'name'     => 'Admin Demo',
            'email'    => 'admin@test.com',
            'password' => 'password',
        ]);
        $userAdmin->assignRole($admin);
    }
}
