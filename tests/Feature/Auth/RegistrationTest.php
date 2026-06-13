<?php

namespace Tests\Feature\Auth;

use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Spatie\Permission\Models\Role;
use Tests\TestCase;

class RegistrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_registration_screen_can_be_rendered(): void
    {
        $response = $this->get('/register');

        $response->assertStatus(200);
    }

    public function test_new_users_can_register(): void
    {
        // El controlador asigna el rol 'Invitado' al registrar,
        // por lo que debe existir en la BD de testing.
        Role::create(['name' => 'Invitado']);

        $response = $this->post('/register', [
            'name' => 'Test User',
            'email' => 'test@example.com',
            // Contraseña que cumple Password::defaults():
            // mín. 12 chars, letras, números y símbolos.
            'password' => 'SecurePass1!xx',
            'password_confirmation' => 'SecurePass1!xx',
            'g-recaptcha-response' => 'test-token',
        ]);

        $this->assertAuthenticated();
        $response->assertRedirect(RouteServiceProvider::HOME);
    }
}
