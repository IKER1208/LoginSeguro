<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RegisterRequest;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use App\Traits\LogsSecurityEvents;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class RegisteredUserController extends Controller
{
    use LogsSecurityEvents;

    /**
     * Display the registration view.
     */
    public function create(): View
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * SEGURIDAD: La contraseña se asigna en texto plano porque el cast
     * 'hashed' en el modelo User se encarga automáticamente del hashing.
     * NO usar Hash::make() aquí, ya que causaría double-hashing.
     *
     * CLEAN CODE: La validación se delega al Form Request RegisterRequest.
     * Laravel lanza ValidationException automáticamente si falla — NO se
     * necesita try/catch para validaciones.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(RegisterRequest $request): RedirectResponse
    {
        $validated = $request->validated();

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => $validated['password'],
        ]);

        $user->assignRole('Invitado');

        $this->logSecurity('info', '✅ [SEGURIDAD] Nuevo usuario registrado', [
            'role' => 'Invitado',
        ]);

        event(new Registered($user));

        Auth::login($user);

        $request->session()->regenerate();
        session(['auth_level' => 1]);

        return redirect(RouteServiceProvider::HOME);
    }
}
