<?php

use App\Http\Controllers\Auth\RoleRedirectController;
use App\Http\Controllers\Auth\ThreeFactorController;
use App\Http\Controllers\Auth\TwoFactorController;
use App\Http\Controllers\Auth\TwoFactorSetupController;
use App\Http\Controllers\ProfileController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Aquí se registran las rutas web de la aplicación.
| Están asignadas al grupo de middleware "web" por el RouteServiceProvider.
|
*/

Route::get('/', function () {
    return view('welcome');
});

// ============================================================
// RUTA DE REDIRECCIÓN BASADA EN ROL
// ============================================================
// Punto central del pipeline MFA. Después de cada paso de autenticación,
// el usuario es redirigido aquí para determinar su siguiente paso.
Route::get('/redirect', RoleRedirectController::class)
    ->middleware('auth')
    ->name('role.redirect');

// ============================================================
// RUTAS DE VERIFICACIÓN MFA (requieren autenticación básica)
// ============================================================
// Estas rutas NO tienen los middlewares 2fa/3fa porque son precisamente
// las rutas a las que se redirige cuando esos niveles no se han alcanzado.
Route::middleware('auth')->prefix('verify')->group(function () {

    // --- 2FA: Verificación TOTP ---
    Route::get('/2fa', [TwoFactorController::class, 'show'])
        ->name('verify.2fa');
    Route::post('/2fa', [TwoFactorController::class, 'verify'])
        ->middleware('throttle:2fa-verify');

    // --- 3FA: Verificación PIN por correo ---
    Route::get('/3fa', [ThreeFactorController::class, 'show'])
        ->name('verify.3fa');
    Route::post('/3fa', [ThreeFactorController::class, 'verify'])
        ->middleware('throttle:3fa-pin');
});

// ============================================================
// RUTAS DE CONFIGURACIÓN 2FA (Setup inicial)
// ============================================================
// Permite a usuarios sin secreto TOTP configurar su autenticador
// por primera vez (escanear QR code).
Route::middleware('auth')->prefix('2fa-setup')->group(function () {
    Route::get('/', [TwoFactorSetupController::class, 'show'])
        ->name('2fa.setup');
    Route::post('/', [TwoFactorSetupController::class, 'enable'])
        ->name('2fa.setup.enable');
});

// ============================================================
// DASHBOARDS PROTEGIDOS POR ROL + NIVEL MFA
// ============================================================
// SEGURIDAD CRÍTICA: El middleware 'role' DEBE ejecutarse ANTES
// que los middlewares MFA ('2fa', '3fa').
//
// Orden correcto:  auth → role → 2fa → 3fa
// Orden incorrecto: auth → 2fa → 3fa → role  ← VULNERABLE
//
// Si el rol se verifica después del MFA, un usuario sin el rol
// correcto sería redirigido al formulario de configuración MFA
// en lugar de recibir un 403 Forbidden. Esto:
// 1. Expone formularios MFA a usuarios no autorizados
// 2. Permite a un Invitado configurar 2FA sin necesitarlo
// 3. Permite a un Usuario ver el flujo 3FA de administrador
// ============================================================

// --- Dashboard Invitado: Solo requiere 1FA (auth) + rol Invitado ---
Route::middleware(['auth', 'role:Invitado'])->group(function () {
    Route::get('/guest-dashboard', function () {
        return view('dashboards.guest');
    })->name('guest.dashboard');
});

// --- Dashboard Usuario: Requiere rol Usuario + 2FA ---
// Flujo: auth → role:Usuario (403 si no es Usuario) → 2fa (redirige a TOTP si falta)
Route::middleware(['auth', 'role:Usuario', '2fa'])->group(function () {
    Route::get('/user-dashboard', function () {
        return view('dashboards.user');
    })->name('user.dashboard');
});

// --- Dashboard Admin: Requiere rol Admin + 2FA + 3FA ---
// Flujo: auth → role:Admin (403 si no es Admin) → 2fa → 3fa
Route::middleware(['auth', 'role:Admin', '2fa', '3fa'])->group(function () {
    Route::get('/admin-dashboard', function () {
        return view('dashboards.admin');
    })->name('admin.dashboard');
});

// ============================================================
// RUTAS DE PERFIL (Breeze default)
// ============================================================
Route::middleware('auth')->group(function () {
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');
});

// ============================================================
// RUTAS DE AUTENTICACIÓN DE BREEZE (login, register, etc.)
// ============================================================
require __DIR__ . '/auth.php';
