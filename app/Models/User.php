<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

// ============================================================
// INTEGRACIÓN SPATIE: Trait HasRoles para gestión de roles/permisos
// Permite usar $user->assignRole(), $user->hasRole(), etc.
// ============================================================
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, HasRoles, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
        'two_factor_secret',
        'three_factor_pin',
    ];

    /**
     * The attributes that should be hidden for serialization.
     * SEGURIDAD: Se ocultan los secretos MFA en las respuestas JSON/array.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
        'two_factor_secret',
        'three_factor_pin',
    ];

    /**
     * The attributes that should be cast.
     *
     * SEGURIDAD CRÍTICA:
     * - 'password' => 'hashed': Laravel hashea automáticamente al asignar.
     * - 'two_factor_secret' => 'encrypted': Cifrado AES-256-CBC en reposo
     *   usando la APP_KEY. Esto protege el secreto TOTP incluso si la BD
     *   es comprometida (siempre que APP_KEY se mantenga segura).
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
        'two_factor_secret' => 'encrypted',
    ];
}
