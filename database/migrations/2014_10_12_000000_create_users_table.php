<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');

            // ============================================================
            // COLUMNAS MFA (Multi-Factor Authentication)
            // ============================================================

            // Secreto TOTP para 2FA - se almacena cifrado en la BD
            // mediante el cast 'encrypted' en el modelo User.
            // Nullable porque los Invitados no requieren 2FA.
            $table->string('two_factor_secret')->nullable();

            // PIN de seguridad para 3FA - se almacena hasheado (bcrypt).
            // Se genera dinámicamente y se envía por correo electrónico.
            // Solo aplica al rol Admin.
            $table->string('three_factor_pin')->nullable();

            $table->rememberToken();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
