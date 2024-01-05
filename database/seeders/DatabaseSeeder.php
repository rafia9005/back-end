<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        User::create([
            'username' => "rafia9005",
            'email' => "rafia9005@gmail.com",
            'password' => bcrypt('ahmadrafi01'),
            'role' => 'admin',
        ]);
    }
}
