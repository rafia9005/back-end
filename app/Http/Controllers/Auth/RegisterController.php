<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Validated;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class RegisterController extends Controller
{
    public function index()
    {
        $title = "Halaman register";
        return view('auth.register', compact('title'));
    }
    public function register(Request $request)
    {
        $request->validate([
            'username' => 'required|string|max:255|unique:users',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed'
        ]);
        if(User::where('username', $request->username)->exists()){
            return redirect()->back()->with('error', 'Username sudah ada');
        }
        if (User::where('email', $request->email)->exists()) {
            return redirect()->back()->with('error', 'Maaf, email Anda sudah terdaftar.');
        }
        if ($request->password !== $request->password_confirmation){
            return redirect()->back()->with('error', 'Password tidak sama');
        }
        if(strlen($request->password) < 8) {
            return redirect()->back()->with('error', 'Password minimal 8 huruf');
        }

        User::create([
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        return redirect('/login')->with('succes', 'Registrasi berhasil');
    }
}
