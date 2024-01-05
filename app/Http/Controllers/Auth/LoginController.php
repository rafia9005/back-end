<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    public function index(){
        $title = "Halaman Login";
        return view('auth.login', compact('title'));
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (Auth::attempt($credentials)){
            return redirect('/dashboard');
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return redirect()->back()->withInput($request->only('email'))->withErrors(['email' => "Email tidak terdaftar"]);
        }

        return redirect()->back()->withInput($request->only('email'))->withErrors(['password' => "Password anda salah"]);
    }
}
