<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            "username" => 'required|string|max:255|unique:users',
            "email" => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8'
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = new User();
        $user->username = $request->username;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->role = 'user';

        $user->save();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'data' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            "email" => 'required|string',
            'password' => 'required|string|min:8'
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $credentials = $request->only('email', 'password');

        if (!Auth::attempt($credentials)) {
            $user = User::where('email', $request['email'])->first();

            if (!$user) {
                return response()->json(['message' => 'Email not found'], 401);
            }

            return response()->json(['message' => 'Incorrect password'], 401);
        }

        $user = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json(['message' => 'Hi ' . $user->username . ', welcome to home', 'access_token' => $token]);
    }
}
