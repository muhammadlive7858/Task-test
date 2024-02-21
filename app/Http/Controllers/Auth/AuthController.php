<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use App\Http\Requests\RegisterRequest;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        // dd('test');
        $email = User::where('email',$request->email)->get();

        if($email){
            return response()_.json([
                'status'=>false,
                'message'=>'Such a user exists'
            ]);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        
        $token = $user->createToken('token-name')->plainTextToken;

        return response()->json([
            'status'=> true,
            'message' => 'User created successfully',
            'token' => $token
        ], 201);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json(['message' => 'The user does not exist'], 401);
        }

        $user = User::where('email', $request->email)->firstOrFail();
        $token = $user->createToken('token-name')->plainTextToken;

        return response()->json([
            'status'=> true,
            'token' => $token,
        ], 200);
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'Logged out'], 200);
    }
    public function refresh(Request $request)
    {
        $request->user()->tokens()->delete();

        $token = $request->user()->createToken('token-name')->plainTextToken;

        return response()->json(['token' => $token], 200);
    }
}
