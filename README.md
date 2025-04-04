# Laravel JWT Authentication MVP with Role-based Redirection

This guide will help you build a simple Laravel application with JWT authentication and role-based redirection.

## Step 1: Create a new Laravel project

```bash
composer create-project laravel/laravel jwt-auth-app
cd jwt-auth-app
```

## Step 2: Install the JWT package

```bash
composer require tymon/jwt-auth
```

## Step 3: Publish the JWT config file

```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

## Step 4: Generate JWT secret key

```bash
php artisan jwt:secret
```

## Step 5: Configure the User model

Update `app/Models/User.php`:

```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    protected $fillable = [
        'name', 'email', 'password', 'role',
    ];

    protected $hidden = [
        'password', 'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
    ];

    // JWT required methods
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }

    // Helper methods for roles
    public function isAdmin()
    {
        return $this->role === 'admin';
    }

    public function isMember()
    {
        return $this->role === 'member';
    }
}
```

## Step 6: Update database migration for users table

Create a new migration to add the role column:

```bash
php artisan make:migration add_role_to_users_table --table=users
```

Edit the migration file in `database/migrations/xxxx_xx_xx_add_role_to_users_table.php`:

```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('role')->default('member');
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('role');
        });
    }
};
```

## Step 7: Configure auth.php

Update `config/auth.php`:

```php
<?php

return [
    'defaults' => [
        'guard' => 'api',
        'passwords' => 'users',
    ],

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],
    ],

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_reset_tokens',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],

    'password_timeout' => 10800,
];
```

## Step 8: Create AuthController

```bash
php artisan make:controller AuthController
```

Edit `app/Http/Controllers/AuthController.php`:

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'showLoginForm', 'showRegisterForm']]);
    }

    public function showLoginForm()
    {
        return view('auth.login');
    }

    public function showRegisterForm()
    {
        return view('auth.register');
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
            'role' => 'required|in:admin,member',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role' => $request->role,
        ]);

        $token = JWTAuth::fromUser($user);
        
        // Store token in cookie
        $cookie = cookie('jwt_token', $token, 60 * 24); // 24 hours
        
        // Redirect based on role
        if ($user->isAdmin()) {
            return redirect()->route('admin.dashboard')->withCookie($cookie);
        } else {
            return redirect()->route('member.dashboard')->withCookie($cookie);
        }
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = $request->only('email', 'password');

        if (!$token = auth()->attempt($credentials)) {
            return back()->withErrors([
                'email' => 'The provided credentials do not match our records.',
            ]);
        }

        // Store token in cookie
        $cookie = cookie('jwt_token', $token, 60 * 24); // 24 hours
        
        // Redirect based on role
        if (auth()->user()->isAdmin()) {
            return redirect()->route('admin.dashboard')->withCookie($cookie);
        } else {
            return redirect()->route('member.dashboard')->withCookie($cookie);
        }
    }

    public function logout()
    {
        auth()->logout();
        
        // Remove token cookie
        $cookie = cookie()->forget('jwt_token');
        
        return redirect()->route('login')->withCookie($cookie);
    }

    public function refresh()
    {
        $token = auth()->refresh();
        $cookie = cookie('jwt_token', $token, 60 * 24);
        
        return response()->json(['status' => 'success'])->withCookie($cookie);
    }
}
```

## Step 9: Create AdminController and MemberController

```bash
php artisan make:controller AdminController
php artisan make:controller MemberController
```

Edit `app/Http/Controllers/AdminController.php`:

```php
<?php

namespace App\Http\Controllers;

class AdminController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api');
        $this->middleware('role:admin');
    }

    public function dashboard()
    {
        return view('admin.dashboard');
    }
}
```

Edit `app/Http/Controllers/MemberController.php`:

```php
<?php

namespace App\Http\Controllers;

class MemberController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api');
        $this->middleware('role:member');
    }

    public function dashboard()
    {
        return view('member.dashboard');
    }
}
```

## Step 10: Create a role middleware

```bash
php artisan make:middleware CheckRole
```

Edit `app/Http/Middleware/CheckRole.php`:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CheckRole
{
    public function handle(Request $request, Closure $next, $role)
    {
        if ($role == 'admin' && !$request->user()->isAdmin()) {
            return redirect()->route('member.dashboard');
        }

        if ($role == 'member' && !$request->user()->isMember() && !$request->user()->isAdmin()) {
            return redirect()->route('login');
        }

        return $next($request);
    }
}
```

## Step 11: Create a JWT middleware

```bash
php artisan make:middleware JwtMiddleware
```

Edit `app/Http/Middleware/JwtMiddleware.php`:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JwtMiddleware
{
    public function handle($request, Closure $next)
    {
        try {
            $token = $request->cookie('jwt_token');
            if (!$token) {
                return redirect()->route('login');
            }
            
            JWTAuth::setToken($token);
            $user = JWTAuth::authenticate();
            
            if (!$user) {
                return redirect()->route('login');
            }
            
        } catch (TokenExpiredException $e) {
            return redirect()->route('login')->withErrors(['token' => 'Token expired']);
        } catch (TokenInvalidException $e) {
            return redirect()->route('login')->withErrors(['token' => 'Invalid token']);
        } catch (\Exception $e) {
            return redirect()->route('login')->withErrors(['token' => 'Token error']);
        }
        
        return $next($request);
    }
}
```

## Step 12: Register middlewares

Update `app/Http/Kernel.php`:

```php
protected $routeMiddleware = [
    // ... other middlewares
    'role' => \App\Http\Middleware\CheckRole::class,
    'jwt.verify' => \App\Http\Middleware\JwtMiddleware::class,
];
```

## Step 13: Create views

Create the login form at `resources/views/auth/login.blade.php`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Login</div>
                    <div class="card-body">
                        <form method="POST" action="{{ route('login') }}">
                            @csrf
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control @error('email') is-invalid @enderror" id="email" name="email" value="{{ old('email') }}" required>
                                @error('email')
                                    <div class="invalid-feedback">{{ $message }}</div>
                                @enderror
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control @error('password') is-invalid @enderror" id="password" name="password" required>
                                @error('password')
                                    <div class="invalid-feedback">{{ $message }}</div>
                                @enderror
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                            <a href="{{ route('register') }}" class="btn btn-link">Register</a>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

Create the register form at `resources/views/auth/register.blade.php`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Register</div>
                    <div class="card-body">
                        <form method="POST" action="{{ route('register') }}">
                            @csrf
                            <div class="mb-3">
                                <label for="name" class="form-label">Name</label>
                                <input type="text" class="form-control @error('name') is-invalid @enderror" id="name" name="name" value="{{ old('name') }}" required>
                                @error('name')
                                    <div class="invalid-feedback">{{ $message }}</div>
                                @enderror
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control @error('email') is-invalid @enderror" id="email" name="email" value="{{ old('email') }}" required>
                                @error('email')
                                    <div class="invalid-feedback">{{ $message }}</div>
                                @enderror
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control @error('password') is-invalid @enderror" id="password" name="password" required>
                                @error('password')
                                    <div class="invalid-feedback">{{ $message }}</div>
                                @enderror
                            </div>
                            <div class="mb-3">
                                <label for="password_confirmation" class="form-label">Confirm Password</label>
                                <input type="password" class="form-control" id="password_confirmation" name="password_confirmation" required>
                            </div>
                            <div class="mb-3">
                                <label for="role" class="form-label">Role</label>
                                <select class="form-select @error('role') is-invalid @enderror" id="role" name="role" required>
                                    <option value="member">Member</option>
                                    <option value="admin">Admin</option>
                                </select>
                                @error('role')
                                    <div class="invalid-feedback">{{ $message }}</div>
                                @enderror
                            </div>
                            <button type="submit" class="btn btn-primary">Register</button>
                            <a href="{{ route('login') }}" class="btn btn-link">Login</a>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

Create the admin dashboard at `resources/views/admin/dashboard.blade.php`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Admin Dashboard</h5>
                        <form method="POST" action="{{ route('logout') }}">
                            @csrf
                            <button type="submit" class="btn btn-danger btn-sm">Logout</button>
                        </form>
                    </div>
                    <div class="card-body">
                        <h2>Welcome, {{ auth()->user()->name }}</h2>
                        <p>You are logged in as an <strong>Admin</strong>.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

Create the member dashboard at `resources/views/member/dashboard.blade.php`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Member Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5>Member Dashboard</h5>
                        <form method="POST" action="{{ route('logout') }}">
                            @csrf
                            <button type="submit" class="btn btn-danger btn-sm">Logout</button>
                        </form>
                    </div>
                    <div class="card-body">
                        <h2>Welcome, {{ auth()->user()->name }}</h2>
                        <p>You are logged in as a <strong>Member</strong>.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
```

## Step 14: Define routes

Update `routes/web.php`:

```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\MemberController;

// Public routes
Route::get('/', function () {
    return redirect()->route('login');
});

Route::get('/login', [AuthController::class, 'showLoginForm'])->name('login');
Route::post('/login', [AuthController::class, 'login']);
Route::get('/register', [AuthController::class, 'showRegisterForm'])->name('register');
Route::post('/register', [AuthController::class, 'register']);

// Protected routes
Route::middleware(['jwt.verify'])->group(function () {
    Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
    
    // Admin routes
    Route::middleware(['role:admin'])->group(function () {
        Route::get('/admin/dashboard', [AdminController::class, 'dashboard'])->name('admin.dashboard');
    });
    
    // Member routes
    Route::middleware(['role:member'])->group(function () {
        Route::get('/member/dashboard', [MemberController::class, 'dashboard'])->name('member.dashboard');
    });
});
```

## Step 15: Run migrations and start the application

```bash
php artisan migrate
php artisan serve
```

That's it! Visit http://localhost:8000 to see your application in action.