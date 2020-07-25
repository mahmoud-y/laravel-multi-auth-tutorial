Laravel provide authentication out of the box with many features and perks, in this tutorial we'll use it to implement multiple authentication system meaning having different type of users let's say admin or author.

What drove me to this approach is the attempt to extended laravel authentication to support multi auth without losing any functionality.

Blog will be the tutorial subject where we implement admin auth alongside the default user auth.

Tutorial code is available here [laravel-multi-auth-tutorial](https://github.com/mhmudyns/laravel-mutli-auth-tutorial)

Following are the steps that we'll go through

- [Initialization](#initialization)
- [Model and Migration](#model-and-migration)
- [Configuration](#configuration)
- [Service Provider](#service-provider)
- [Middlewares](#middlewares)
- [Controllers](#controllers)
- [Routing](#routing)
- [Views](#views)

# Initialization

Create a fresh laravel installation with authentication scaffolding included and configure [Database](https://laravel.com/docs/7.x/database#configuration) and [Mail](https://laravel.com/docs/7.x/mail#mail-and-local-development) in **.env**

```
laravel new blog --auth
```

Setup [Password Confirmation](https://laravel.com/docs/7.x/authentication#password-confirmation)

**routes/web.php**

* copy documentation demo [route](https://laravel.com/docs/7.x/authentication#password-confirmation) and register it as '/confirmed' and make it return 'password confirmed' string

    ```php
    Route::get('/confirmed', function () {
        return 'password confirmed';
    })->middleware(['auth', 'password.confirm']);
    ```

Setup [Email Verification](https://laravel.com/docs/7.x/verification)

**app/User.php**

* in `App\User` model implement `Illuminate\Contracts\Auth\MustVerifyEmail`

**routes/web.php**

* email verification routes are disabled by default we'll have to enable them, in `Auth::routes` method set the verify option to true

    ```php
    Auth::routes(['verify' => true]);
    ```

* copy documentation demo [route](https://laravel.com/docs/7.x/verification#protecting-routes) and register it as '/verified' and make it return 'email verified' string

    ```php
    Route::get('/verified', function () {
        return 'email verified';
    })->middleware('verified');
    ```

Setup [API Authentication](https://laravel.com/docs/6.x/api-authentication)

Note: this feature completes laravel authentication by providing simple api authentication which we think is missing but is actually there, it's available since 5.2 release but without documentation it was just mentioned in the authentication documentation, in 5.8 release luckily they decided to document it, in 7.x release for some reason the documentation is gone although the feature still exists (probably it has something to do with releasing [Sanctum Package](https://laravel.com/docs/7.x/sanctum) that offers similar [capabilities](https://laravel.com/docs/7.x/sanctum#api-token-authentication)).

**database/migrations/xxxx_xx_xx_xxxxxx_create_users_table.php**

* api authentication uses the token driver which require a column to store tokens by default this column is named api_token, in users migration add api_token column

    ```php
    Schema::create('users', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password');
        $table->string('api_token', 80)->unique()->nullable()->default(null);
        $table->rememberToken();
        $table->timestamps();
    });
    ```

**app/Http/Controllers/Auth/RegisterController.php**

* in `create` method assign random api token to user during registration

    ```php
    use Illuminate\Support\Str;

    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'api_token' => Str::random(80),
        ]);
    }
    ```

**app/User.php**

* because user registration logic use [mass assignment](https://laravel.com/docs/7.x/eloquent#mass-assignment) the previous step won't work unless we make api_token attribute mass assignable by adding it to `$fillable` property

    ```php
    protected $fillable = [
        'name', 'email', 'password', 'api_token'
    ];
    ```

# Model and Migration

Create admin model and it's corresponding migration
    
```
php artisan make:model -m Admin
```

**database/migrations/xxxx_xx_xx_xxxxxx_create_admins_table.php**

* we'll use user migration as a template for admin migration, copy user migration columns into admin migration

    ```php
    Schema::create('admins', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->timestamp('email_verified_at')->nullable();
        $table->string('password');
        $table->string('api_token', 80)->unique()->nullable()->default(null);
        $table->rememberToken();
        $table->timestamps();
    });
    ```

**app/Admin.php**

* we'll use user model as a template for admin model, replace admin model code with user model code and change the class name accordingly

    ```php
    <?php

    namespace App;

    use Illuminate\Contracts\Auth\MustVerifyEmail;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    use Illuminate\Notifications\Notifiable;

    class Admin extends Authenticatable implements MustVerifyEmail
    {
        use Notifiable;

        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password', 'api_token'
        ];

        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
            'password', 'remember_token',
        ];

        /**
         * The attributes that should be cast to native types.
         *
         * @var array
         */
        protected $casts = [
            'email_verified_at' => 'datetime',
        ];
    }

    ```

[Password Reset](https://laravel.com/docs/7.x/passwords)

`Admin` model extends `Authenticatable` an alias for `Illuminate\Foundation\Auth\User` which provide authentication functionalities, the latter use `Illuminate\Auth\Passwords\CanResetPassword` trait to include reset password necessary methods, this trait use `ResetPasswordNotification` an alias for `Illuminate\Auth\Notifications\ResetPassword` notification to send reset password email containing reset password link that expire after a period specified in user reset password configuration, we'll customize this notification to receive reset password url and configuration as parameters.

Create a new notification named `ResetPasswordNotification`

```
php artisan make:notification ResetPasswordNotification
```

**app/Notifications/ResetPasswordNotification.php**

* import and extend `Illuminate\Auth\Notifications\ResetPassword`

* remove `Illuminate\Bus\Queueable`, `Illuminate\Contracts\Queue\ShouldQueue`, `Illuminate\Notifications\Notification` imports

* remove `Queueable` trait

* remove `via`, `toMail`, `toArray` methods

* define `$resetPasswordRoute`, `$resetPasswordConfig` properties

    ```php
    class ResetPasswordNotification extends ResetPassword
    {
        public $resetPasswordRoute;

        public $resetPasswordConfig;

        // ...
    }
    ```

* in constructor define `$token` parent class property and nullable `$resetPasswordRoute`, `$resetPasswordConfig` parameters, call parent constructor, assign `$resetPasswordRoute`, `$resetPasswordConfig` parameters to corresponding properties

    ```php
    public function __construct($token, $resetPasswordRoute = null, $resetPasswordConfig = null)
    {
        parent::__construct($token);
        $this->resetPasswordRoute = $resetPasswordRoute;
        $this->resetPasswordConfig = $resetPasswordConfig;
    }
    ```

* override `Illuminate\Auth\NotificationsResetPassword` notification [toMail](https://github.com/laravel/framework/blob/54d097b56bc58253ba977b4e028755ca3d74392e/src/Illuminate/Auth/Notifications/ResetPassword.php#L60) method using same code, use `$resetPasswordRoute` property instead of 'password.reset' and `$resetPasswordConfig` property instead of `config('auth.defaults.passwords')` when properties are not null, import `Illuminate\Support\Facades\Lang`

    ```php
    use Illuminate\Support\Facades\Lang;
    
    public function toMail($notifiable)
    {
        if (static::$toMailCallback) {
            return call_user_func(static::$toMailCallback, $notifiable, $this->token);
        }

        if (static::$createUrlCallback) {
            $url = call_user_func(static::$createUrlCallback, $notifiable, $this->token);
        } else {
            $url = url(config('app.url').route($this->resetPasswordRoute ?: 'password.reset', [
                'token' => $this->token,
                'email' => $notifiable->getEmailForPasswordReset(),
            ], false));
        }

        return (new MailMessage)
            ->subject(Lang::get('Reset Password Notification'))
            ->line(Lang::get('You are receiving this email because we received a password reset request for your account.'))
            ->action(Lang::get('Reset Password'), $url)
            ->line(Lang::get('This password reset link will expire in :count minutes.', ['count' => config('auth.passwords.'.($this->resetPasswordConfig ?: config('auth.defaults.passwords')).'.expire')]))
            ->line(Lang::get('If you did not request a password reset, no further action is required.'));
    }
    ```

**app/Admin.php**

* override `Illuminate\Auth\Passwords\CanResetPassword` trait [sendPasswordResetNotification](https://github.com/laravel/framework/blob/54d097b56bc58253ba977b4e028755ca3d74392e/src/Illuminate/Auth/Passwords/CanResetPassword.php#L25) method using same code, in `ResetPasswordNotification` instantiation pass `$resetPasswordRoute` parameter as 'admin.password.reset' and `$resetPasswordConfig` parameter as 'admins' alongside `$token`, import `App\Notifications\ResetPasswordNotification`

    ```php
    use App\Notifications\ResetPasswordNotification;

    public function sendPasswordResetNotification($token)
    {
        $this->notify(new ResetPasswordNotification($token, 'admin.password.reset', 'admins'));
    }
    ```

[Email Verification](https://laravel.com/docs/7.x/verification)

Admin model extends `Authenticatable` an alias for `Illuminate\Foundation\Auth\User` which provide authentication functionalities, the latter use `Illuminate\Auth\MustVerifyEmail` trait to include email verification necessary methods, this trait use `Illuminate\Auth\Notifications\VerifyEmail` notification to send emails containing verification link, we'll customize this notification to receive email verification route as parameter instead of using staticly defined one.

create a new notification named `VerifyEmailNotification`

```
php artisan make:notification VerifyEmailNotification
```

**app/Notifications/VerifyEmailNotification.php**

* import and extend `Illuminate\Auth\Notifications\VerifyEmail`

* remove `Illuminate\Bus\Queueable`, `Illuminate\Contracts\Queue\ShouldQueue`, `Illuminate\Notifications\Messages\MailMessage`, `Illuminate\Notifications\Notification` imports

* remove `Queueable` trait

* remove `via`, `toMail`, `toArray` methods

* define `$verifyEmailRoute` property

    ```php
    class VerifyEmailNotification extends VerifyEmail
    {
        public $verifyEmailRoute;

        // ...
    }
    ```

* in constructor define nullable `$verifyEmailRoute` parameter, assign `$verifyEmailRoute` parameter to corresponding property

    ```php
    public function __construct($verifyEmailRoute)
    {
        $this->verifyEmailRoute = $verifyEmailRoute;
    }
    ```

* override `Illuminate\Auth\Notifications\VerifyEmail` notification [verificationUrl](https://github.com/laravel/framework/blob/54d097b56bc58253ba977b4e028755ca3d74392e/src/Illuminate/Auth/Notifications/VerifyEmail.php#L59) method using same code, use `$verifyEmailRoute` property instead of 'verification.verify' when property is not null, import `Illuminate\Support\Facades\URL`, `Illuminate\Support\Carbon`, `Illuminate\Support\Facades\Config`

    ```php
    use Illuminate\Support\Facades\URL;
    use Illuminate\Support\Carbon;
    use Illuminate\Support\Facades\Config;

    /**
     * Get the verification URL for the given notifiable.
     *
     * @param  mixed  $notifiable
     * @return string
     */
    protected function verificationUrl($notifiable)
    {
        return URL::temporarySignedRoute(
            $this->verifyEmailRoute ?: 'verification.verify',
            Carbon::now()->addMinutes(Config::get('auth.verification.expire', 60)),
            [
                'id' => $notifiable->getKey(),
                'hash' => sha1($notifiable->getEmailForVerification()),
            ]
        );
    }
    ```

**app/Admin.php**

* override `Illuminate\Auth\MustVerifyEmail` trait [sendEmailVerificationNotification](https://github.com/laravel/framework/blob/54d097b56bc58253ba977b4e028755ca3d74392e/src/Illuminate/Auth/MustVerifyEmail.php#L36) using same code, use `App\Notifications\VerifyEmailNotification` instead of `Illuminate\Auth\Notifications\VerifyEmail`, in instantiation pass `$verifyEmailRoute` parameter as 'admin.verification.verify', import `App\Notifications\VerifyEmailNotification`

    ```php
    use App\Notifications\VerifyEmailNotification;

    public function sendEmailVerificationNotification()
    {
        $this->notify(new VerifyEmailNotification('admin.verification.verify'));
    }
    ```

# Configuration

**config/auth.php**

* guards define how users are authenticated, define 'admin-web' / 'admin-api' guards by copying 'web' / 'api' guards and changing provider option to 'admins'

    ```php
    'guards' => [
        // ...

        'admin-web' => [
            'driver' => 'session',
            'provider' => 'admins',
        ],

        'admin-api' => [
            'driver' => 'token',
            'provider' => 'admins',
            'hash' => false,
        ],
    ],
    ```

* providers define how users are retrieved, define 'admins' provider by copying 'users' provider and changing model option to `App\Admin::class`

    ```php
    'providers' => [
        // ...

        'admins' => [
            'driver' => 'eloquent',
            'model' => App\Admin::class,
        ],
    ],
    ```

* passwords define users reset password configurations, define 'admins' reset password configuration by copying 'users' reset password configuration and changing provider option to 'admins'

    ```php
    'passwords' => [
        // ...

        'admins' => [
            'provider' => 'admins',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],
    ```

# Service Provider

Laravel defines user home url using `HOME` constant in `RouteServiceProvider` we'll do the same for admin

**app/Providers/RouteServiceProvider.php**

* define `ADMIN_HOME` const and set it to '/admin/home'

    ```php
    class RouteServiceProvider extends ServiceProvider
    {
        public const ADMIN_HOME = '/admin/home';

        // ...
    }
    ```
    
# Middlewares

`App\Http\Middleware\Authenticate=auth` middleware checks if user is authenticated before accessing protected routes if not user is redirected to login route, we'll have to customize redirection logic so that redirection is done based on specified guard

**app/Http/Middleware/Authenticate.php**

* `App\Http\Middleware\Authenticate=auth` extends `Illuminate\Auth\Middleware\Authenticate` which provide the functionality, we'll have to customize `unauthenticated` method to retreive request guard, override [unauthenticated](https://github.com/laravel/framework/blob/ce33b09cc7574427b4dd4709fce2213c406f2160/src/Illuminate/Auth/Middleware/Authenticate.php#L80) method using same code, in `AuthenticationException` instantiation pass `$guards` as a second parameter on `redirectTo` method, import `Illuminate\Auth\AuthenticationException`

    ```php
    use Illuminate\Auth\AuthenticationException;

    protected function unauthenticated($request, array $guards)
    {
        throw new AuthenticationException(
            'Unauthenticated.', $guards, $this->redirectTo($request, $guards)
        );
    }
    ```

* in `redirectTo` method add `$guards` parameter, redirect based on `$guards` to corresponding login route

    ```php
    protected function redirectTo($request, array $guards)
    {
        if (! $request->expectsJson()) {
            switch (current($guards)) {
                case 'admin-web':
                    return route('admin.login');
                
                default:
                    return route('login');
            }
        }
    }
    ```

`App\Http\Middleware\RedirectIfAuthenticated=guest` middleware checks if user is authenticated before accessing protected routes if so user is redirected to home route, we'll have to customize redirection logic so that redirection is done based on specified guard

**app/Http/Middleware/RedirectIfAuthenticated.php**

* redirect based on `$guard` to corresponding home route

    ```php
    public function handle($request, Closure $next, $guard = null)
    {
        if (Auth::guard($guard)->check()) {
            switch ($guard) {
                case 'admin-web':
                    return redirect(RouteServiceProvider::ADMIN_HOME);
                
                default:
                    return redirect(RouteServiceProvider::HOME);
            }
        }

        return $next($request);
    }
    ```

[Illuminate\Auth\Middleware\EnsureEmailIsVerified=verified](https://laravel.com/api/7.x/Illuminate/Auth/Middleware/EnsureEmailIsVerified.html) middleware checks if user email is verified before accessing protected routes, we'll have to customize it's logic to retrieve user using the specified guard

create a new middleware named EnsureEmailIsVerified
    
```
php artisan make:middleware EnsureEmailIsVerified
```

**app/Http/Middleware/EnsureEmailIsVerified.php**

* we'll use original middleware as a template for `App\Http\Middleware\EnsureEmailIsVerified` middleware, replace `App\Http\Middleware\EnsureEmailIsVerified` code with [Illuminate\Auth\Middleware\EnsureEmailIsVerified](https://github.com/laravel/framework/blob/3b267932d4666e56bf5fe74c6e735497d6fd6039/src/Illuminate/Auth/Middleware/EnsureEmailIsVerified.php#L19) code, add a new nullable parameter called `$guard`, in `$request->user` method occurrences set `$guard` parameter to the newly defined parameter

    ```php
    <?php

    namespace App\Http\Middleware;

    use Closure;
    use Illuminate\Contracts\Auth\MustVerifyEmail;
    use Illuminate\Support\Facades\Redirect;

    class EnsureEmailIsVerified
    {
        /**
         * Handle an incoming request.
         *
         * @param  \Illuminate\Http\Request  $request
         * @param  \Closure  $next
         * @param  string|null  $redirectToRoute
         * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
         */
        public function handle($request, Closure $next, $redirectToRoute = null, $guard = null)
        {
            if (! $request->user($guard) ||
                ($request->user($guard) instanceof MustVerifyEmail &&
                ! $request->user($guard)->hasVerifiedEmail())) {
                return $request->expectsJson()
                        ? abort(403, 'Your email address is not verified.')
                        : Redirect::route($redirectToRoute ?: 'verification.notice');
            }

            return $next($request);
        }
    }

    ```

**app/Http/Kernel.php**

* in `$routeMiddleware` property comment existing verified middleware registration and keep it as reference, register `App\Http\Middleware\EnsureEmailIsVerified` middleware as verified

    ```php
    protected $routeMiddleware = [
        'auth' => \App\Http\Middleware\Authenticate::class,
        'auth.basic' => \Illuminate\Auth\Middleware\AuthenticateWithBasicAuth::class,
        'bindings' => \Illuminate\Routing\Middleware\SubstituteBindings::class,
        'cache.headers' => \Illuminate\Http\Middleware\SetCacheHeaders::class,
        'can' => \Illuminate\Auth\Middleware\Authorize::class,
        'guest' => \App\Http\Middleware\RedirectIfAuthenticated::class,
        'password.confirm' => \Illuminate\Auth\Middleware\RequirePassword::class,
        'signed' => \Illuminate\Routing\Middleware\ValidateSignature::class,
        'throttle' => \Illuminate\Routing\Middleware\ThrottleRequests::class,
        // 'verified' => \Illuminate\Auth\Middleware\EnsureEmailIsVerified::class,
        'verified' => \App\Http\Middleware\EnsureEmailIsVerified::class,
    ];
    ```

# Controllers

Laravel ships with several pre-built authentication controllers which handles registration, authentication, resetting passwords and email verification, these controllers use traits to include their necessary methods, we'll create admin auth controllers by copying existing ones and making needed adjustments

Group admin controllers in a directory / namespace, create app/Http/Controllers/Admin directory / namespace

Create admin auth controllers, copy app/Http/Controllers/Auth directory as app/Http/Controllers/Admin/Auth

**app/Http/Controllers/Admin/Auth/RegisterController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* import `App\Admin` model instead of `App\User`

* set `$redirectTo` property to `RouteServiceProvider::ADMIN_HOME`

* in constructor specify 'admin-web' as the guard that `guest=App\Http\Middleware\RedirectIfAuthenticated` middleware should use

    ```php
    public function __construct()
    {
        $this->middleware('guest:admin-web');
    }
    ```

* in `validator` method set unique rule table parameter to 'admins'

    ```php
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:admins'],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
        ]);
    }
    ```

* in `create` method change `User` model to `Admin`

    ```php
    protected function create(array $data)
    {
        return Admin::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'api_token' => Str::random(80),
        ]);
    }
    ```

* `RegisterController` uses `Illuminate\Foundation\Auth\RegistersUsers` trait [showRegistrationForm](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/RegistersUsers.php#L19) method to show registration form, override this method using same code, change `view('auth.register')` to `view('admin.auth.register')`

    ```php
    public function showRegistrationForm()
    {
        return view('admin.auth.register');
    }
    ```

* `RegisterController` uses `Illuminate\Foundation\Auth\RegistersUsers` trait [guard](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/RegistersUsers.php#L52) method to get the guard to be used during registration, override this method using same code, in `Auth::guard` method pass guard parameter as 'admin-web', import `Illuminate\Support\Facades\Auth`

    ```php
    use Illuminate\Support\Facades\Auth;

    protected function guard()
    {
        return Auth::guard('admin-web');
    }
    ```

**app/Http/Controllers/Admin/Auth/LoginController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* set `$redirectTo` property to `RouteServiceProvider::ADMIN_HOME`

* in constructor specify 'admin-web' as the guard that `guest=App\Http\Middleware\RedirectIfAuthenticated` middleware should use

    ```php
    public function __construct()
    {
        $this->middleware('guest:admin-web');
    }
    ```

* `LoginController` uses `Illuminate\Foundation\Auth\AuthenticatesUsers` trait [showLoginForm](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/AuthenticatesUsers.php#L19) method to show login form, override this method using same code, change `view('auth.login')` to `view('admin.auth.login')`

    ```php
    public function showLoginForm()
    {
        return view('admin.auth.login');
    }
    ```

* `LoginController` uses `Illuminate\Foundation\Auth\AuthenticatesUsers` trait [logout](https://github.com/laravel/ui/blob/5b2c2ab062d07e788bf25a93ec13c499203b7a66/auth-backend/AuthenticatesUsers.php#L162) method to log the user out, this trait offer [loggedOut](https://github.com/laravel/ui/blob/5b2c2ab062d07e788bf25a93ec13c499203b7a66/auth-backend/AuthenticatesUsers.php#L185) method which allow customization of `logout` method response, override this method, use `logout` method [response](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/AuthenticatesUsers.php#L174) and change `redirect('/')` to `redirect('/admin')`, import `Illuminate\Http\Request`, `Illuminate\Http\Response`

    ```php
    use Illuminate\Http\Request;
    use Illuminate\Http\Response;

    protected function loggedOut(Request $request)
    {
        return $request->wantsJson()
            ? new Response('', 204)
            : redirect('/admin');
    }
    ```

* `LoginController` uses `Illuminate\Foundation\Auth\AuthenticatesUsers` trait [guard](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/AuthenticatesUsers.php#L195) method to get the guard to be used during authentication, override this method, in `Auth::guard` method pass guard parameter as 'admin-web', import `Illuminate\Support\Facades\Auth`

    ```php
    use Illuminate\Support\Facades\Auth;

    protected function guard()
    {
        return Auth::guard('admin-web');
    }
    ```

**app/Http/Controllers/Admin/Auth/VerificationController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* set `$redirectTo` property to `RouteServiceProvider::ADMIN_HOME`

* in constructor specify 'admin-web' as the guard that `auth=App\Http\Middleware\Authenticate` middleware should use

    ```php
    public function __construct()
    {
        $this->middleware('auth:admin-web');
        $this->middleware('signed')->only('verify');
        $this->middleware('throttle:6,1')->only('verify', 'resend');
    }
    ```

* `VerificationController` uses `Illuminate\Foundation\Auth\VerifiesEmails` trait [show](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/VerifiesEmails.php#L20) method to show email verification notice form, override this method using same code, in `$request->user` method pass guard parameter as 'admin-web', change `view('auth.verify')` to `view('admin.auth.verify')`, import `Illuminate\Http\Request`

    ```php
    use Illuminate\Http\Request;

    public function show(Request $request)
    {
        return $request->user('admin-web')->hasVerifiedEmail()
                        ? redirect($this->redirectPath())
                        : view('admin.auth.verify');
    }
    ```

**app/Http/Controllers/Admin/Auth/ConfirmPasswordController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* set `$redirectTo` property to `RouteServiceProvider::ADMIN_HOME`

* in constructor specify 'admin-web' as the guard that `auth=App\Http\Middleware\Authenticate` middleware should use

    ```php
    public function __construct()
    {
        $this->middleware('auth:admin-web');
    }
    ```

* `ConfirmPasswordController` uses `Illuminate\Foundation\Auth\ConfirmsPasswords` trait [showConfirmForm](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/ConfirmsPasswords.php#L17) method to show the password confirmation form, override this method using same code, change `view('auth.passwords.confirm')` to `view('admin.auth.passwords.confirm')`

    ```php
    public function showConfirmForm()
    {
        return view('admin.auth.passwords.confirm');
    }
    ```

**app/Http/Controllers/Admin/Auth/ForgotPasswordController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* `ForgotPasswordController` uses `Illuminate\Foundation\Auth\SendsPasswordResetEmails` trait [showLinkRequestForm](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/SendsPasswordResetEmails.php#L17) method to show the form to request a password reset link, override this method using same code, change `view('auth.passwords.email')` to `view('admin.auth.passwords.email')`

    ```php
    public function showLinkRequestForm()
    {
        return view('admin.auth.passwords.email');
    }
    ```

* `ForgotPasswordController` uses `Illuminate\Foundation\Auth\SendsPasswordResetEmails` trait [broker](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/SendsPasswordResetEmails.php#L105) method to get the broker to be used during password reset, override this method using same code, in `Password::broker` method pass broker parameter as 'admins', import `Illuminate\Support\Facades\Password`

    ```php
    public function broker()
    {
        return Password::broker('admins');
    }
    ```

**app/Http/Controllers/Admin/Auth/ResetPasswordController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* set `$redirectTo` property to `RouteServiceProvider::ADMIN_HOME`

* `ResetPasswordController` uses `Illuminate\Foundation\Auth\ResetsPasswords` trait [showResetForm](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/ResetsPasswords.php#L27) method to show the password reset form, override this method, change `view('auth.passwords.reset')` to `view('admin.auth.passwords.reset')`, import `Illuminate\Http\Request`

    ```php
    use Illuminate\Http\Request;

    public function showResetForm(Request $request, $token = null)
    {
        return view('admin.auth.passwords.reset')->with(
            ['token' => $token, 'email' => $request->email]
        );
    }
    ```

* `ResetPasswordController` uses `Illuminate\Foundation\Auth\ResetsPasswords` trait [broker](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/ResetsPasswords.php#L172) method to get the broker to be used during password reset, override this method, in `Password::broker` method pass broker parameter as 'admins', import `Illuminate\Support\Facades\Password`

    ```php
    use Illuminate\Support\Facades\Password;

    public function broker()
    {
        return Password::broker('admins');
    }
    ```

* `ResetPasswordController` uses `Illuminate\Foundation\Auth\ResetsPasswords` trait [guard](https://github.com/laravel/ui/blob/e2383b58d7950f273e9ebb4c0b5601bcbdfc7418/auth-backend/ResetsPasswords.php#L182) method to get the guard to be used during password reset, override this method, in `Auth::guard` method pass guard parameter as 'admin-web', import `Illuminate\Support\Facades\Auth`

    ```php
    use Illuminate\Support\Facades\Auth;

    protected function guard()
    {
        return Auth::guard('admin-web');
    }
    ```

Create admin home controller, copy app/Http/Controllers/HomeController.php as app/Http/Controllers/Admin/HomeController.php

**app/Http/Controllers/Admin/HomeController.php**

* change namespace to `App\Http\Controllers\Admin\Auth`

* import `App\Http\Controllers\Controller`

* in constructor specify 'admin-web' as the guard that `auth=App\Http\Middleware\Authenticate` middleware should use

    ```php
    public function __construct()
    {
        $this->middleware('auth:admin-web');
    }
    ```

* in `index` method change `view('home')` to `view('admin.home')`

    ```php
    public function index()
    {
        return view('admin.home');
    }
    ```

# Routing

**routes/web.php**

* register admin route group and set 'prefix' option to 'admin', 'namespace' option to 'Admin' and 'as' option to 'admin.'

    ```php
    Route::group(['prefix' => '/admin', 'namespace' => 'Admin', 'as' => 'admin.'], function () {
        // ...
    });
    ```
* copy user routes into admin group

* in '/' route change `view('welcome')` to `view('admin.welcome')`

    ```php
    Route::get('/', function () {
        return view('admin.welcome');
    });
    ```

* in '/confirmed' route pass auth middleware guard parameter as 'admin-web' and password.confirm middleware `$redirectToRoute` parameter as 'admin.password.confirm'

    ```php
    Route::get('/confirmed', function () {
        return 'password confirmed';
    })->middleware(['auth:admin-web', 'password.confirm:admin.password.confirm']);
    ```

* in '/verified' route pass verified middleware `$redirectToRoute` parameter as 'admin.verification.notice' and guard parameter as 'admin-web'

    ```php
    Route::get('/verified', function () {
        return 'email verified';
    })->middleware('verified:admin.verification.notice,admin-web');
    ```

Laravel ships with a user demo api route, we'll add one for admin

**routes/api.php**

* copy '/user' route and register it as '/admin', set auth middleware and `$request->user` method guard parameter to 'admin-api'

    ```php
    Route::middleware('auth:admin-api')->get('/admin', function (Request $request) {
        return $request->user('admin-api');
    });
    ```

# Views

Create a layout for admin, copy resources\views\layouts\app.blade.php as resources\views\layouts\admin.blade.php

**resources/views/layouts/admin.blade.php**

* change `url('/')` to `url('/admin')`
* pass `@guest` directive guard parameter as 'admin-web'
* add 'admin.' route name prefix to auth routes
* in `Auth::user` specify the guard that auth facade should use, chain `guard` method and pass guard parameter as 'admin-web'

    ```html
    {{ Auth::guard('admin-web')->user()->name }}
    ```

Group admin views in a directory, create resources/views/admin directory

Create admin welcome view, copy resources/views/welcome.blade.php as resources/views/admin/welcome.blade.php

**resources/views/admin/welcome.blade.php**

* add 'admin.' route name prefix to auth routes
* set `@auth` directive guard parameter to 'admin-web'
* change `url('/home')` to `url('/admin/home')`

Create admin auth views, copy resources/views/auth as resources/views/admin/auth

**resources/views/admin/auth/register.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`
* add 'admin.' route name prefix to auth routes

**resources/views/admin/auth/login.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`
* add 'admin.' route name prefix to auth routes

**resources/views/admin/auth/verify.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`
* add 'admin.' route name prefix to auth routes

**resources/views/admin/auth/passwords/confirm.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`
* add 'admin.' route name prefix to auth routes

**resources/views/admin/auth/passwords/email.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`
* add 'admin.' route name prefix to auth routes

**resources/views/admin/auth/passwords/reset.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`
* add 'admin.' route name prefix to auth routes

Create admin home view, copy resources\views\home.blade.php as resources\views\admin\home.blade.php

**resources\views\admin\home.blade.php**

* change `@extends('layouts.app')` to `@extends('layouts.admin')`

# Conclusion

Now that we've finished we should check that multi auth is working by trying available actions on user and admin. Finally i want to say that Laravel flexibility is what made this implementation that simple so the next time you look for something that's not available out of the box get the shovel and start digging