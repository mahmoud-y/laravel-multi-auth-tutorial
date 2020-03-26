<?php

namespace App\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Lang;

class ResetPasswordNotification extends ResetPassword
{
    public $resetPasswordRoute;

    public $resetPasswordConfig;

    /**
     * Create a new notification instance.
     *
     * @return void
     */
    public function __construct($token, $resetPasswordRoute = null, $resetPasswordConfig = null)
    {
        parent::__construct($token);
        $this->resetPasswordRoute = $resetPasswordRoute;
        $this->resetPasswordConfig = $resetPasswordConfig;
    }

    /**
     * Build the mail representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return \Illuminate\Notifications\Messages\MailMessage
     */
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
}
