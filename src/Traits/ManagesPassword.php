<?php

namespace Helium\LaravelHelpers\Traits;

use Carbon\Carbon;
use Helium\LaravelHelpers\Contracts\PasswordNotifiable;
use Helium\LaravelHelpers\Rules\PasswordDoesNotContainRule;
use Helium\LaravelHelpers\Rules\PasswordLengthRule;
use Helium\LaravelHelpers\Rules\PasswordLowercaseCharacterRule;
use Helium\LaravelHelpers\Rules\PasswordSpecialCharacterRule;
use Helium\LaravelHelpers\Rules\PasswordUppercaseCharacterRule;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\UnauthorizedException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Validation\ValidationException as IlluminateValidationException;
use Helium\LaravelHelpers\Exceptions\ValidationException as HeliumValidationException;
use Ramsey\Uuid\Uuid;

trait ManagesPassword
{
	private static function getNotifiableModel(): string
	{
		$model = static::notifiableModel();

		if (!is_subclass_of($model, Model::class))
		{
			throw new \InvalidArgumentException(
				trans('heliumHelpers::error.password.model'),
				['class' => $model]
			);
		}
		if (!is_subclass_of($model, PasswordNotifiable::class))
		{
			throw new \InvalidArgumentException(
				trans('heliumHelpers::error.password.interface'),
				['class' => $model]
			);
		}

		return $model;
	}

	protected static function createPasswordResetToken($notifiable): string
	{
		$token = Uuid::uuid4()->getHex();

		DB::table('password_resets')->insert([
			'email' => $notifiable->email,
			'token' => $token,
			'created_at' => Carbon::now()
		]);

		return $token;
	}

	protected function passwordRules(): array
	{
		$rules = [
			new PasswordLengthRule(12),
			new PasswordUppercaseCharacterRule(),
			new PasswordLowercaseCharacterRule(),
			new PasswordSpecialCharacterRule(),
			new PasswordDoesNotContainRule('password')
		];

		if ($this->username) {
		    if (method_exists($this, 'validateAttribute')) {
		        $this->validateAttribute('username');
            }
			$rules[] = new PasswordDoesNotContainRule($this->username);
		}

		if ($this->email) {
            if (method_exists($this, 'validateAttribute')) {
                $this->validateAttribute('email');
            }
			$rules[] = new PasswordDoesNotContainRule($this->email);
		}

		return $rules;
	}

	public function validatePassword(string $password, string $password_confirm = null)
	{
		/**
		 * Check if the password is already hashed
		 * If it is, throw an InvalidArgumentException,
		 * since the Password validation rules will not function
		 * properly on pre-hashed values
		 */
		if (preg_match('/^\$2y\$.{56}$/', $password))
		{
			throw new \InvalidArgumentException(trans('password_manager:error.hashed'));
		}

		$attributes = ['password' => $password];
		$rules = ['password' => $this->passwordRules()];

		if ($password_confirm)
		{
			$attributes['password_confirmation'] = $password_confirm;
			$rules['password'][] = 'confirmed';
		}

		try {
            Validator::make($attributes, $rules)->validate();
        } catch (IlluminateValidationException $e) {
		    throw new HeliumValidationException($e);
        }
	}

	/**
	 * This function returns the class which should receive password-related
	 * notifications, and may be overwritten by classes which use this trait.
	 *
	 * This function should NOT be used in the functions which send notifications.
	 * Instead, use static::getNotifiableModel() (defined above) which first
	 * validates the requirements of the provided model class.
	 *
	 * @return string
	 */
	public static function notifiableModel(): string
	{
		return static::class;
	}

	public static function randomPassword(): string
	{
		return uniqid('He2@', true);
	}

	public static function forgotPassword(string $email)
	{
		$notifiable = static::getNotifiableModel()::where('email', $email)
			->firstOrFail();

		$token = static::createPasswordResetToken($notifiable);

		$notifiable->sendPasswordResetNotification($token);
	}

	public static function resetPassword(string $token,
		string $password, string $password_confirm)
	{
		$tokenObject = DB::table('password_resets')
			->where(['token' => $token])
			->first();

		if (!$tokenObject) {
			throw new UnauthorizedException('Reset Password Link Expired');
		}

		$user = static::getNotifiableModel()::where('email', $tokenObject->email)
			->firstOrFail();
		$user->updatePassword($password, $password_confirm);

		DB::table('password_resets')->where(['token' => $token])->delete();
	}

	public function setPasswordAttribute(string $password, string $password_confirm = null)
	{
        $this->validatePassword($password, $password_confirm);
		$this->attributes['password'] = Hash::make($password);
	}

	public function checkPassword(string $password): bool
	{
		return Hash::check($password, $this->password);
	}

	public function updatePassword(string $password,
		string $password_confirm, string $old_password = null)
	{
		if ($old_password && !$this->checkPassword($old_password))
		{
			throw new UnauthorizedException(trans('heliumHelpers::error.password.incorrect'));
		}

		$this->setPasswordAttribute($password, $password_confirm);
	}
}