<?php

namespace Helium\LaravelHelpers\Traits;

use Helium\LaravelHelpers\Helpers\StringHelper;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException as IlluminateValidationException;
use Helium\LaravelHelpers\Exceptions\ValidationException as HeliumValidationException;

trait HasPhoneNumbers
{
	public function getPhoneNumbers(): array
	{
		return $this->phoneNumbers ?? [
			'phone_number',
			'phone',
			'secondary_phone_number',
			'secondary_phone'
		];
	}

	public static function bootHasPhoneNumbers()
	{
		$model = new static;

		if (!method_exists(static::class, 'registerAttributeMutator'))
        {
            throw new \BadMethodCallException("The " . static::class . " class must use the trait " . HasAttributeEvents::class);
        }

		foreach ($model->getPhoneNumbers() as $attribute)
		{
			static::registerAttributeMutator($attribute, function ($value) use ($attribute) {
				return strval(Str::of($value)->replaceMatches('/[^0-9]/', ''));
			});
		}
	}
}