<?php

namespace Helium\LaravelHelpers\Traits;

use Helium\LaravelHelpers\Contracts\Enum;
use Helium\LaravelHelpers\Exceptions\EnumException;
use Illuminate\Database\Eloquent\Model;

trait HasEnums
{
	//region Helpers
	/**
	 * @description Determines whether the specified attribute is an enum
	 * @param $key
	 * @return bool
	 */
	public function isEnum($key): bool
	{
		return array_key_exists($key, $this->getEnums());
	}

	/**
	 * @description Validates that the specified attribute value is in the allowed
	 * set of enum values
	 * @param $key
	 * @param $value
	 * @throws EnumException
	 */
	public function validateEnum($key, $value): void
	{
		if ($this->isEnum($key))
		{
			if (is_string($this->getEnums()[$key]) &&
				is_subclass_of($this->getEnums()[$key], Enum::class))
			{
				$enum = $this->getEnums()[$key];
				$array = $enum::all();
			}
			elseif (is_array($this->getEnums()[$key]))
			{
				$array = $this->getEnums()[$key];
			}

			if (!in_array($value, $array))
			{
				throw new EnumException($key, $value, $array);
			}
		}
	}
	//endregion

	//region Functions
	public function getEnums(): array
	{
		return property_exists($this, 'enums') ? $this->enums : [];
	}

	/**
	 * @description Register enum validation on setting attributes
	 */
	public static function bootHasEnums()
	{
        if (!method_exists(static::class, 'settingAttribute'))
        {
            throw new \BadMethodCallException("The " . static::class . " class must use the trait " . HasAttributeEvents::class);
        }

		self::settingAttribute(function(Model $model, $key, $value) {
			$model->validateEnum($key, $value);
		});
	}
	//endregion
}