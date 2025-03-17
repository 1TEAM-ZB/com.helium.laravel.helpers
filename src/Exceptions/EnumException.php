<?php

namespace Helium\LaravelHelpers\Exceptions;

use Illuminate\Validation\ValidationException as IlluminateValidationException;

class EnumException extends ApiException
{
	protected $key;
	protected $value;
	protected $enumValues;

	public function __construct(string $key, $value, array $enumValues)
	{
		$this->key = $key;
		$this->value = $value;
		$this->enumValues = $enumValues;

		parent::__construct("'$value' is not in the specified enum values for '$key'",
			400);
	}

	/**
	 * @description Get the array of allowed enum values
	 * @return array
	 */
	public function getEnumValues(): array
	{
		return $this->enumValues;
	}
}