<?php

namespace Helium\LaravelHelpers\Contracts;

use ReflectionClass;

abstract class Enum
{
	/**
	 * @description Get all enum values
	 * @param bool $acceptNull Include null as an enum value
	 * @return array
	 */
	public static function all(bool $acceptNull = false): array
	{
		$reflector = new ReflectionClass(static::class);

		$all = array_values($reflector->getConstants());

		$all = array_filter($all, function ($value) {
			return is_string($value);
		});

		if ($acceptNull)
		{
			$all[] = null;
		}

		return $all;
	}
}