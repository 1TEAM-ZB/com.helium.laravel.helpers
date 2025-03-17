<?php

namespace Helium\LaravelHelpers\Helpers;

use Ramsey\Uuid\Uuid;

class StringHelper
{
	/**
	 * @description Returns a random token of specified length using a specified
	 * charset
	 * @param array $charSet
	 * @param int $length
	 * @return string
	 */
	public static function randomToken(array $charSet, int $length)
	{
		shuffle($charSet);

		$output = '';

		for ($i = 0; $i < $length; $i++) {
			$output .= $charSet[rand(0, count($charSet) - 1)];
		}

		return $output;
	}

	/**
	 * @description Returns Random numerical token of specified length.
	 * @param int $length
	 * @return null|string|string[]
	 */
	public static function randomNumericalToken (int $length) {

		$numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

		return self::randomToken($numbers, $length);
	}

	/**
	 * @description Returns Random alpha numerical token of specified length.
	 * @param $length
	 * @return null|string
	 * @throws \Exception
	 */
	public static function randomAlphaNumericalToken (int $length) {
		$numbers = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'a', 'b', 'c', 'd', 'e', 'f'];

		return self::randomToken($numbers, $length);
	}

	/**
	 * @description Returns a randomly generated UUID string
	 * @param bool $dashes Return the UUID with or without dashes
	 * @return string
	 */
	public static function uuid(bool $dashes = true) {
		$uuid = Uuid::uuid4();

		if (!$dashes) {
			return $uuid->getHex();
		} else {
			return $uuid->toString();
		}
	}

	/**
	 * @description Returns Only Alpha Numeric Chars from String.
	 * @param $number
	 * @return null|string|string[]
	 */
	public static function onlyAlphaNumeric ($string) {
		return preg_replace('/[^a-zA-Z0-9]/', '', $string);
	}

	/**
	 * @description Returns Only Numeric Chars from String.
	 * @param $number
	 * @return null|string|string[]
	 */
	public static function onlyNumeric ($number) {
		return preg_replace('/[^0-9.]/', '', $number);
	}
}