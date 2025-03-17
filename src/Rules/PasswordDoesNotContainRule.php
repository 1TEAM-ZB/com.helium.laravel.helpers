<?php

namespace Helium\LaravelHelpers\Rules;

use Illuminate\Contracts\Validation\Rule;

class PasswordDoesNotContainRule implements Rule
{
	protected $pattern;
	protected $convertSymbols;

	public function __construct(string $pattern, bool $convertSymbols = true)
	{
		$this->pattern = $convertSymbols ? $this->convertSymbols($pattern) : $pattern;
		$this->convertSymbols = $convertSymbols;
	}

	protected function convertSymbols(string $stringToConvert): string
	{
		$stringToConvert = strtolower($stringToConvert);

		$patterns = [
			'/[$5]/' => 's',
			'/[1!]/' => 'i',
			'/[@]/' => 'a',
			'/[7]/' => 't',
			'/[3]/' => 'e',
			'/[96]/' => 'g',
			'/[0]/' => 'o',
			'/[8]/' => 'b',
		];

		$stringToConvert = preg_replace(array_keys($patterns),
			array_values($patterns),
			$stringToConvert);

		return $stringToConvert;
	}

	public function passes($attribute, $value)
	{
		$value = $this->convertSymbols ? $this->convertSymbols($value) : $value;

		return strpos($value, $this->pattern) === false;
	}

	public function message()
	{
		return trans('heliumHelpers::error.password.not_contains', [
			'pattern' => $this->pattern
		]);
	}
}