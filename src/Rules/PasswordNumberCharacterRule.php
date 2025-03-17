<?php

namespace Helium\LaravelHelpers\Rules;

use Illuminate\Contracts\Validation\Rule;

class PasswordNumberCharacterRule extends PasswordMustContainRule
{
	public function __construct(int $minOccurrences = 1)
	{
		parent::__construct('/[0-9]/', $minOccurrences);
	}

	public function message()
	{
		return trans('heliumHelpers::error.password.number', [
			'count' => $this->minOccurrences
		]);
	}
}