<?php

namespace Helium\LaravelHelpers\Rules;

use Illuminate\Contracts\Validation\Rule;

class PasswordLowercaseCharacterRule extends PasswordMustContainRule
{
	public function __construct(int $minOccurrences = 1)
	{
		parent::__construct('/[a-z]/', $minOccurrences);
	}

	public function message()
	{
		return trans('heliumHelpers::error.password.lowercase', [
			'count' => $this->minOccurrences
		]);
	}
}