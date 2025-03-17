<?php

namespace Helium\LaravelHelpers\Rules;

use Illuminate\Contracts\Validation\Rule;

class PasswordSpecialCharacterRule extends PasswordMustContainRule
{
	protected $characters;

	public function __construct(int $minOccurrences = 1, string $characters = '!@#$%^&*(),.?":{}|<>')
	{
		$this->characters = $characters;
		parent::__construct("/[$characters]/", $minOccurrences);
	}

	public function message()
	{
		return trans('heliumHelpers::error.password.special', [
			'count' => $this->minOccurrences,
			'characters' => $this->characters
		]);
	}
}