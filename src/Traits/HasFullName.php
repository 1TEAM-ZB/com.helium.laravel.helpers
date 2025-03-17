<?php

namespace Helium\LaravelHelpers\Traits;

use Helium\LaravelHelpers\Helpers\StringHelper;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException as IlluminateValidationException;
use Helium\LaravelHelpers\Exceptions\ValidationException as HeliumValidationException;

trait HasFullName
{
	public function getFirstName()
	{
		$firstNameAttribute = $this->firstNameAttribute ?? 'first_name';
		return $this->$firstNameAttribute ?? '';
	}

	public function getLastName()
	{
		$lastNameAttribute = $this->lastNameAttribute ?? 'last_name';
		return $this->$lastNameAttribute ?? '';
	}

	public function getFullNameAttribute()
	{
		return $this->getFirstName() . ' ' . $this->getLastName();
	}
}