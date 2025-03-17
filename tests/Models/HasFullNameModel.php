<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\HasFullName;
use Tests\Models\Base\TestModel;

class HasFullNameModel extends TestModel
{
	use HasFullName;

	public $firstNameAttribute = null;
	public $lastNameAttribute = null;
}