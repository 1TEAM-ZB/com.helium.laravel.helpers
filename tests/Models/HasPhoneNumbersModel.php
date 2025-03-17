<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\HasAttributeEvents;
use Helium\LaravelHelpers\Traits\HasPhoneNumbers;
use Tests\Models\Base\TestModel;

class HasPhoneNumbersModel extends TestModel
{
    use HasAttributeEvents;
	use HasPhoneNumbers;

	public $phoneNumbers = null;
}