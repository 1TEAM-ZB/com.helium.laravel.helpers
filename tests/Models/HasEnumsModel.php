<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\HasAttributeEvents;
use Helium\LaravelHelpers\Traits\HasEnums;
use Tests\Models\Base\SetupHasEnums;
use Tests\Models\Base\TestModel;

class HasEnumsModel extends TestModel
{
    use HasAttributeEvents;
	use HasEnums;
	use SetupHasEnums;
}