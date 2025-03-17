<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\HasAttributeEvents;
use Tests\Models\Base\SetupHasAttributeEvents;
use Tests\Models\Base\TestModel;

class HasAttributeEventsModel extends TestModel
{
	use HasAttributeEvents;
	use SetupHasAttributeEvents;
}