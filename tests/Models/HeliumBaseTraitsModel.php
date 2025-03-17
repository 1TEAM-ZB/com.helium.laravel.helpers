<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\HeliumBaseTraits;
use Tests\Models\Base\SetupGeneratesPrimaryKey;
use Tests\Models\Base\SetupHasAttributeEvents;
use Tests\Models\Base\SetupHasEnums;
use Tests\Models\Base\SetupSelfValidates;
use Tests\Models\Base\TestModel;

class HeliumBaseTraitsModel extends TestModel
{
	use HeliumBaseTraits;
	use SetupGeneratesPrimaryKey;
	use SetupHasAttributeEvents;
	use SetupHasEnums;
	use SetupSelfValidates;
}