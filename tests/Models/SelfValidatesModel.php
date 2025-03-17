<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\SelfValidates;
use Tests\Models\Base\SetupSelfValidates;
use Tests\Models\Base\TestModel;

class SelfValidatesModel extends TestModel
{
	use SelfValidates;
	use SetupSelfValidates;

    public $hidden = [
        'foreign_key'
    ];
}