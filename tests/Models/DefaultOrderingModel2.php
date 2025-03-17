<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\DefaultOrdering;
use Tests\Models\Base\TestModel;

class DefaultOrderingModel2 extends TestModel
{
	use DefaultOrdering;

	protected $table = 'default_ordering_models';

	protected $defaultOrderings = [
		'created_at' => 'desc',
		'updated_at' => 'asc'
	];
}