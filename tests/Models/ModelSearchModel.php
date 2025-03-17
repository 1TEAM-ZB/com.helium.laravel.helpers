<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\ModelSearch;
use Tests\Models\Base\TestModel;

class ModelSearchModel extends TestModel
{
	use ModelSearch;

	protected $fillable = [
		'data',
        'parent_id'
	];

	public function parent()
    {
        return $this->belongsTo(ModelSearchModel::class, 'parent_id');
    }
}