<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\BulkActions;
use Helium\LaravelHelpers\Traits\DefaultOrdering;
use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Helium\LaravelHelpers\Traits\HasFailedEvents;
use Tests\Models\Base\TestModel;

class HasFailedEventsModel extends TestModel
{
	use HasFailedEvents;

	protected $fillable = [
		'data'
	];

	public $createDidFail = false;
	public $updateDidFail = false;
	public $saveDidFail = false;

	protected static function boot()
	{
		parent::boot();

        static::createFailed(function (HasFailedEventsModel $model) {
            $model->createDidFail = true;
        });

        static::updateFailed(function (HasFailedEventsModel $model) {
            $model->updateDidFail = true;
        });

        static::saveFailed(function (HasFailedEventsModel $model) {
            $model->saveDidFail = true;
        });
	}
}