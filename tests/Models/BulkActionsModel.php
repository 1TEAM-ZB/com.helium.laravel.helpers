<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Traits\BulkActions;
use Helium\LaravelHelpers\Traits\DefaultOrdering;
use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Tests\Models\Base\TestModel;

class BulkActionsModel extends TestModel
{
	use BulkActions;

	protected $fillable = [
		'data'
	];

	public $firedSaving = false;
	public $firedUpdating = false;
	public $firedCreating = false;
	public $firedSaved = false;
	public $firedUpdated = false;
	public $firedCreated = false;

	protected static function boot()
	{
		parent::boot();

		self::saving(function (BulkActionsModel $model) {
			$model->firedSaving = true;
		});

		self::updating(function (BulkActionsModel $model) {
			$model->firedUpdating = true;
		});

		self::creating(function (BulkActionsModel $model) {
			$model->firedCreating = true;
		});

		self::saved(function (BulkActionsModel $model) {
			$model->firedSaved = true;
		});

		self::updated(function (BulkActionsModel $model) {
			$model->firedUpdated = true;
		});

		self::created(function (BulkActionsModel $model) {
			$model->firedCreated = true;
		});
	}
}