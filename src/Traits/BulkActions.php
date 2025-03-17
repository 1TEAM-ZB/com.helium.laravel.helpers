<?php

namespace Helium\LaravelHelpers\Traits;

use Helium\LaravelHelpers\Exceptions\BatchLimitException;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\ModelNotFoundException;

trait BulkActions
{
	//region Helpers
	protected static function getLimitDataMb()
	{
		return config('batch.limit.data_mb', 250);
	}

	protected static function getLimitDataRows()
	{
		return config('batch.limit.data_rows', 1000);
	}

	protected static function validateLimits(array $entries)
	{
		$data_mb = floatval(mb_strlen(serialize($entries))) / 1000000.0;
		$data_mb_limit = self::getLimitDataMb();
		if ($data_mb > $data_mb_limit)
		{
			throw BatchLimitException::DATA_MB($data_mb, $data_mb_limit);
		}

		$data_rows = count($entries);
		$data_rows_limit = self::getLimitDataRows();
		if ($data_rows > $data_rows_limit)
		{
			throw BatchLimitException::DATA_ROWS($data_rows, $data_rows_limit);
		}
	}
	//endregion

	//region ORM
	public function prepareToSave()
	{
		$this->mergeAttributesFromClassCasts();

		// If the "saving" event returns false we'll bail out of the save and return
		// false, indicating that the save failed. This provides a chance for any
		// listeners to cancel save operations if validations fail or whatever.
		if ($this->fireModelEvent('saving') === false) {
			return false;
		}

		if ($this->exists)
		{
			if ($this->isDirty() && $this->prepareToUpdate() === false)	{
				return false;
			}
		}
		else
		{
			if ($this->prepareToInsert() === false) {
				return false;
			}
		}

		return true;
	}

	public function executeSave(array $options = [])
	{
		$query = $this->newModelQuery();

		if ($this->exists)
		{
			$saved = $this->isDirty() ? $this->executeUpdate($query) : true;
		}
		else
		{
			$saved = $this->executeInsert($query);

			if (! $this->getConnectionName() &&
				$connection = $query->getConnection()) {
				$this->setConnection($connection->getName());
			}
		}

		// If the model is successfully saved, we need to do a few more things once
		// that is done. We will call the "saved" method here to run any actions
		// we need to happen after a model gets successfully saved right here.
		if ($saved) {
			$this->finishSave($options);
		}

		return $saved;
	}

	public function prepareToUpdate()
	{
		// If the updating event returns false, we will cancel the update operation so
		// developers can hook Validation systems into their models and cancel this
		// operation if the model does not pass validation. Otherwise, we update.
		if ($this->fireModelEvent('updating') === false) {
			return false;
		}
	}

	public function executeUpdate(Builder $query)
	{
		// First we need to create a fresh query instance and touch the creation and
		// update timestamp on the model which are maintained by us for developer
		// convenience. Then we will just continue saving the model instances.
		if ($this->usesTimestamps()) {
			$this->updateTimestamps();
		}

		// Once we have run the update operation, we will fire the "updated" event for
		// this model instance. This will allow developers to hook into these after
		// models are updated, giving them a chance to do any special processing.
		$dirty = $this->getDirty();

		if (count($dirty) > 0) {
			$this->setKeysForSaveQuery($query)->update($dirty);

			$this->syncChanges();

			$this->fireModelEvent('updated', false);
		}

		return true;
	}

	public function prepareToInsert()
	{
		if ($this->fireModelEvent('creating') === false) {
			return false;
		}
	}

	public function executeInsert(Builder $query)
	{
		// First we'll need to create a fresh query instance and touch the creation and
		// update timestamps on this model, which are maintained by us for developer
		// convenience. After, we will just continue saving these model instances.
		if ($this->usesTimestamps()) {
			$this->updateTimestamps();
		}

		// If the model has an incrementing key, we can use the "insertGetId" method on
		// the query builder, which will give us back the final inserted ID for this
		// table from the database. Not all tables have to be incrementing though.
		$attributes = $this->getAttributes();

		if ($this->getIncrementing()) {
			$this->insertAndSetId($query, $attributes);
		}

		// If the table isn't incrementing we'll simply insert these attributes as they
		// are. These attribute arrays must contain an "id" column previously placed
		// there by the developer as the manually determined key for these models.
		else {
			if (empty($attributes)) {
				return true;
			}

			$query->insert($attributes);
		}

		// We will go ahead and set the exists property to true, so that it is set when
		// the created event is fired, just in case the developer tries to update it
		// during the event. This will allow them to do so and run an update here.
		$this->exists = true;

		$this->wasRecentlyCreated = true;

		$this->fireModelEvent('created', false);

		return true;
	}
	//endregion

	//region Actions
	/**
	 * @param array $entries
	 * @return array|bool
	 */
	public static function batchCreate(array $entries)
	{
		self::validateLimits($entries);

		$models = [];

		/**
		 * Check each model by instantiating the instance and running the
		 * associated saving and creating events.
		 * This step is important to run pre-creation events such as validate, which
		 * may throw an exception. If an excepiton is to be thrown, it should be
		 * thrown now during this check step, rather than during the actual insert
		 * loop.
		 */
		foreach ($entries as $entry)
		{
			/** @var static $model */
			$model = static::make($entry);

			if ($model->prepareToSave() === false)
			{
				return false;
			}

			$models[] = $model;
		}

		/** @var static $model */
		foreach ($models as $model)
		{
			$saved = $model->executeSave();
		}

		return $models;
	}

	/**
	 * @param array $entries
	 * @return array|bool
	 */
	public static function bulkUpdate(array $entries)
	{
		self::validateLimits($entries);

		$models = [];

		$keyField = (new static)->getKeyName();

		foreach ($entries as $entry)
		{
			/** @var static $model */
			if (isset($entry[$keyField]) && $model = static::find($entry[$keyField]))
			{
				$model->fill($entry);

				if ($model->prepareToSave() === false)
				{
					return false;
				}

				$models[] = $model;
			}
			else
			{
				throw (new ModelNotFoundException())->setModel(static::class, [$entry[$keyField]]);
			}
		}

		/** @var static $model */
		foreach ($models as $model)
		{
			$saved = $model->executeSave();
		}

		return $models;
	}

	/**
	 * @param array $entries
	 * @return array|bool
	 */
	public static function bulkCreateOrUpdate(array $entries)
	{
		self::validateLimits($entries);

		$models = [];

		$keyField = (new static)->getKeyName();

		foreach ($entries as $entry)
		{
			/** @var static $model */
			if (isset($entry[$keyField]) && $model = static::find($entry[$keyField]))
			{
				$model->fill($entry);
				$model->prepareToSave();

				$models[] = $model;
			}
			else
			{
				$model = static::make($entry);
			}

			if ($model->prepareToSave() === false)
			{
				return false;
			}

			$models[] = $model;
		}

		/** @var static $model */
		foreach ($models as $model)
		{
			$saved = $model->executeSave();
		}

		return $models;
	}
	//endregion
}