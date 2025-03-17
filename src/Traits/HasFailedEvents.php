<?php

namespace Helium\LaravelHelpers\Traits;

use Illuminate\Database\Eloquent\Builder;

trait HasFailedEvents
{
    public static function saveFailed($callback)
    {
        static::registerModelEvent('saveFailed', $callback);
    }

    public static function createFailed($callback)
    {
        static::registerModelEvent('createFailed', $callback);
    }

    public static function updateFailed($callback)
    {
        static::registerModelEvent('updateFailed', $callback);
    }

    public function save(array $options = [])
    {
        try {
            return parent::save($options);
        } catch (\Throwable $t) {
            $this->fireModelEvent('saveFailed');

            throw $t;
        }
    }

    protected function performInsert(Builder $query)
    {
        try {
            return parent::performInsert($query);
        } catch (\Throwable $t) {
            $this->fireModelEvent('createFailed');

            throw $t;
        }
    }

    protected function performUpdate(Builder $query)
    {
        try {
            return parent::performUpdate($query);
        } catch (\Throwable $t) {
            $this->fireModelEvent('updateFailed');

            throw $t;
        }
    }
}