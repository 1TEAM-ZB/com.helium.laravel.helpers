<?php

namespace Helium\LaravelHelpers\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;

trait FlexModel
{
    use HasFailedEvents;

    //region Base
    private $baseColumns;

    /**
     * @description Get the name of the column into which flex data is encoded
     * @return string
     */
    public function getFlexColumn(): string
    {
        return $this->flexColumn ?? 'data';
    }

    public static function bootFlexModel()
    {
        static::retrieved(function (Model $model) {
            $model->unpackFlexAttributes();
        });

        static::saving(function (Model $model) {
            $model->packFlexAttributes();
        });

        static::saved(function (Model $model) {
            $model->unpackFlexAttributes();
        });

        static::saveFailed(function (Model $model) {
            $model->unpackFlexAttributes();
        });
    }
    //endregion

    //region Helpers
    /**
     * @description Get table columns, except data
     * @return array
     */
    public function getBaseColumns(): array
    {
        if (!$this->baseColumns) {
            $columns = Schema::getColumnListing($this->getTable());

            $this->baseColumns = array_filter($columns, function ($value) {
                return $value != $this->getFlexColumn();
            });
        }

        return $this->baseColumns;
    }

    /**
     * @description Determines whether the specified key is a native table attribute
     * @param $key
     * @return bool
     */
    public function isBaseAttribute($key): bool
    {
        return in_array($key, $this->getBaseColumns());
    }

    /**
     * @description Determines whether the specified key is a flex attibute
     * @param $key
     * @return bool
     */
    public function isFlexAttribute($key): bool
    {
        return !$this->isBaseAttribute($key) && $key != $this->getFlexColumn();
    }

    /**
     * @description Given an array of attributes, filter out the ones which are
     * native table attributes
     * @param array $attributes
     * @return array
     */
    public function filterBaseAttributes(array $attributes = [])
    {
        return array_filter($attributes, function ($key) {
            return $this->isBaseAttribute($key);
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * @description Given an array of attributes, filter out the ones which are flex
     * attributes
     * @param array $attributes
     * @return array
     */
    public function filterFlexAttributes(array $attributes = [])
    {
        return array_filter($attributes, function ($key) {
            return $this->isFlexAttribute($key);
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * @description Get all base table attributes
     * @return array
     */
    public function getBaseAttributes()
    {
        return $this->filterBaseAttributes($this->getAttributes());
    }

    /**
     * @description Get all flex attributes
     * @return array
     */
    public function getFlexAttributes()
    {
        return $this->filterFlexAttributes($this->getAttributes());
    }

    /**
     * @description Get all attributes as they will be stored in the database
     * @return array
     */
    public function getTableAttributes()
    {
        $tableAttributes = $this->getBaseAttributes();
        $flexAttributes = $this->getFlexAttributes();

        $tableAttributes[$this->getFlexColumn()] = json_encode($flexAttributes);

        return $tableAttributes;
    }
    //endregion

    //region Flex Attributes
    public function unpackFlexAttributes()
    {
        if (isset($this->attributes[$this->getFlexColumn()]))
        {
            $json = $this->attributes[$this->getFlexColumn()];
            $flexData = is_array($json) ? $json : json_decode($json, true);

            unset($this->attributes[$this->getFlexColumn()]);
            $this->attributes = array_merge($this->attributes, $flexData);
        }
    }

    public function packFlexAttributes()
    {
        $flexData = $this->getFlexAttributes();
        $this->attributes[$this->getFlexColumn()] = json_encode($flexData);

        foreach (array_keys($flexData) as $key)
        {
            unset($this->attributes[$key]);
        }
    }
    //endregion
}