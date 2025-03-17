<?php

namespace Helium\LaravelHelpers\Traits;

use Helium\LaravelHelpers\Search\SearchQuery;
use Illuminate\Database\Eloquent\Builder;

trait ModelSearch
{
    /** @var array $allowedRelations */
    protected $allowedRelations = null;

    public static function search(?Builder $query = null): SearchQuery
    {
        return (new SearchQuery($query ?? static::query()));
    }

    public function allowRelations(?array $allowedRelations = null)
    {
        if (is_null($this->allowedRelations))
        {
            $this->allowedRelations = [];
        }

        if ($allowedRelations)
        {
            $this->allowedRelations = array_merge($this->allowedRelations, $allowedRelations);
        }

        return $this;
    }

    public function load($relations)
    {
        if (is_string($relations) &&
            (is_null($this->allowedRelations) || in_array($relations, $this->allowedRelations)))
        {
            return parent::load($relations);
        }

        if(is_array($relations))
        {
            $allowedRelations = is_null($this->allowedRelations) ?
                $relations :
                array_intersect($this->allowedRelations, $relations);
            return parent::load($allowedRelations);
        }

        return $this;
    }
}