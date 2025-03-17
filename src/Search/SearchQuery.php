<?php

namespace Helium\LaravelHelpers\Search;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;

class SearchQuery
{
    protected const FILTER_OPERATORS = [
        'lt' => '<',
        'lte' => '<=',
        'eq' => '=',
        'gte' => '>=',
        'gt' => '>',
        'like' => 'LIKE'
    ];

    /** @var Builder $builder */
    protected $builder;

    /** @var array $filters */
    protected $filters = [];

    /** @var array $orders */
    protected $orders = [];

    /** @var array $relations */
    protected $relations = [];

    /** @var ?array $allowedRelations */
    protected $allowedRelations = null;

    public function __construct(Builder $builder)
    {
        $this->builder = $builder;
    }

    public function filter(?array $filters = null): SearchQuery
    {
        if ($filters)
        {
            $this->filters = array_merge($this->filters, $filters);
        }

        return $this;
    }

    public function orderBy(?array $orders = null): SearchQuery
    {
        if ($orders)
        {
            $this->orders = array_merge($this->orders, $orders);
        }

        return $this;
    }

    public function load(?array $relations = null): SearchQuery
    {
        if ($relations)
        {
            $this->relations = array_merge($this->relations, $relations);
        }

        return $this;
    }

    public function allowRelations(?array $allowedRelations = null): SearchQuery
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

    public function paginate(?int $page = null, ?int $perPage = null,
         string $perPageName = 'per_page'): LengthAwarePaginator
    {
        foreach ($this->filters as $column => $columnFilters)
        {
            foreach ($columnFilters as $operator => $value)
            {
                $this->builder->where(
                    $column,
                    self::FILTER_OPERATORS[$operator],
                    $value
                );
            }
        }

        foreach ($this->orders as $column => $direction)
        {
            $this->builder->orderBy($column, $direction);
        }

        $relations = is_null($this->allowedRelations) ?
            $this->relations : array_intersect($this->relations, $this->allowedRelations);
        $this->builder->with($relations);

        $list = $this->builder->paginate(
            $perPage ?? 15,
            ['*'],
            'page',
            $page ?? 1
        );

        if ($perPage)
        {
            $list->appends($perPageName, $perPage);
        }

        return $list;
    }
}