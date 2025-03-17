<?php

namespace Helium\LaravelHelpers\Traits;

trait FillableOnCreate
{
    public function getFillable()
    {
        $base = $this->fillable;

        if (isset($this->fillableOnCreate) && !$this->exists)
        {
            return array_merge($base, $this->fillableOnCreate);
        }

        return $base;
    }
}