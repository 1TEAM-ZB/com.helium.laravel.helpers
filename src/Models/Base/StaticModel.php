<?php

namespace Helium\LaravelHelpers\Models\Base;

use Illuminate\Database\Eloquent\Model;

class StaticModel extends Model
{
    public function fill(array $attributes)
    {
        return $this;
    }

    public function setAttribute($key, $value)
    {
        return $this;
    }

    public function save(array $options = [])
    {
        return false;
    }

    public function delete()
    {
        return false;
    }
}