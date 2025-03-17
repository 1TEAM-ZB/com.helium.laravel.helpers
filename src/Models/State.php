<?php

namespace Helium\LaravelHelpers\Models;

use Helium\LaravelHelpers\Models\Base\StaticModel;
use Illuminate\Database\Eloquent\Builder;

/**
 * State Model
 *
 * Properties
 * --------------------
 * @property int id
 * @property string name
 * @property string iso_3166_2
 * @property string abbreviation
 * @property string country_code
 *
 * Scopes
 * --------------------
 * @method static Builder US()
 */
class State extends StaticModel
{
    public function scopeUS(Builder $query)
    {
        return $query->where('country_code', 'US');
    }

    public function getAbbreviationAttribute()
    {
        return $this->iso_3166_2;
    }
}