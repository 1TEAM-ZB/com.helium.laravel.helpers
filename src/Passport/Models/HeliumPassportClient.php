<?php

namespace Helium\LaravelHelpers\Passport\Models;

use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Illuminate\Database\Eloquent\SoftDeletes;
use Laravel\Passport\Client;

class HeliumPassportClient extends Client
{
    use GeneratesPrimaryKey;
    use SoftDeletes;

    public $primaryKeyPrefix = 'PP-CLI';

    public function skipsAuthorization()
    {
        return $this->firstParty();
    }
}