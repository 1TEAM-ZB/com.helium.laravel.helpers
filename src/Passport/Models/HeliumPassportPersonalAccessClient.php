<?php

namespace Helium\LaravelHelpers\Passport\Models;

use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Illuminate\Database\Eloquent\SoftDeletes;
use Laravel\Passport\PersonalAccessClient;

class HeliumPassportPersonalAccessClient extends PersonalAccessClient
{
    use GeneratesPrimaryKey;
    use SoftDeletes;

    public $primaryKeyPrefix = 'PP-PAC';
}