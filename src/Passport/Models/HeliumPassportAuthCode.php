<?php

namespace Helium\LaravelHelpers\Passport\Models;

use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Illuminate\Database\Eloquent\SoftDeletes;
use Laravel\Passport\AuthCode;

class HeliumPassportAuthCode extends AuthCode
{
    use GeneratesPrimaryKey;
    use SoftDeletes;

    public $primaryKeyPrefix = 'PP-ACD';
}