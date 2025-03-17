<?php

namespace Helium\LaravelHelpers\Passport\Models;

use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Illuminate\Database\Eloquent\SoftDeletes;
use Laravel\Passport\Token;

class HeliumPassportRefreshToken extends Token
{
    use GeneratesPrimaryKey;
    use SoftDeletes;

    public $primaryKeyPrefix = 'PP-RTK';
}