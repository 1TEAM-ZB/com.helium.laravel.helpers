<?php

namespace Tests\database\seeds;

use Helium\LaravelHelpers\Database\Seeds\OneTimeSeeder;
use Illuminate\Support\Facades\DB;

class OneTimeTestSeeder extends OneTimeSeeder
{
    public function run()
    {
        DB::table('one_time_seed_data')->insert(['data' => 'abc']);
    }
}