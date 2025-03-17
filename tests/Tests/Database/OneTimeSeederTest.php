<?php

namespace Tests\Tests\Database;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Tests\database\seeds\OneTimeTestSeeder;
use Tests\TestCase;

class OneTimeSeederTest extends TestCase
{
    public function testSeedsOnce()
    {
        $seedClass = Str::of(OneTimeTestSeeder::class)->replace('\\', '\\\\')->__toString();

        $this->artisan("db:seed --class=$seedClass");

        $this->assertEquals(1, DB::table('one_time_seed_data')->count());

        $this->artisan("db:seed --class=$seedClass");

        $this->assertEquals(1, DB::table('one_time_seed_data')->count());
    }
}