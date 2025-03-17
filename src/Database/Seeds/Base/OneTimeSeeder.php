<?php

namespace Helium\LaravelHelpers\Database\Seeds\Base;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class OneTimeSeeder extends Seeder
{
    public function __invoke()
    {
        $class = static::class;

        if (DB::table('one_time_seeds')->where('seeder', $class)->exists()) {
            println("$class already ran. Skipping.");
            return;
        }

        $returnValue = parent::__invoke();

        DB::table('one_time_seeds')->insert(['seeder' => $class]);

        return $returnValue;
    }
}