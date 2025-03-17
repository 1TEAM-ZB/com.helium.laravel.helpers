<?php

use Faker\Generator as Faker;
use Illuminate\Support\Str;
use Tests\Models\GeneratesPrimaryKeyModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(GeneratesPrimaryKeyModel::class, function (Faker $faker) {
    return [
    	'string' => $faker->word
    ];
});
