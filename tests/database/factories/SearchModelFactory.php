<?php

use Faker\Generator as Faker;
use Tests\TestModels\SearchModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(SearchModel::class, function (Faker $faker) {
    return [
    	'age' => $faker->numberBetween(0, 85)
    ];
});
