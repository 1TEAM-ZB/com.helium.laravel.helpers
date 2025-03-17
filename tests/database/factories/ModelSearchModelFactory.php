<?php

use Faker\Generator as Faker;
use Tests\Models\ModelSearchModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(ModelSearchModel::class, function (Faker $faker) {
    return [
		'data' => $faker->words(3, true)
    ];
});
