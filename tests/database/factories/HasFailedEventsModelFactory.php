<?php

use Faker\Generator as Faker;
use Tests\Models\HasFailedEventsModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(HasFailedEventsModel::class, function (Faker $faker) {
    return [
		'data' => $faker->words(3, true)
    ];
});
