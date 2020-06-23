<?php

use Faker\Generator as Faker;
use Tests\TestModels\BulkActionsModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(BulkActionsModel::class, function (Faker $faker) {
    return [
		'data' => $faker->words(3, true)
    ];
});
