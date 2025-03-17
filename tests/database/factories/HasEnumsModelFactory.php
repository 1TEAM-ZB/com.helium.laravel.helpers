<?php

use Faker\Generator as Faker;
use Illuminate\Support\Str;
use Tests\Enums\Color;
use Tests\Models\HasEnumsModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(HasEnumsModel::class, function (Faker $faker) {
    return [
		'favorite_color' => $faker->randomElement(Color::all()),
	    'favorite_primary_color' => $faker->randomElement(Color::PRIMARY)
    ];
});
