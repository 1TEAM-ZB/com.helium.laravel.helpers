<?php

use Faker\Generator as Faker;
use Illuminate\Support\Str;
use Tests\Models\HasFullNameModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(HasFullNameModel::class, function (Faker $faker) {
    return [
    	'first_name' => $faker->firstName,
	    'last_name' => $faker->lastName,
	    'first_name_custom' => $faker->firstName,
	    'last_name_custom' => $faker->lastName
    ];
});
