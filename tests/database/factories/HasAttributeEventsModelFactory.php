<?php

use Faker\Generator as Faker;
use Illuminate\Support\Str;
use Tests\Models\HasAttributeEventsModel;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(HasAttributeEventsModel::class, function (Faker $faker) {
    return [
    	'string' => $faker->word,
	    'capital_string_internal' => $faker->name,
	    'lowercase_string_internal' => $faker->name,
	    'capital_string_external' => $faker->name,
	    'lowercase_string_external' => $faker->name,
	    'capital_string_both' => $faker->name,
	    'lowercase_string_both' => $faker->name,
    ];
});
