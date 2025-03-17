<?php

use Faker\Generator as Faker;
use Illuminate\Support\Str;
use Tests\Enums\Color;
use Tests\Models\GeneratesPrimaryKeyModel;
use Tests\Models\HeliumBaseTraitsModel2;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(HeliumBaseTraitsModel2::class, function (Faker $faker) {
    return [
	    'favorite_color' => $faker->randomElement(Color::all()),
	    'favorite_primary_color' => $faker->randomElement(Color::PRIMARY),
	    'string' => $faker->word,
	    'int' => $faker->numberBetween(),
	    'bool' => $faker->boolean,
	    'foreign_key' => function (array $testSelfValidatesModel) {
		    $model = factory(GeneratesPrimaryKeyModel::class)->create();
		    return $model->getKey();
	    },
	    'capital_string_internal' => $faker->name,
	    'lowercase_string_internal' => $faker->name,
	    'capital_string_external' => $faker->name,
	    'lowercase_string_external' => $faker->name,
	    'capital_string_both' => $faker->name,
	    'lowercase_string_both' => $faker->name,
    ];
});
