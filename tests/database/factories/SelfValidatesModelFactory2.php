<?php

use Faker\Generator as Faker;
use Illuminate\Support\Str;
use Tests\Models\GeneratesPrimaryKeyModel;
use Tests\Models\SelfValidatesModel2;

/** @var \Illuminate\Database\Eloquent\Factory $factory */
$factory->define(SelfValidatesModel2::class, function (Faker $faker) {
    return [
    	'string' => $faker->word,
	    'int' => $faker->numberBetween(),
	    'bool' => $faker->boolean,
	    'foreign_key' => function (array $testSelfValidatesModel) {
    	    $model = factory(GeneratesPrimaryKeyModel::class)->create();
    	    return $model->getKey();
	    }
    ];
});
