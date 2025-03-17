<?php

namespace Tests\Models\Base;

use Tests\Enums\Color;

trait SetupHasEnums
{
	protected $enums = [
		'favorite_color' => Color::class,
		'favorite_primary_color' => Color::PRIMARY
	];
}