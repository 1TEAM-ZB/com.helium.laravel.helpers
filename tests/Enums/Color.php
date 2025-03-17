<?php

namespace Tests\Enums;

use Helium\LaravelHelpers\Contracts\Enum;

class Color extends Enum
{
	const RED = 'Red';
	const ORANGE = 'Orange';
	const YELLOW = 'Yellow';
	const GREEN = 'Green';
	const BLUE = 'Blue';
	const PURPLE = 'Purple';

	const PRIMARY = [
		self::RED,
		self::YELLOW,
		self::BLUE
	];
}