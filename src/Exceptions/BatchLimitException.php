<?php

namespace Helium\LaravelHelpers\Exceptions;

class BatchLimitException extends \RuntimeException
{
	public static function DATA_MB(int $actual, int $expected)
	{
		return new static("Batch action of $expected MB exceeded, got $actual MB");
	}

	public static function DATA_ROWS(int $actual, int $expected)
	{
		return new static("Batch action of $expected rows exceeded, got $actual rows");
	}
}