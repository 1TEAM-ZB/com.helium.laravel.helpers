<?php

namespace Tests\Tests\Traits;

use Helium\LaravelHelpers\Generators\UuidPrimaryKeyGenerator;
use Helium\LaravelHelpers\Contracts\IdGenerator;
use Tests\Models\GeneratesPrimaryKeyModel;
use Tests\TestCase;

abstract class PrimaryKeyGeneratorTest extends TestCase
{
	protected abstract function getInstance(): IdGenerator;

	public function testGenerateUnique()
	{
		$generator = $this->getInstance();

		$keys = [];

		//Generate 10,000 keys, ensure they are all unique
		for ($i = 0; $i < 10000; $i++)
		{
			$newKey = $generator->generate();

			$this->assertNotContains($newKey, $keys);

			$keys[] = $newKey;
		}
	}
}