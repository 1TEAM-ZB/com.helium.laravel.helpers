<?php

namespace Tests\Tests\Traits;

use Helium\LaravelHelpers\Generators\UuidPrimaryKeyGenerator;
use Helium\LaravelHelpers\Contracts\IdGenerator;
use Tests\Models\GeneratesPrimaryKeyModel;
use Tests\TestCase;

class UuidPrimaryKeyGeneratorTest extends PrimaryKeyGeneratorTest
{
	protected function getInstance(): IdGenerator
	{
		$model = new GeneratesPrimaryKeyModel();
		return new UuidPrimaryKeyGenerator($model);
	}

	public function testGenerateFormat()
	{
		$model = new GeneratesPrimaryKeyModel();
		$generator = new UuidPrimaryKeyGenerator($model);

		$this->assertRegExp("/^{$model->primaryKeyPrefix}-[a-f0-9]{32}$/", $generator->generate());
	}
}