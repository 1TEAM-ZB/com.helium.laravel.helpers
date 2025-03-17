<?php

namespace Tests\Tests\Traits;

use Tests\Models\GeneratesPrimaryKeyModel;
use Tests\TestCase;

class GeneratesPrimaryKeyTest extends TestCase
{
	protected const TEST_CLASS = GeneratesPrimaryKeyModel::class;

	protected function getInstance()
	{
		return factory(self::TEST_CLASS)->create([
			'id' => null
		]);
	}

	public function testCreate()
	{
		$model = $this->getInstance();

		$this->assertIsString($model->getKey());
		$this->assertRegExp("/^{$model->primaryKeyPrefix}-[a-f0-9]{32}$/", $model->getKey());
	}

	public function testCreateIdAlreadySet()
	{
		$model = factory(self::TEST_CLASS)->create([
			'id' => 'abc123'
		]);

		$this->assertEquals('abc123', $model->id);
	}

	public function testUpdate()
	{
		/**
		 * Test that update does not re-generate/change the primary key
		 */
		$model = $this->getInstance();

		$key = $model->getKey();

		$model->update([
			'string' => 'lorem ipsum'
		]);

		$this->assertEquals($key, $model->getKey());
	}
}