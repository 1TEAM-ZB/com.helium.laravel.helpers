<?php

namespace Tests\Tests\Traits;

use Tests\Models\HasAdminsModel;
use Tests\TestCase;

class HasAdminsTest extends TestCase
{
	protected const TEST_CLASS = HasAdminsModel::class;

	protected function getInstance($args = [])
	{
		return factory(self::TEST_CLASS)->create($args);
	}

	public function testIsAdmin()
	{
		$model = $this->getInstance(['admin' => true]);

		$this->assertTrue($model->isAdmin());

		$model = $this->getInstance(['admin' => false]);

		$this->assertFalse($model->isAdmin());
	}
}