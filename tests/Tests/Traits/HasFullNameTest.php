<?php

namespace Tests\Tests\Traits;

use Tests\Models\HasFullNameModel;
use Tests\TestCase;

class HasFullNameTest extends TestCase
{
	protected const TEST_CLASS = HasFullNameModel::class;

	protected const FIRST_NAME_DEFAULT = 'George';
	protected const LAST_NAME_DEFAULT = 'Burdell';
	protected const FIRST_NAME_CUSTOM_DEFAULT = 'Johnny';
	protected const LAST_NAME_CUSTOM_DEFAULT = 'Appleseed';

	protected function getInstance($args = [])
	{
		return factory(self::TEST_CLASS)->create([
			'first_name' => self::FIRST_NAME_DEFAULT,
			'last_name' => self::LAST_NAME_DEFAULT,
			'first_name_custom' => self::FIRST_NAME_CUSTOM_DEFAULT,
			'last_name_custom' => self::LAST_NAME_CUSTOM_DEFAULT
		]);
	}

	public function testGetFirstName()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->getFirstName(), self::FIRST_NAME_DEFAULT);

		$model->firstNameAttribute = 'first_name_custom';

		$this->assertEquals($model->getFirstName(), self::FIRST_NAME_CUSTOM_DEFAULT);
	}

	public function testGetLastName()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->getLastName(), self::LAST_NAME_DEFAULT);

		$model->lastNameAttribute = 'last_name_custom';

		$this->assertEquals($model->getLastName(), self::LAST_NAME_CUSTOM_DEFAULT);
	}

	public function testGetFullName()
	{
		$model = $this->getInstance();

		$expectedFullName = self::FIRST_NAME_DEFAULT . ' ' . self::LAST_NAME_DEFAULT;

		$this->assertEquals($model->getFullNameAttribute(), $expectedFullName);

		$this->assertEquals($model->fullName, $expectedFullName);

		$this->assertEquals($model->full_name, $expectedFullName);
	}
}