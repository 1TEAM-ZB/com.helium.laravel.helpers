<?php

namespace Tests\Tests\Traits;

use Tests\Models\HasAttributeEventsModel;
use Tests\TestCase;

class HasAttributeEventsTest extends TestCase
{
	protected const TEST_CLASS = HasAttributeEventsModel::class;

	protected function getInstance()
	{
		return factory(self::TEST_CLASS)->create();
	}

	public function testSettingAttribute()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->_settingAttributeCalled);
		$this->assertNull($model->_settingAttributeKey);
		$this->assertNull($model->_settingAttributeValue);

		$string = 'lorem ipsum';
		$model->string = $string;

		$this->assertTrue($model->_settingAttributeCalled);
		$this->assertEquals($model->_settingAttributeKey, 'string');
		$this->assertEquals($model->_settingAttributeValue, $string);
		$this->assertFalse($model->_gettingAttributeCalled);
	}

	public function testDidSetAttribute()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->_didSetAttributeCalled);
		$this->assertNull($model->_didSetAttributeKey);
		$this->assertNull($model->_didSetAttributeValue);

		$string = 'lorem ipsum';
		$model->string = $string;

		$this->assertTrue($model->_didSetAttributeCalled);
		$this->assertEquals($model->_didSetAttributeKey, 'string');
		$this->assertEquals($model->_didSetAttributeValue, $string);
		$this->assertFalse($model->_didGetAttributeCalled);
	}

	public function testGettingAttribute()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->_gettingAttributeCalled);
		$this->assertNull($model->_gettingAttributeKey);

		$string = $model->string;

		$this->assertTrue($model->_gettingAttributeCalled);
		$this->assertEquals($model->_gettingAttributeKey, 'string');
		$this->assertFalse($model->_settingAttributeCalled);
	}

	public function testDidGetAttribute()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->_didGetAttributeCalled);
		$this->assertNull($model->_didGetAttributeKey);

		$string = $model->string;

		$this->assertTrue($model->_didGetAttributeCalled);
		$this->assertEquals($model->_didGetAttributeKey, 'string');
		$this->assertFalse($model->_didSetAttributeCalled);
	}

	public function testHasExternallyRegisteredMutator()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->hasExternallyRegisteredMutator('capital_string_internal'));
		$this->assertTrue($model->hasExternallyRegisteredMutator('capital_string_external'));
		$this->assertTrue($model->hasExternallyRegisteredMutator('capital_string_both'));
	}

	public function testHasSetMutator()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->hasSetMutator('id'));
		$this->assertTrue($model->hasSetMutator('capital_string_internal'));
		$this->assertTrue($model->hasSetMutator('capital_string_external'));
		$this->assertTrue($model->hasSetMutator('capital_string_both'));
	}

	public function testHasExternallyRegisteredAccessor()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->hasExternallyRegisteredAccessor('lowercase_string_internal'));
		$this->assertTrue($model->hasExternallyRegisteredAccessor('lowercase_string_external'));
		$this->assertTrue($model->hasExternallyRegisteredAccessor('lowercase_string_both'));
	}

	public function testHasGetMutator()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->hasGetMutator('id'));
		$this->assertTrue($model->hasGetMutator('lowercase_string_internal'));
		$this->assertTrue($model->hasGetMutator('lowercase_string_external'));
		$this->assertTrue($model->hasGetMutator('lowercase_string_both'));
	}

	public function testRegisterAttributeMutator()
	{
		$model = $this->getInstance();

		$model->capital_string_external = 'abc';
		$model->capital_string_internal = 'abc';
		$model->capital_string_both = 'abc';

		$attributes = $model->getAttributes();

		$this->assertEquals($attributes['capital_string_external'], 'ABC');
		$this->assertEquals($attributes['capital_string_internal'], 'ABC');
		$this->assertEquals($attributes['capital_string_both'], 'CAPITAL: ABC');
	}

	public function testRegisterAttributeAccessor()
	{
		$model = $this->getInstance();

		$attributes = $model->getAttributes();
		$attributes['lowercase_string_external'] = 'ABC';
		$attributes['lowercase_string_internal'] = 'ABC';
		$attributes['lowercase_string_both'] = 'ABC';

		$model->setRawAttributes($attributes);

		$this->assertEquals($model->lowercase_string_external, 'abc');
		$this->assertEquals($model->lowercase_string_internal, 'abc');
		$this->assertEquals($model->lowercase_string_both, 'lowercase: abc');
	}
}