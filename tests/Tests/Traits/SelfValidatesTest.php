<?php

namespace Tests\Tests\Traits;

use Helium\LaravelHelpers\Exceptions\ValidationException;
use Illuminate\Support\Collection;
use Tests\Models\SelfValidatesModel;
use Tests\Models\SelfValidatesModel2;
use Tests\TestCase;

/**
 * Note: It is not necessary to test every possible validation rule, since
 * SelfValidates makes use of Laravel's built-in validator.
 *
 * Rather, unit tests should cover the successful use of the suppliedconfiguration,
 * including validation rules, messages, and validatesOnSave.
 */
class SelfValidatesTest extends TestCase
{
	protected const TEST_CLASS = SelfValidatesModel::class;
	protected const TEST_CLASS_2 = SelfValidatesModel2::class;

	protected function getInstance()
	{
		return factory(self::TEST_CLASS)->create();
	}

	protected function getInstance2()
	{
		return factory(self::TEST_CLASS_2)->create();
	}

	//region Configuration
	public function testValidationRulesArray()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->validationRules, $model->getValidationRules());
	}

	public function testValidationRulesFunction()
	{
		$model = $this->getInstance2();

		$this->assertEquals($model->validationRules(), $model->getValidationRules());
	}

	public function testValidationMessagesArray()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->validationMessages, $model->getValidationMessages());
	}

	public function testValidationMessagesFunction()
	{
		$model = $this->getInstance2();

		$this->assertEquals($model->validationMessages(), $model->getValidationMessages());
	}

	public function testValidatesOnSaveAttribute()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->validatesOnSave, $model->getValidatesOnSave());
	}

	public function testValidatesOnSaveFunction()
	{
		$model = $this->getInstance2();

		$this->assertEquals($model->validatesOnSave(), $model->getValidatesOnSave());
	}
	//endregion

	//region Validation
	public function testDoesNotValidateOnSave()
	{
		try
		{
			$model = factory(SelfValidatesModel::class)->create();

			$model->string = 123;

			$model->save();
		}
		catch (ValidationException $e)
		{
			//Fail if validation exception thrown
			$this->assertTrue(false);
			return;
		}

		$this->assertTrue(true);
	}

	public function testDoesValidateOnSave()
	{
		$this->assertThrowsException(function() {
			$model = factory(SelfValidatesModel::class)->create();

			$model->validatesOnSave = true;
			$model->string = 123;

			$model->save();
		}, ValidationException::class);
	}

	public function testManualValidate()
	{
		$this->assertThrowsException(function() {
			$model = factory(SelfValidatesModel::class)->create();

			$model->string = 123;

			$model->validate();
		}, ValidationException::class);
	}

	public function testValidateAttribute()
    {
        $model = factory(SelfValidatesModel::class)->create();

        $model->int = 'string';

        try {
            $model->validateAttribute('string');
        } catch (ValidationException $e) {
            $this->assertFalse(true);
        }

        $this->assertThrowsException(function() use ($model) {
            $model->string = 123;

            $model->validateAttribute('string');
        });


    }
	//endregion

	//region Exception
	public function testValidationExceptionToArray()
	{
		try
		{
			$model = factory(SelfValidatesModel::class)->create();

			$model->string = 123;

			$model->validate();
		}
		catch (ValidationException $e)
		{
			$this->assertIsArray($e->toArray());
			$this->assertCount(1, $e->toArray());

			return;
		}

		$this->assertTrue(false);
	}

	public function testDefaultValidationMessageUsed()
	{
		try
		{
			$model = factory(SelfValidatesModel::class)->create();

			$messages = $model->validationMessages;
			unset($model->validationMessages);

			$model->string = 123;

			$model->validate();
		}
		catch (ValidationException $e)
		{
			$this->assertArrayHasKey('string', $e->toArray(false));
			$this->assertArrayHasKey('string', $e->toArray(true));

			$this->assertNotEquals(
				$e->toArray(true)['string'][0],
				$messages['string.string']
			);

			$this->assertNotEquals(
				$e->toArray(false)['string'][0],
				$messages['string.string']
			);

			return;
		}

		$this->assertTrue(false);
	}

	public function testCustomValidationMessageUsed()
	{
		try
		{
			$model = factory(SelfValidatesModel::class)->create();

			$model->string = 123;

			$model->validate();
		}
		catch (ValidationException $e)
		{
			$this->assertArrayHasKey('string', $e->toArray(false));
			$this->assertArrayHasKey('string', $e->toArray(true));

			$this->assertStringContainsString(
				$model->getValidationMessages()['string.string'],
				$e->toArray(true)['string'][0]);

			$this->assertStringContainsString(
				$model->getValidationMessages()['string.string'],
				$e->toArray(false)['string'][0]);

			return;
		}

		$this->assertTrue(false);
	}

	public function testHelpfulExceptionMessageGiven()
	{
		try
		{
			$model = factory(SelfValidatesModel::class)->create();

			$model->string = 123;

			$model->validate();
		}
		catch (ValidationException $e)
		{
			$this->assertArrayHasKey('string', $e->toArray(false));
			$this->assertArrayHasKey('string', $e->toArray(true));

			foreach ($e->toArray(false)['string'] as $message)
			{
				$this->assertStringContainsString('string', $message);
			}

			foreach ($e->toArray(true)['string'] as $message)
			{
				$this->assertStringContainsString('string', $message);
				$this->assertStringContainsString($model->string, $message);
			}

			return;
		}

		$this->assertTrue(false);
	}
	//endregion

    //region Hidden
    public function testAllAttributesToArray()
    {
        $model = $this->getInstance();
        $attributes = $model->allAttributesToArray();

        $this->assertArrayHasKey('foreign_key', $attributes);
    }
    //endregion
}