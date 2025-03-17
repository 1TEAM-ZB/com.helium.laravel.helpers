<?php

namespace Tests;

use Exception;
use Helium\LaravelHelpers\Exceptions\ValidationException;

trait TestingHelpers
{
	public function assertThrowsException(callable $callback, string $exceptionClass = null)
	{
		$exceptionClass = $exceptionClass ?? Exception::class;
		$assertionMessage = "Failed to assert that {$exceptionClass} was thrown";

		try
		{
			$callback();

			$this->assertTrue(false, $assertionMessage);
		}
		catch (Exception $e)
		{
			$assertionMessage .= ', got ' . get_class($e);
			$this->assertInstanceOf($exceptionClass, $e, $assertionMessage);
		}
	}

	public function assertCreateHasErrors(array $attributes, int $expectedErrors)
	{
		try {
			$model = forward_static_call_array([$this->_modelClass, 'create'], [$attributes]);
			self::assertEquals($expectedErrors, 0);

			return $model;
		} catch (ValidationException $e) {
			$errors = $e->validator->errors()->all();
			self::assertCount($expectedErrors, $errors, implode(PHP_EOL, $errors));
		}

		return null;
	}
}