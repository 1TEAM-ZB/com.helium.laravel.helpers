<?php

namespace Tests\Tests\Resources;

use Exception;
use Helium\LaravelHelpers\Exceptions\ValidationException;
use Helium\LaravelHelpers\Resources\ApiErrorResource;
use Illuminate\Http\Request;
use Tests\TestCase;
use Tests\Models\SelfValidatesModel;

class ApiErrorResourceTest extends TestCase
{
	public function testBasicException()
	{
		$message = 'An error occurred';
		$e = new Exception($message);

		$resource = new ApiErrorResource($e);
		$array = $resource->toArray(new Request());

		$this->assertCount(1, $array);

		$this->assertArrayHasKey('message', $array);
		$this->assertEquals($array['message'], $message);
	}

	public function testValidationException()
	{
		try {
			factory(SelfValidatesModel::class)->make([
				'string' => null
			])->validate();

			$this->assertTrue(false);
		} catch (ValidationException $e) {
			$resource = new ApiErrorResource($e);
			$array = $resource->toArray(new Request());

			$this->assertCount(2, $array);

			$this->assertArrayHasKey('message', $array);
			$this->assertEquals($array['message'], $e->getMessage());

			$this->assertArrayHasKey('messages', $array);
			$this->assertEquals($array['messages'], $e->toArray());
		}
	}

	public function testDebug()
	{
		config(['app.debug' => true]);

		$message = 'An error occurred';
		$e = new Exception($message);

		$resource = new ApiErrorResource($e);
		$array = $resource->toArray(new Request());

		$this->assertCount(3, $array);

		$this->assertArrayHasKey('message', $array);
		$this->assertEquals($array['message'], $message);

		$this->assertArrayHasKey('exception_class', $array);
		$this->assertEquals(Exception::class, $array['exception_class']);

		$this->assertArrayHasKey('stack_trace', $array);
		$this->assertIsArray($array['stack_trace']);
	}
}