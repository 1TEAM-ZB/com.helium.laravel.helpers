<?php

namespace Tests\Tests\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Tests\Controllers\RespondCamelCaseController;
use Tests\TestCase;

class RespondCamelCaseTest extends TestCase
{
    public function testCallAction()
    {
        /**
         * This controller simply returns any data that is passed into it
         */
        $controller = new RespondCamelCaseController;

        /**
         * Test when data is given in snake
         */
        $request = new Request;

        $request->merge([
            'some_attribute' => 'abc'
        ]);

        $response = $controller->callAction('index', [$request]);

        $this->assertInstanceOf(JsonResponse::class, $response);

        $data = $response->getData(true);
        $this->assertArrayHasKey('someAttribute', $data);
        $this->assertEquals('abc', $data['someAttribute']);
        $this->assertArrayNotHasKey('some_attribute', $data);

        /**
         * Test when data is given in camel
         */
        $request = new Request;

        $request->merge([
            'someAttribute' => 'abc'
        ]);

        $response = $controller->callAction('index', [$request]);

        $this->assertInstanceOf(JsonResponse::class, $response);

        $data = $response->getData(true);
        $this->assertArrayHasKey('someAttribute', $data);
        $this->assertEquals('abc', $data['someAttribute']);
        $this->assertArrayNotHasKey('some_attribute', $data);

        /**
         * Test when data is given in both camel and snake
         */
        $request = new Request;

        $request->merge([
            'someAttribute' => 'abc',
            'some_attribute' => '123'
        ]);

        $response = $controller->callAction('index', [$request]);

        $this->assertInstanceOf(JsonResponse::class, $response);

        $data = $response->getData(true);
        $this->assertArrayHasKey('someAttribute', $data);
        $this->assertEquals('abc', $data['someAttribute']);
        $this->assertArrayHasKey('some_attribute', $data);
        $this->assertEquals('123', $data['some_attribute']);


        /**
         * Test recursion
         */
        $request = new Request;

        $request->merge([
            'some_object' => [
                'some_attribute' => 'abc'
            ]
        ]);

        $response = $controller->callAction('index', [$request]);

        $this->assertInstanceOf(JsonResponse::class, $response);

        $data = $response->getData(true);
        $this->assertArrayHasKey('someObject', $data);
        $this->assertIsArray($data['someObject']);
        $this->assertArrayHasKey('someAttribute', $data['someObject']);
        $this->assertEquals('abc', $data['someObject']['someAttribute']);
    }
}