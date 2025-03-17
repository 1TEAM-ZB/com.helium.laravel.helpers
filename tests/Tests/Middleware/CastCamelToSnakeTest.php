<?php

namespace Tests\Tests\Middleware;

use Helium\LaravelHelpers\Middleware\CastCamelToSnake;
use Illuminate\Http\Request;
use Tests\TestCase;

class CastCamelToSnakeTest extends TestCase
{
    public function testCastCamelToSnake()
    {
        /**
         * Test when only camel is given
         */
        $middleware = new CastCamelToSnake;
        $request = new Request;

        $request->merge([
            'someAttribute' => 'abc'
        ]);

        $middleware->handle($request, function($req) {
            $this->assertArrayHasKey('someAttribute', $req->all());
            $this->assertArrayHasKey('some_attribute', $req->all());
            $this->assertEquals('abc', $req->someAttribute);
            $this->assertEquals('abc', $req->some_attribute);
        });

        /**
         * Test when only snake is given
         */
        $middleware = new CastCamelToSnake;
        $request = new Request;

        $request->merge([
            'some_attribute' => 'abc'
        ]);

        $middleware->handle($request, function($req) {
            $this->assertArrayHasKey('some_attribute', $req->all());
            $this->assertEquals('abc', $req->some_attribute);
        });

        /**
         * Test when mix of camel and snake is given
         */
        $middleware = new CastCamelToSnake;
        $request = new Request;

        $request->merge([
            'someAttribute' => 'abc',
            'some_attribute' => '123'
        ]);

        $middleware->handle($request, function($req) {
            $this->assertArrayHasKey('someAttribute', $req->all());
            $this->assertArrayHasKey('some_attribute', $req->all());
            $this->assertEquals('abc', $req->someAttribute);
            $this->assertEquals('123', $req->some_attribute);
        });

        /**
         * Test recursion
         */
        $middleware = new CastCamelToSnake;
        $request = new Request;

        $request->merge([
            'someObject' => [
                'someAttribute' => 'abc'
            ]
        ]);

        $middleware->handle($request, function($req) {
            $this->assertArrayHasKey('some_object', $req->all());
            $this->assertIsArray($req->some_object);
            $this->assertArrayHasKey('some_attribute', $req->some_object);
            $this->assertEquals('abc', $req->some_object['some_attribute']);
        });
    }
}