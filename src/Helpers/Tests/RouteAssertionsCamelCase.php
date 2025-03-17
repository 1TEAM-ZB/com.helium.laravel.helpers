<?php

namespace Helium\LaravelHelpers\Helpers\Tests;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Tests\TestCase;

/**
 * @mixin TestCase
 */
trait RouteAssertionsCamelCase
{
    /**
     * @description Assert that the given data array matches the format of a
     * paginated list, and that the perPage parameter is handled correctly
     * @param array $data
     * @param int|null $perPage
     */
    public function assertPaginatedList(array $data, ?int $perPage = null)
    {
        $this->assertArrayHasKey('currentPage', $data);
        $this->assertArrayHasKey('data', $data);
        $this->assertArrayHasKey('firstPageUrl', $data);
        $this->assertArrayHasKey('from', $data);
        $this->assertArrayHasKey('lastPage', $data);
        $this->assertArrayHasKey('lastPageUrl', $data);
        $this->assertArrayHasKey('nextPageUrl', $data);
        $this->assertArrayHasKey('path', $data);
        $this->assertArrayHasKey('perPage', $data);
        $this->assertArrayHasKey('prevPageUrl', $data);
        $this->assertArrayHasKey('to', $data);
        $this->assertArrayHasKey('total', $data);

        if ($perPage) {
            $this->assertEquals($perPage, $data['perPage']);
            $this->assertStringContainsString("perPage={$perPage}", $data['firstPageUrl']);
            $this->assertStringContainsString("perPage={$perPage}", $data['lastPageUrl']);
            $this->assertStringContainsString("perPage={$perPage}", $data['nextPageUrl']);
            $this->assertStringContainsString("perPage={$perPage}", $data['prevPageUrl']);
        }
    }

    /**
     * @description Given the original model instance, ensure that the JSON data
     * being returned from a GET endpoint matches the data in every way.
     * @param Model $model
     * @param array $data
     */
    public function assertModelData(Model $model, array $data)
    {
        foreach ($model->attributesToArray() as $key => $value) {
            $camelKey = Str::camel($key);
            $this->assertArrayHasKey($camelKey, $data);
            $this->assertEquals(
                $value,
                $data[$camelKey],
                "Failed to assert that {$camelKey} equals expected {$value}"
            );
        }
    }

    /**
     * @description Given an instance of the model, ensure that the JSON data
     * being returned from a GET endpoint matches the expected structure in every
     * way. Unlike assertModelData (above), we cannot test the actual values since
     * we do not have the original instance.
     * @param Model $model
     * @param array $data
     */
    public function assertModelDataStructure(Model $model, array $data)
    {
        foreach ($model->attributesToArray() as $key => $value) {
            $this->assertArrayHasKey(Str::camel($key), $data);
        }
    }
}
