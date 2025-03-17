<?php

namespace Tests\Tests\Traits;

use Carbon\Carbon;
use Illuminate\Database\QueryException;
use Tests\Models\FlexModelModel;
use Tests\TestCase;

class FlexModelTest extends TestCase
{
	protected const TEST_CLASS = FlexModelModel::class;

	protected const FLEX_ATTRIBUTE_INITIAL_VALUE = 'lorem ipsum';
	protected const FLEX_ARRAY_INITIAL_VALUE = ['a', 'b', 'c'];

	protected function getInstance()
	{
		return factory(self::TEST_CLASS)->create([
            'required_string' => 'abc123',
			'flex_attribute' => self::FLEX_ATTRIBUTE_INITIAL_VALUE,
			'flex_array' => self::FLEX_ARRAY_INITIAL_VALUE
		]);
	}

	public function testGetFlexColumn()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->getFlexColumn(), 'data');

		$newFlexColumn = 'flex_data';
		$model->flexColumn = $newFlexColumn;

		$this->assertEquals($model->getFlexColumn(), $newFlexColumn);
	}

	public function testGetBaseColumns()
	{
		$model = $this->getInstance();

		$this->assertEquals($model->getBaseColumns(), [
			'id',
			'created_at',
			'updated_at',
            'required_string'
		]);
	}

	public function testIsBaseAttribute()
	{
		$model = $this->getInstance();

		$this->assertTrue($model->isBaseAttribute('id'));
		$this->assertFalse($model->isBaseAttribute('data'));
		$this->assertFalse($model->isBaseAttribute('flex_attribute'));
	}

	public function testIsFlexAttribute()
	{
		$model = $this->getInstance();

		$this->assertFalse($model->isFlexAttribute('id'));
		$this->assertFalse($model->isFlexAttribute('data'));
		$this->assertTrue($model->isFlexAttribute('flex_attribute'));
	}

	public function testFilterBaseAttributes()
	{
		$model = $this->getInstance();
		$attributes = $model->getAttributes();

		$filteredAttributes = $model->filterBaseAttributes($attributes);

		$this->assertCount(4, $filteredAttributes);
		$this->assertArrayHasKey('id', $filteredAttributes);
		$this->assertEquals($filteredAttributes['id'], $attributes['id']);
		$this->assertArrayHasKey('created_at', $filteredAttributes);
		$this->assertEquals($filteredAttributes['created_at'], $attributes['created_at']);
		$this->assertArrayHasKey('updated_at', $filteredAttributes);
		$this->assertEquals($filteredAttributes['updated_at'], $attributes['updated_at']);
	}

	public function testFilterFlexAttributes()
	{
		$model = $this->getInstance();
		$attributes = $model->getAttributes();

		$filteredAttributes = $model->filterFlexAttributes($attributes);

		$this->assertCount(2, $filteredAttributes);
		$this->assertArrayHasKey('flex_attribute', $filteredAttributes);
		$this->assertEquals($filteredAttributes['flex_attribute'], $attributes['flex_attribute']);
		$this->assertArrayHasKey('flex_array', $filteredAttributes);
		$this->assertEquals($filteredAttributes['flex_array'], $attributes['flex_array']);
	}

	public function testGetBaseAttributes()
	{
		$model = $this->getInstance();
		$attributes = $model->getAttributes();

		$baseAttributes = $model->getBaseAttributes();

		$this->assertCount(4, $baseAttributes);
		$this->assertArrayHasKey('id', $baseAttributes);
		$this->assertEquals($baseAttributes['id'], $attributes['id']);
		$this->assertArrayHasKey('created_at', $baseAttributes);
		$this->assertEquals($baseAttributes['created_at'], $attributes['created_at']);
		$this->assertArrayHasKey('updated_at', $baseAttributes);
		$this->assertEquals($baseAttributes['updated_at'], $attributes['updated_at']);
	}

	public function testGetFlexAttributes()
	{
		$model = $this->getInstance();
		$attributes = $model->getAttributes();

		$flexAttributes = $model->getFlexAttributes();

		$this->assertCount(2, $flexAttributes);
		$this->assertArrayHasKey('flex_attribute', $flexAttributes);
		$this->assertEquals($flexAttributes['flex_attribute'], $attributes['flex_attribute']);
		$this->assertArrayHasKey('flex_array', $flexAttributes);
		$this->assertEquals($flexAttributes['flex_array'], $attributes['flex_array']);
	}

	public function testGetTableAttributes()
	{
		$model = $this->getInstance();
		$attributes = $model->getAttributes();

		$tableAttributes = $model->getTableAttributes();

		$this->assertCount(5, $tableAttributes);
		$this->assertArrayHasKey('id', $tableAttributes);
		$this->assertEquals($tableAttributes['id'], $attributes['id']);
		$this->assertArrayHasKey('created_at', $tableAttributes);
		$this->assertEquals($tableAttributes['created_at'], $attributes['created_at']);
		$this->assertArrayHasKey('updated_at', $tableAttributes);
		$this->assertEquals($tableAttributes['updated_at'], $attributes['updated_at']);
		$this->assertArrayHasKey('data', $tableAttributes);
		$this->assertJson($tableAttributes['data']);

		$flexAttributes = json_decode($tableAttributes['data'], true);
		$this->assertCount(2, $flexAttributes);
		$this->assertArrayHasKey('flex_attribute', $flexAttributes);
		$this->assertEquals($flexAttributes['flex_attribute'], $attributes['flex_attribute']);
		$this->assertArrayHasKey('flex_array', $flexAttributes);
		$this->assertEquals($flexAttributes['flex_array'], $attributes['flex_array']);
	}

	public function testRetrieve()
    {
        $class = self::TEST_CLASS;

        $attributes = [
            'id' => 100,
            'created_at' => Carbon::now()->toDateTimeString(),
            'updated_at' => Carbon::now()->toDateTimeString(),
            'required_string' => 'abc123',
            'flex_attribute' => 'abc',
            'flex_array' => ['a', 'b', 'c']
        ];

        $class::create($attributes);

        $model = $class::find(100);

        foreach($attributes as $key => $value)
        {
            $this->assertEquals($attributes[$key], $model->$key);
        }
    }

	public function testCreate()
	{
		$class = self::TEST_CLASS;

		$attributes = [
			'id' => 100,
			'created_at' => Carbon::now()->toDateTimeString(),
			'updated_at' => Carbon::now()->toDateTimeString(),
            'required_string' => 'abc123',
            'flex_attribute' => 'abc',
            'flex_array' => ['a', 'b', 'c']
		];

		$model = $class::create($attributes);

		foreach($attributes as $key => $value)
        {
            $this->assertEquals($attributes[$key], $model->$key);
        }
	}

	public function testCreateFail()
    {
        $class = self::TEST_CLASS;

        $attributes = [
            'id' => 100,
            'created_at' => Carbon::now()->toDateTimeString(),
            'updated_at' => Carbon::now()->toDateTimeString(),
            'required_string' => null,
            'flex_attribute' => 'abc',
            'flex_array' => ['a', 'b', 'c']
        ];

        $model = $class::make($attributes);

        try {
            $model->save();

            $this->assertTrue(false);
        } catch (QueryException $t) {
            foreach($attributes as $key => $value)
            {
                $this->assertEquals($value, $model->$key);
            }
        }
    }

    public function testUpdate()
    {
        $class = self::TEST_CLASS;

        $attributes = [
            'id' => 100,
            'created_at' => Carbon::now()->toDateTimeString(),
            'updated_at' => Carbon::now()->toDateTimeString(),
            'required_string' => 'abc123'
        ];

        $model = $class::create($attributes);

        $updateAttributes = [
            'flex_attribute' => 'abc',
            'flex_array' => ['a', 'b', 'c']
        ];

        $model->update($updateAttributes);

        $testAttributes = array_merge($attributes, $updateAttributes);

        foreach($testAttributes as $key => $value)
        {
            $this->assertEquals($value, $model->$key);
        }
    }

    public function testUpdateFail()
    {
        $class = self::TEST_CLASS;

        $attributes = [
            'id' => 100,
            'created_at' => Carbon::now()->toDateTimeString(),
            'updated_at' => Carbon::now()->toDateTimeString(),
            'required_string' => 'abc123'
        ];

        $model = $class::create($attributes);

        $updateAttributes = [
            'required_string' => null,
            'flex_attribute' => 'abc',
            'flex_array' => ['a', 'b', 'c']
        ];

        try {
            $model->update($updateAttributes);

            $this->assertTrue(false);
        } catch (QueryException $t) {
            $testAttributes = array_merge($attributes, $updateAttributes);

            foreach($testAttributes as $key => $value)
            {
                $this->assertEquals($value, $model->$key);
            }
        }
    }
}