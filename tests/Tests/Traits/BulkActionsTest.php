<?php

namespace Tests\Tests\Traits;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;
use Tests\Models\BulkActionsModel;

class BulkActionsTest extends TestCase
{
	protected function setUp(): void
	{
		parent::setUp();

		BulkActionsModel::truncate();
	}

	public function testBatchCreate()
	{
		$entries = factory(BulkActionsModel::class, 5)->raw();

		$results = BulkActionsModel::batchCreate($entries);

		$this->assertIsArray($results);
		foreach ($results as $result)
		{
			$this->assertInstanceOf(BulkActionsModel::class, $result);
			$this->assertTrue(BulkActionsModel::where('id', $result->id)->exists());

			$this->assertTrue($result->firedSaving);
			$this->assertFalse($result->firedUpdating);
			$this->assertTrue($result->firedCreating);
			$this->assertTrue($result->firedSaved);
			$this->assertFalse($result->firedUpdated);
			$this->assertTrue($result->firedCreated);
		}

		$this->assertEquals(5, BulkActionsModel::count());
	}

	public function testBulkUpdate()
	{
		$entries = factory(BulkActionsModel::class, 5)->create()->toArray();

		foreach (range(0, count($entries) - 1) as $i)
		{
			$entries[$i]['data'] = 'abc 123';
		}

		$results = BulkActionsModel::bulkUpdate($entries);

		$this->assertIsArray($results);
		foreach ($results as $result)
		{
			$this->assertInstanceOf(BulkActionsModel::class, $result);
			$this->assertEquals('abc 123', $result->data);

			$this->assertTrue($result->firedSaving);
			$this->assertTrue($result->firedUpdating);
			$this->assertFalse($result->firedCreating);
			$this->assertTrue($result->firedSaved);
			$this->assertTrue($result->firedUpdated);
			$this->assertFalse($result->firedCreated);
		}

		$this->assertEquals(5, BulkActionsModel::count());
	}

	public function testBulkCreateOrUpdate()
	{
		$createEntries = factory(BulkActionsModel::class, 5)->create()->toArray();

		$existingEntries = [];

		foreach (range(0, count($createEntries) - 1) as $i)
		{
			$createEntries[$i]['data'] = 'abc 123';
			$existingEntries[$createEntries[$i]['id']] = $createEntries[$i];
		}

		$newEntries = factory(BulkActionsModel::class, 5)->raw();

		$entries = array_merge($createEntries, $newEntries);

		$results = BulkActionsModel::bulkCreateOrUpdate($entries);

		$this->assertIsArray($results);
		foreach ($results as $result)
		{
			$this->assertInstanceOf(BulkActionsModel::class, $result);

			if (array_key_exists($result->id, $existingEntries))
			{
				$this->assertEquals('abc 123', $result->data);

				$this->assertTrue($result->firedSaving);
				$this->assertTrue($result->firedUpdating);
				$this->assertFalse($result->firedCreating);
				$this->assertTrue($result->firedSaved);
				$this->assertTrue($result->firedUpdated);
				$this->assertFalse($result->firedCreated);
			}
			else
			{
				$this->assertTrue(BulkActionsModel::where('id', $result->id)->exists());

				$this->assertTrue($result->firedSaving);
				$this->assertFalse($result->firedUpdating);
				$this->assertTrue($result->firedCreating);
				$this->assertTrue($result->firedSaved);
				$this->assertFalse($result->firedUpdated);
				$this->assertTrue($result->firedCreated);
			}
		}
		$this->assertEquals(10, BulkActionsModel::count());
	}
}