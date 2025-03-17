<?php

namespace Tests\Tests\Traits;

use Tests\TestCase;
use Tests\Models\DefaultOrderingModel;
use Tests\Models\DefaultOrderingModel2;

class DefaultOrderingTest extends TestCase
{
	public function testDefaultOrdering()
	{
		$sql = DefaultOrderingModel::query()->toSql();

		$this->assertStringContainsString('order by', $sql);
		$this->assertStringContainsString('"default_ordering_models"."updated_at" desc', $sql);
	}

	public function testSpecifiedOrdering()
	{
		$sql = DefaultOrderingModel2::query()->toSql();

		$this->assertStringContainsString('order by', $sql);
		$this->assertStringContainsString('"default_ordering_models"."created_at" desc', $sql);
		$this->assertStringContainsString('"default_ordering_models"."updated_at" asc', $sql);
	}
}