<?php

namespace Tests\Tests\Traits;

use Tests\Models\HeliumBaseTraitsModel;

/**
 * Inherits all test cases from GeneratesPrimaryKeyTest
 */
class HeliumBaseGeneratesPrimaryKeyTest extends GeneratesPrimaryKeyTest
{
	protected const TEST_CLASS = HeliumBaseTraitsModel::class;
}