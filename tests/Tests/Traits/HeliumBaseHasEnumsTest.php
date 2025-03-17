<?php

namespace Tests\Tests\Traits;

use Tests\Models\HeliumBaseTraitsModel;

/**
 * Inherits all test cases from HasEnumsTest
 */
class HeliumBaseHasEnumsTest extends HasEnumsTest
{
	protected const TEST_CLASS = HeliumBaseTraitsModel::class;
}