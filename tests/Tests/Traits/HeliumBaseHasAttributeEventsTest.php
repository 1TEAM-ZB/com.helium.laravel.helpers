<?php

namespace Tests\Tests\Traits;

use Tests\Models\HeliumBaseTraitsModel;

/**
 * Inherits all test cases from HasAttributeEventsTest
 */
class HeliumBaseHasAttributeEventsTest extends HasAttributeEventsTest
{
	protected const TEST_CLASS = HeliumBaseTraitsModel::class;
}