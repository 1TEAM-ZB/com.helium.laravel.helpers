<?php

namespace Tests\Tests\Traits;

use Tests\Models\HeliumBaseTraitsModel;
use Tests\Models\HeliumBaseTraitsModel2;

/**
 * Inherits all test cases from SelfValidatesTest
 */
class HeliumBaseSelfValidatesTest extends SelfValidatesTest
{
	protected const TEST_CLASS = HeliumBaseTraitsModel::class;
	protected const TEST_CLASS_2 = HeliumBaseTraitsModel2::class;
}