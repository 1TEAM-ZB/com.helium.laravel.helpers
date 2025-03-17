<?php

namespace Tests\Tests\Traits;

use Askedio\SoftCascade\Traits\SoftCascadeTrait;
use Czim\NestedModelUpdater\Traits\NestedUpdatable;
use Helium\LaravelHelpers\Exceptions\ValidationException;
use Helium\LaravelHelpers\Traits\BulkActions;
use Helium\LaravelHelpers\Traits\DefaultOrdering;
use Helium\LaravelHelpers\Traits\FillableOnCreate;
use Helium\LaravelHelpers\Traits\GeneratesPrimaryKey;
use Helium\LaravelHelpers\Traits\HasAttributeEvents;
use Helium\LaravelHelpers\Traits\HasEnums;
use Helium\LaravelHelpers\Traits\HeliumBaseTraits;
use Helium\LaravelHelpers\Traits\ModelSearch;
use Helium\LaravelHelpers\Traits\SelfValidates;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Collection;
use Tests\Models\SelfValidatesModel;
use Tests\Models\SelfValidatesModel2;
use Tests\TestCase;

/**
 * Note: It is not necessary to test every possible validation rule, since
 * SelfValidates makes use of Laravel's built-in validator.
 *
 * Rather, unit tests should cover the successful use of the suppliedconfiguration,
 * including validation rules, messages, and validatesOnSave.
 */
class HeliumBaseTraitsTest extends TestCase
{
	public function testHasTraits()
	{
		$uses = class_uses(HeliumBaseTraits::class);

		$this->assertContains(GeneratesPrimaryKey::class, $uses);
		$this->assertContains(HasAttributeEvents::class, $uses);
		$this->assertContains(HasEnums::class, $uses);
		$this->assertContains(SelfValidates::class, $uses);
		$this->assertContains(SoftDeletes::class, $uses);
		$this->assertContains(SoftCascadeTrait::class, $uses);
		$this->assertContains(DefaultOrdering::class, $uses);
		$this->assertContains(BulkActions::class, $uses);
		$this->assertContains(FillableOnCreate::class, $uses);
		$this->assertContains(ModelSearch::class, $uses);
	}
}