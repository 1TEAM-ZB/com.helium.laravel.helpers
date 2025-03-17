<?php

namespace Tests\Tests\Traits;

use Tests\TestCase;
use Tests\Models\FillableOnCreateModel;

class FillableOnCreateTest extends TestCase
{
    public function testGetFillable()
    {
        $model = new FillableOnCreateModel();

        $this->assertCount(2, $model->getFillable());
        $this->assertContains('fillable_attribute', $model->getFillable());
        $this->assertContains('not_fillable_attribute', $model->getFillable());

        $model = factory(FillableOnCreateModel::class)->create();

        $this->assertCount(1, $model->getFillable());
        $this->assertContains('fillable_attribute', $model->getFillable());
        $this->assertNotContains('not_fillable_attribute', $model->getFillable());
    }
}