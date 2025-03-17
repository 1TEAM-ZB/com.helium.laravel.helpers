<?php

namespace Tests\Tests\Traits;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;
use Tests\Models\BulkActionsModel;
use Tests\Models\HasFailedEventsModel;

class HasFailedEventsTest extends TestCase
{
    public function testCreate()
    {
        $model = factory(HasFailedEventsModel::class)->make([
            'data' => null
        ]);

        try {
            $model->save();

            $this->assertTrue(false);
        } catch (\Throwable $t) {
            $this->assertTrue($model->saveDidFail);
            $this->assertTrue($model->createDidFail);
            $this->assertFalse($model->updateDidFail);
        }
    }

    public function testUpdate()
    {
        $model = factory(HasFailedEventsModel::class)->create();

        try {
            $model->update([
                'data' => null
            ]);

            $this->assertTrue(false);
        } catch (\Throwable $t) {
            $this->assertTrue($model->saveDidFail);
            $this->assertFalse($model->createDidFail);
            $this->assertTrue($model->updateDidFail);
        }
    }
}