<?php

namespace Tests\Tests\Traits;

use Helium\LaravelHelpers\Search\SearchQuery;
use Tests\TestCase;
use Tests\Models\ModelSearchModel;

class ModelSearchTest extends TestCase
{
    public function testSearch()
    {
        $this->assertInstanceOf(SearchQuery::class, ModelSearchModel::search());
        $this->assertInstanceOf(SearchQuery::class, ModelSearchModel::search()->filter());
        $this->assertInstanceOf(SearchQuery::class, ModelSearchModel::search()->orderBy());
        $this->assertInstanceOf(SearchQuery::class, ModelSearchModel::search()->allowRelations());
        $this->assertInstanceOf(SearchQuery::class, ModelSearchModel::search()->load());

        $parent = factory(ModelSearchModel::class)->create();
        factory(ModelSearchModel::class, 10)->create([
            'data' => 'abc',
            'parent_id' => $parent->id
        ]);
        factory(ModelSearchModel::class, 10)->create([
            'data' => 'cde',
            'parent_id' => $parent->id
        ]);

        $query = ModelSearchModel::search()->filter([
                'data' => [
                    'eq' => 'abc'
                ]
            ])
            ->allowRelations([])
            ->load(['parent'])
            ->paginate();

        $this->assertCount(10, $query->items());
        foreach ($query->items() as $item)
        {
            $this->assertArrayNotHasKey('parent', $item->toArray());
        }

        $query = ModelSearchModel::search()->filter([
                'data' => [
                    'like' => '%c%'
                ]
            ])
            ->orderBy([
                'data' => 'desc'
            ])
            ->allowRelations(['parent'])
            ->load(['parent'])
            ->paginate(1, 20);

        $this->assertCount(20, $query->items());

        $prev = null;
        foreach ($query->items() as $item)
        {
            $this->assertArrayHasKey('parent', $item->toArray());

            if ($prev) {
                $this->assertGreaterThanOrEqual($item->data, $prev->data);
            }

            $prev = $item;
        }

        $query = ModelSearchModel::search()->filter([
                'data' => [
                    'like' => '%c%'
                ]
            ])
            ->orderBy([
                'data' => 'desc'
            ])
            ->allowRelations(['parent'])
            ->load(['parent'])
            ->paginate(2, 7);

        $array = $query->toArray();
        $this->assertStringContainsString('per_page=7', $array['first_page_url']);
        $this->assertStringContainsString('per_page=7', $array['prev_page_url']);
        $this->assertStringContainsString('per_page=7', $array['next_page_url']);
        $this->assertStringContainsString('per_page=7', $array['last_page_url']);
        $this->assertEquals(7, $array['per_page']);
        $this->assertEquals(2, $array['current_page']);

        $query = ModelSearchModel::search()->filter([
            'data' => [
                'like' => '%c%'
            ]
        ])
            ->orderBy([
                'data' => 'desc'
            ])
            ->allowRelations(['parent'])
            ->load(['parent'])
            ->paginate(2, 7, 'perPage');

        $array = $query->toArray();
        $this->assertStringContainsString('perPage=7', $array['first_page_url']);
        $this->assertStringContainsString('perPage=7', $array['prev_page_url']);
        $this->assertStringContainsString('perPage=7', $array['next_page_url']);
        $this->assertStringContainsString('perPage=7', $array['last_page_url']);
    }

    public function testAllowRelations()
    {
        $parent = factory(ModelSearchModel::class)->create();

        /** Test default (no relations restricted */
        $model = factory(ModelSearchModel::class)->create([
            'parent_id' => $parent->id
        ]);
        $model->load('parent');
        $this->assertArrayHasKey('parent', $model->toArray());

        /** Test No Relations Allowed (empty array) */
        $model = factory(ModelSearchModel::class)->create([
            'parent_id' => $parent->id
        ]);
        $model->allowRelations([])
            ->load('parent');
        $this->assertArrayNotHasKey('parent', $model->toArray());

        /** Test 'parent' Relation allowed with load string */
        $model = factory(ModelSearchModel::class)->create([
            'parent_id' => $parent->id
        ]);
        $model->allowRelations(['parent'])
            ->load('parent');
        $this->assertArrayHasKey('parent', $model->toArray());

        /** Test 'parent' Relation allowed with load array */
        $model = factory(ModelSearchModel::class)->create([
            'parent_id' => $parent->id
        ]);
        $model->allowRelations(['parent'])
            ->load(['parent']);
        $this->assertArrayHasKey('parent', $model->toArray());
    }
}