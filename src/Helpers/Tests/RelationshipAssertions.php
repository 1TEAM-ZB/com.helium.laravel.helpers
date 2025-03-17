<?php

namespace Helium\LaravelHelpers\Helpers\Tests;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Tests\TestCase;

/**
 * @mixin TestCase
 */
trait RelationshipAssertions
{
    /**
     * @description Test that the specified relationship functions as a basic
     * belongsTo relationship with a single foreign key. Composite keys are NOT
     * currently supported.
     * @param string $class The class being tested
     * @param string $foreign_key The foreign key field on the class being tested
     * @param string $relationship The name of the relationship
     * @param string $otherClass The class of the related object
     * @param string $local_key The primary key of $model
     * @return Model
     */
    public function assertBasicBelongsToRelationship(
        string $class,
		string $foreign_key,
        string $relationship,
        string $otherClass,
		string $local_key = 'id'
    )
    {
        $related = factory($otherClass)->create();
        $model = factory($class)->create([
            $foreign_key => $related->$local_key
        ]);

        $this->assertNotNull($model->$foreign_key);
        $this->assertNotNull($model->$relationship);
        $this->assertInstanceOf($otherClass, $model->$relationship);

        return $model;
    }

    /**
     * @description Test that the specified relationship functions as a basic
     * hasMany relationship with a single foreign key. Composite keys are NOT
     * currently supported.
     * @param string $class The class being tested
     * @param string $relationship The name of the relationship
     * @param string $otherClass The class of the related objects
     * @param string $foreign_key The foreign key field on the related object
     * @return Model
     */
    public function assertBasicHasManyRelationship(
        string $class,
		string $relationship,
        string $otherClass,
        string $foreign_key
    )
    {
        $model = factory($class)->create();

        $related1 = factory($otherClass)->create([
            $foreign_key => $model->getKey()
        ]);

        $related2 = factory($otherClass)->create([
            $foreign_key => $model->getKey()
        ]);

        $this->assertNotNull($model->$relationship);
        $this->assertInstanceOf(Collection::class, $model->$relationship);

        $this->assertTrue($model->$relationship->contains(
            $related1->getKeyName(),
            $related1->getKey()
        ));

        $this->assertTrue($model->$relationship->contains(
            $related2->getKeyName(),
            $related2->getKey()
        ));

        return $model;
    }

    /**
     * @description Test that the specified relationship functions as a basic
     * belongsToMany relationship. Composite keys are NOT currently supported.
     * @param string $class The class being tested
     * @param string $relationship The name of the relationship
     * @param string $relatedClass The class of the related objects
     * @param string $throughClass The class of the joining class
     * @param string $classForeignKey The foreign key column name on $throughClass to $class
     * @param string $relatedClassForeignKey The foreign key column name on $throughClass to $relatedClass
     * @return Model
     */
    public function assertBasicBelongsToManyRelationship(
        string $class,
		string $relationship,
        string $relatedClass,
        string $throughClass,
		string $classForeignKey,
        string $relatedClassForeignKey
    )
    {
    	$model = factory($class)->create();

    	$related = factory($relatedClass)->create();

    	$through = factory($throughClass)->create([
			$classForeignKey => $model->getKey(),
		    $relatedClassForeignKey => $related->getKey()
	    ]);

    	$this->assertTrue($model->$relationship->contains(
    		$related->getKeyName(),
		    $related->getKey()
	    ));

    	return $model;
    }
    /**
     * @description Test that the specified relationship functions as a basic
     * hasManyThrough relationship. Composite keys are NOT currently supported.
     * @param string $class The class being tested
     * @param string $relationship The name of the relationship
     * @param string $relatedClass The class of the related objects
     * @param string $throughClass The class of the joining class
     * @param string $classForeignKey The foreign key column name on $throughClass to $class
     * @param string $throughClassForeignKey The foreign key column name on $throughClass to $relatedClass
     * @return Model
     */
    public function assertBasicHasManyThroughRelationship(
        string $class,
        string $relationship,
        string $relatedClass,
        string $throughClass,
        string $classForeignKey,
        string $throughClassForeignKey
    )
    {
        $model = factory($class)->create();

        $through = factory($throughClass)->create([
            $classForeignKey => $model->id
        ]);

        $related = factory($relatedClass)->create([
            $throughClassForeignKey => $through->id
        ]);

        $this->assertTrue($model->$relationship->contains(
            $related->getKeyName(),
            $related->getKey()
        ));

        return $model;
    }
}
