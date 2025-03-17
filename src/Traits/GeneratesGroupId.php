<?php

namespace Helium\LaravelHelpers\Traits;

use Helium\LaravelHelpers\Generators\UuidIdGenerator;
use Helium\LaravelHelpers\Contracts\IdGenerator;
use Illuminate\Database\Eloquent\Model;

trait GeneratesGroupId
{
	//region Helpers
	/**
	 * @description Get IdGenerator instance
	 * @return IdGenerator
	 */
	public function getGroupIdGenerator(): IdGenerator
	{
        return new UuidIdGenerator($this->groupIdPrefix);
	}
	//endregion

	//region Functions
    public function getGroupIdName()
    {
        return property_exists($this, 'groupIdName') ? $this->groupIdName : 'group_id';
    }

    public function getGroupId()
    {
        return $this->getAttribute($this->getGroupIdName());
    }

    public function attemptGenerateGroupId()
    {
        if (!$this->getGroupId())
        {
            $groupIdName = $this->getGroupIdName();

            $this->setAttribute(
                $groupIdName,
                $this->getGroupIdGenerator()->generate()
            );
        }
    }

	/**
	 * @description Generate a unique primary key on creation
	 */
	public static function bootGeneratesGroupId()
	{
		self::creating(function (Model $model) {
            /** @var GeneratesGroupId $model */
		    $model->attemptGenerateGroupId();
		});
	}
	//endregion

    //region Relationships
    public function groupMates()
    {
        return $this->hasMany(static::class, $this->getGroupIdName(), $this->getGroupIdName());
    }
    //endregion
}
