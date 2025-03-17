<?php

namespace Helium\LaravelHelpers\Traits;

trait HasAttributeEvents
{
	//region Base
	/**
	 * @description Registered event listners
	 * @var array
	 */
	protected static $attributeEventListners = [
		'setting_attribute' => [],
		'did_set_attribute' => [],
		'getting_attribute' => [],
		'did_get_attribute' => []
	];

	/**
	 * @description Externally registered attribute mutators
	 * @var array
	 */
	protected static $mutators = [];

	/**
	 * @description Externally registered attribute mutators
	 * @var array
	 */
	protected static $accessors = [];
	//endregion

	//region Helpers
	/**
	 * @description Register an event listener for the specified event
	 * @param string $event
	 * @param callable $callback
	 */
	protected static function addAttributeEventListner(string $event, callable $callback): void
	{
		self::$attributeEventListners[$event][] = $callback;
	}

	/**
	 * @description Trigger any registered event listeners for the specified event
	 * @param string $event
	 * @param mixed ...$args
	 */
	protected static function resolveAttributeEventListners(string $event, ...$args): void
	{
		foreach (self::$attributeEventListners[$event] as $callback)
		{
			call_user_func_array($callback, $args);
		}
	}

	/**
	 * @description Determines whether this model has functions registered using
	 * static::registerAttributeMutator
	 * @param $key
	 * @return bool
	 */
	public function hasExternallyRegisteredMutator($key)
	{
		return !empty(self::$mutators[$key]);
	}

	/**
	 * @description Determines whether this model has functions registered using
	 * static::registerAttributeAccessor
	 * @param $key
	 * @return bool
	 */
	public function hasExternallyRegisteredAccessor($key)
	{
		return !empty(self::$accessors[$key]);
	}
	//endregion

	//region Functions
	/**
	 * @description Register an event listener before setting attributes
	 * @param callable $callback
	 */
	public static function settingAttribute(callable $callback): void
	{
		self::addAttributeEventListner('setting_attribute', $callback);
	}

	/**
	 * @description Register an event listener after setting attributes
	 * @param callable $callback
	 */
	public static function didSetAttribute(callable $callback): void
	{
		self::addAttributeEventListner('did_set_attribute', $callback);
	}

	/**
	 * @description Register an event listener before getting attributes
	 * @param callable $callback
	 */
	public static function gettingAttribute(callable $callback): void
	{
		self::addAttributeEventListner('getting_attribute', $callback);
	}

	/**
	 * @description Register an event listener after getting attributes
	 * @param callable $callback
	 */
	public static function didGetAttribute(callable $callback): void
	{
		self::addAttributeEventListner('did_get_attribute', $callback);
	}

	/**
	 * @description Register an attribute mutator function
	 * @param string $key
	 * @param callable $callback
	 */
	public static function registerAttributeMutator(string $key, callable $callback): void {
		if (!isset(self::$mutators[$key]))
		{
			self::$mutators[$key] = [];
		}

		self::$mutators[$key][] = $callback;
	}

	/**
	 * @description Register an attribute accessor function
	 * @param string $key
	 * @param callable $callback
	 */
	public static function registerAttributeAccessor(string $key, callable $callback): void {
		if (!isset(self::$accessors[$key]))
		{
			self::$accessors[$key] = [];
		}

		self::$accessors[$key][] = $callback;
	}
	//endregion

	//region Overrides
	/**
	 * @description Determine if a set mutator exists for an attribute.
	 * @param  string  $key
	 * @return bool
	 */
	public function hasSetMutator($key)
	{
		return $this->hasExternallyRegisteredMutator($key) || parent::hasSetMutator($key);
	}

	/**
	 * Set the value of an attribute using its mutator.
	 *
	 * @param  string  $key
	 * @param  mixed  $value
	 * @return mixed
	 */
	protected function setMutatedAttributeValue($key, $value)
	{
		if ($this->hasExternallyRegisteredMutator($key))
		{
			foreach (self::$mutators[$key] as $callback)
			{
				$value = $callback($value);
			}
		}

		if (parent::hasSetMutator($key))
		{
			return parent::setMutatedAttributeValue($key, $value);
		}
		else
		{
			return $this->attributes[$key] = $value;
		}
	}

	/**
	 * @description Set attribute with event callbacks
	 * @param $key
	 * @param $value
	 * @return mixed
	 */
	public function setAttribute($key, $value)
	{
		self::resolveAttributeEventListners('setting_attribute',
			$this,
			$key,
			$value
		);

		$results = parent::setAttribute($key, $value);

		self::resolveAttributeEventListners('did_set_attribute',
			$this,
			$key,
			$value
		);

		return $results;
	}

	/**
	 * @description Determine if a set mutator exists for an attribute.
	 * @param  string  $key
	 * @return bool
	 */
	public function hasGetMutator($key)
	{
		return $this->hasExternallyRegisteredAccessor($key) || parent::hasGetMutator($key);
	}

	/**
	 * Get the value of an attribute using its mutator.
	 *
	 * @param  string  $key
	 * @param  mixed  $value
	 * @return mixed
	 */
	protected function mutateAttribute($key, $value)
	{
		if ($this->hasExternallyRegisteredAccessor($key))
		{
			foreach (self::$accessors[$key] as $callback)
			{
				$value = $callback($value);
			}
		}

		if (parent::hasGetMutator($key))
		{
			return parent::mutateAttribute($key, $value);
		}
		else
		{
			return $value;
		}
	}

	/**
	 * @description Get attribute with event callbacks
	 * @param $key
	 * @return mixed
	 */
	public function getAttribute($key)
	{
		self::resolveAttributeEventListners('getting_attribute',
			$this,
			$key
		);

		$results = parent::getAttribute($key);

		self::resolveAttributeEventListners('did_get_attribute',
			$this,
			$key
		);

		return $results;
	}
	//endregion
}