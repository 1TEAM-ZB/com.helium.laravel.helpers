<?php

namespace Tests\Models\Base;

use Helium\LaravelHelpers\Helpers\StringHelper;
use Tests\Models\HasAttributeEventsModel;

trait SetupHasAttributeEvents
{
	public $_settingAttributeCalled = false;
	public $_settingAttributeKey = null;
	public $_settingAttributeValue = null;
	public $_didSetAttributeCalled = false;
	public $_didSetAttributeKey = null;
	public $_didSetAttributeValue = null;
	public $_gettingAttributeCalled = false;
	public $_gettingAttributeKey = null;
	public $_didGetAttributeCalled = false;
	public $_didGetAttributeKey = null;

	protected function setCapitalStringInternalAttribute($value)
	{
		return $this->attributes['capital_string_internal'] = strtoupper($value);
	}

	protected function getLowercaseStringInternalAttribute($value)
	{
		return strtolower($value);
	}

	protected function setCapitalStringBothAttribute($value)
	{
		return $this->attributes['capital_string_both'] = "CAPITAL: $value";
	}

	protected function getLowercaseStringBothAttribute($value)
	{
		return "lowercase: $value";
	}

	protected static function bootSetupHasAttributeEvents()
	{
		static::created(function($model) {
			$model->_settingAttributeCalled = false;
			$model->_settingAttributeKey = null;
			$model->_settingAttributeValue = null;
			$model->_didSetAttributeCalled = false;
			$model->_didSetAttributeKey = null;
			$model->_didSetAttributeValue = null;
			$model->_gettingAttributeCalled = false;
			$model->_gettingAttributeKey = null;
			$model->_didGetAttributeCalled = false;
			$model->_didGetAttributeKey = null;
		});

		static::settingAttribute(function($model, $key, $value) {
			$model->_settingAttributeCalled = true;
			$model->_settingAttributeKey = $key;
			$model->_settingAttributeValue = $value;
		});

		static::didSetAttribute(function($model, $key, $value) {
			$model->_didSetAttributeCalled = true;
			$model->_didSetAttributeKey = $key;
			$model->_didSetAttributeValue = $value;
		});

		static::gettingAttribute(function($model, $key) {
			$model->_gettingAttributeCalled = true;
			$model->_gettingAttributeKey = $key;
		});

		static::didGetAttribute(function($model, $key) {
			$model->_didGetAttributeCalled = true;
			$model->_didGetAttributeKey = $key;
		});

		static::registerAttributeMutator('capital_string_external', function ($value) {
			return strtoupper($value);
		});

		static::registerAttributeAccessor('lowercase_string_external', function ($value) {
			return strtolower($value);
		});

		static::registerAttributeMutator('capital_string_both', function ($value) {
			return strtoupper($value);
		});

		static::registerAttributeAccessor('lowercase_string_both', function ($value) {
			return strtolower($value);
		});
	}
}