<?php

namespace Helium\LaravelHelpers\Traits;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException as IlluminateValidationException;
use Helium\LaravelHelpers\Exceptions\ValidationException as HeliumValidationException;

trait SelfValidates
{
	protected $_preLoadedRelations;

	//region Helpers
	/**
	 * @description Get the model validation rules
	 * @return array
	 */
	public function getValidationRules(): array
	{
		if (method_exists($this, 'validationRules')) {
			return $this->validationRules();
		} else {
			return $this->validationRules ?? [];
		}
	}

	/**
	 * @description Get model validation messages
	 * @return array
	 */
	public function getValidationMessages(): array
	{
		if (method_exists($this, 'validationMessages')) {
			return $this->validationMessages();
		} else {
			return $this->validationMessages ?? [];
		}
	}

	/**
	 * @description Determine whether the model should validate automatically on save
	 * @return bool
	 */
	public function getValidatesOnSave(): bool
	{
		if (method_exists($this, 'validatesOnSave')) {
			return $this->validatesOnSave();
		} else {
			return $this->validatesOnSave ?? true;
		}
	}
	//endregion

	//region Functions
	/**
	 * @description Validate model on save if enabled
	 */
	public static function bootSelfValidates()
	{
		self::saving(function (Model $model) {
		    /** @var SelfValidates $model */
			if ($model->getValidatesOnSave())
			{
				$model->validate();
			}
		});
	}

    /**
     * Copied and modified from attributesToArray to include all attributes
     * @return array
     */
	public function allAttributesToArray(): array
    {
        $attributes = $this->addDateAttributesToArray(
            $attributes = $this->getAttributes()
        );

        $attributes = $this->addMutatedAttributesToArray(
            $attributes, $mutatedAttributes = $this->getMutatedAttributes()
        );

        $attributes = $this->addCastAttributesToArray(
            $attributes, $mutatedAttributes
        );

        foreach ($this->appends ?? [] as $key) {
            $attributes[$key] = $this->mutateAttributeForArray($key, null);
        }

        return $attributes;
    }

	/**
	 * @description Perform attribute and relationship validation on the model
	 * @return array
	 * @throws HeliumValidationException
	 */
	public function validate(): array
	{
		$rules = $this->getValidationRules();
		$messages = $this->getValidationMessages();

		$v = Validator::make($this->allAttributesToArray(), $rules, $messages);

		try {
			//Execute validation, which may throw a
			//Illuminate\Validation\ValidationException
			return $v->validate();
		} catch (IlluminateValidationException $e) {
			//If validation fails, re-wrap the exception as a custom
			//Helium\LaravelHelpers\Exceptions\ValidationException,
			//which is more readable than the native
			//Illuminate\Validation\ValidationException
			throw new HeliumValidationException($e, $this->allAttributesToArray());
		}
	}

	public function validateAttribute(string $attribute) {
        $rules = array_filter($this->getValidationRules(), function($key) use ($attribute) {
            return $key == $attribute;
        }, ARRAY_FILTER_USE_KEY);
        $messages = array_filter($this->getValidationMessages(), function($key) use ($attribute) {
            return $key == $attribute;
        }, ARRAY_FILTER_USE_KEY);

        $v = Validator::make($this->allAttributesToArray(), $rules, $messages);

        try {
            //Execute validation, which may throw a
            //Illuminate\Validation\ValidationException
            return $v->validate();
        } catch (IlluminateValidationException $e) {
            //If validation fails, re-wrap the exception as a custom
            //Helium\LaravelHelpers\Exceptions\ValidationException,
            //which is more readable than the native
            //Illuminate\Validation\ValidationException
            throw new HeliumValidationException($e, $this->allAttributesToArray());
        }
    }
	//endregion
}