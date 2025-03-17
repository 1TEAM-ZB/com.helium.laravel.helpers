<?php

namespace Tests\Models\Base;

trait SetupSelfValidates2
{
	public function validatesOnSave() {
		return false;
	}

	public function validationRules() {
		return [
			'string' => 'required|string',
			'int' => 'required|integer',
			'bool' => 'required|boolean',
			'foreign_key' => 'required|exists:generates_primary_key_models,id'
		];
	}

	public function validationMessages() {
		return [
			'string.required' => 'string required',
			'string.string' => 'string string',
			'int.required' => 'int required',
			'int.integer' => 'int integer',
			'bool.required' => 'bool required',
			'bool.boolean' => 'bool boolean',
			'foreign_key.required' => 'foreign_key required',
			'foregin_key.exists' => 'foreign_key exists'
		];;
	}
}