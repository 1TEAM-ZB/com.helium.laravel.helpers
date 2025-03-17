<?php

namespace Helium\LaravelHelpers\Providers;

use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;

class HeliumHelpersValidationServiceProvider extends ServiceProvider
{
	public function boot()
	{
		Validator::extend('equals', function ($attribute, $value, $parameters, $validator) {
		    return $value == $parameters[0];
        });
	}
}