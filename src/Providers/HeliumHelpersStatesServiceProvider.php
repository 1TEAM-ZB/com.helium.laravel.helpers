<?php

namespace Helium\LaravelHelpers\Providers;

use Helium\LaravelHelpers\Middleware\CastCamelToSnake;
use Illuminate\Support\ServiceProvider;

class HeliumHelpersStatesServiceProvider extends ServiceProvider
{
	public function boot()
	{
		$this->loadMigrationsFrom(__DIR__ . '/../Database/migrations/States');

		$this->publishes([
            __DIR__ . '/../Database/migrations/States' => database_path('migrations'),
            __DIR__ . '/../Database/data/States' => database_path('data'),
            __DIR__ . '/../Database/Seeds/States' => database_path('seeds'),
		]);
	}
}