<?php

namespace Helium\LaravelHelpers\Providers;

use Helium\LaravelHelpers\Middleware\CastCamelToSnake;
use Illuminate\Support\ServiceProvider;

class HeliumHelpersServiceProvider extends ServiceProvider
{
	public function boot()
	{
		$this->loadTranslationsFrom(__DIR__ . '/../lang/', 'heliumHelpers');
		$this->loadMigrationsFrom(__DIR__ . '/../Database/migrations/Common');

		$this->publishes([
			__DIR__ . '/../lang/' => resource_path('lang/vendor/heliumHelpers'),
			__DIR__ . '/../config/batch.php' => config_path('batch.php'),
            __DIR__ . '/../Database/migrations/Common' => database_path('migrations')
		]);

		if ($this->app->runningInConsole())
		{
			$this->commands([
			]);
		}
	}

	public function register()
    {
        app('router')->aliasMiddleware('camelCase', CastCamelToSnake::class);
    }
}