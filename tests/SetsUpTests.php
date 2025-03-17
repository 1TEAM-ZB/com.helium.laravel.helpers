<?php

namespace Tests;

use Helium\LaravelHelpers\Providers\HeliumHelpersServiceProvider;

trait SetsUpTests
{
	protected function setUp(): void
	{
		parent::setUp();

		$this->withFactories(__DIR__ . '/database/factories');
		$this->loadMigrationsFrom(__DIR__ . '/../src/Database/migrations');
		$this->loadMigrationsFrom(__DIR__ . '/database/migrations');
	}

	protected function getPackageProviders($app)
	{
		return [
			HeliumHelpersServiceProvider::class
		];
	}

	protected function getEnvironmentSetUp($app)
	{
		// Setup default database to use sqlite :memory:
		$app['config']->set('database.default', 'testbench');
		$app['config']->set('database.connections.testbench', [
			'driver'   => 'sqlite',
			'database' => ':memory:',
			'prefix'   => '',
		]);
	}
}