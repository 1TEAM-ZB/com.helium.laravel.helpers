<?php

namespace Helium\LaravelHelpers\Helpers\Tests;

use Dotenv\Dotenv;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class TestSetupHelper
{
    protected static $isSetUp;

    public static function setup(): void
    {
        static::loadEnv();

        static::once(function () {
            static::migrateDatabase();
        });

        Mailhog::client()->purgeMessages();

        static::truncateDatabase();

        static::seedDatabase();
    }

    public static function once(callable $callback): void
    {
        if (!self::$isSetUp) {
            self::$isSetUp = true;

            $callback();
        }
    }

    public static function loadEnv(string $name = 'testing'): void
    {
        $suffix = empty($name) ? '' : ".$name";
        $envFile = '.env' . $suffix;

        $env = Dotenv::createMutable(base_path(), $envFile);
        $env->load();
    }

    public static function migrateDatabase(): void
    {
        println('Migrating database...');
        Artisan::call('migrate:fresh');
        println('Finished migrating.');
    }

    public static function seedDatabase(string $class = 'TestSeeder'): void
    {
        Artisan::call('db:seed', [
            '--class' => 'TestSeeder'
        ]);
    }

    protected static function truncateDatabase(): void
    {
        Schema::disableForeignKeyConstraints();

        $tableNames = Schema::getConnection()->getDoctrineSchemaManager()->listTableNames();
        $tableNames[] = 'one_time_seeds';

        foreach ($tableNames as $name) {
            if ($name != 'migrations') {
                DB::table($name)->truncate();
            }
        }

        Schema::enableForeignKeyConstraints();
    }

    public static function deleteStripeCustomers(string $class, string $stripeIdColumn = 'stripe_id'): void
    {
        $customers = $class::where($stripeIdColumn, 'like', 'cus_%')->get();

        foreach ($customers as $customer) {
            try {
                $customer->asStripeCustomer()->delete();
            } catch (\Exception $e) {
                continue;
            }
        }
    }
}
