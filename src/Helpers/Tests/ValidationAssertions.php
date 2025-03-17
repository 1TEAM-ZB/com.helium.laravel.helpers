<?php

namespace Helium\LaravelHelpers\Helpers\Tests;

use Carbon\Carbon;
use Carbon\Exceptions\InvalidFormatException;
use Exception;
use Helium\LaravelHelpers\Exceptions\EnumException;
use Helium\LaravelHelpers\Exceptions\ValidationException;
use Helium\LaravelHelpers\Helpers\StringHelper;
use Illuminate\Database\Eloquent\Builder;
use Tests\TestCase;

/**
 * @mixin TestCase
 */
trait ValidationAssertions
{
    /**
     * @description Test that object creation produces validation errors
     * @param string $class The class being tested
     * @param array $attributes The array of attributes to use on create
     * @param int $expectedErrors Number of expected validation errors
     * @return ValidationException|null The exception object, in case the
     * developer wants to run additional assertions on the contents of the exception
     */
    public function assertHasValidationErrors(
        string $class,
        array $attributes,
        int $expectedErrors): ?ValidationException
    {
        try {
            /** @var Builder $class */
            $model = factory($class)->make($attributes);
            $model->save();
            self::assertEquals($expectedErrors, 0);
        } catch (ValidationException $e) {
            $allErrors = [];

            foreach ($e->toArray() as $key => $errors)
            {
                $allErrors = array_merge($allErrors, $errors);
            }

            self::assertCount($expectedErrors, $allErrors, implode(PHP_EOL,
                $allErrors));

            return $e;
        }

        return null;
    }

    /**
     * @description Test that the specified attribute is validated as nullable
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeNullable(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw();
        unset($attributes[$attribute]);

        $this->assertHasValidationErrors($class, $attributes, 0);
    }

    /**
     * @description Test that the specified attribute is validated as required
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeRequired(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw();
        $attributes[$attribute] = null;

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as required
     * with a specified list of other fields
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     * @param array $others The dependent required fields
     */
    public function assertAttributeRequiredWith(string $class, string $attribute,
                                                array $others): void
    {
        $attributes = factory($class)->raw();

        //All others present
        unset($attributes[$attribute]);

        $this->assertHasValidationErrors($class, $attributes, 1);

        if (count($others) > 1)
        {
	        //Some others not present
	        $firstOther = $others[0];
	        unset($attributes[$firstOther]);

	        $this->assertHasValidationErrors($class, $attributes, 2);
        }

        //All others not present
        foreach ($others as $other)
        {
            unset($attributes[$other]);
        }

        $this->assertHasValidationErrors($class, $attributes, 0);
    }

    /**
     * @description Test that the specified attribute is validated as a foreign
     * key which exists on another table
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     * @param string $otherClass The related class
     */
    public function assertAttributeExists(string $class,
        string $attribute,
        string $otherClass): void
    {
        $otherInstance = factory($otherClass)->create();
        $key = $otherInstance->getKey();

        $otherInstance->forceDelete();

        $attributes = factory($class)->raw([
            $attribute => $key
        ]);

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as unique,
     * except for itself
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeUniqueExceptSelf(string $class,
                                                    string $attribute): void
    {
        $instance = factory($class)->create();

        //Test that saving does not throw ValidationException
        //This would happen if the column is simply marked as unique, without excluding itself
        $instance->save();

        $attributes = factory($class)->raw([
            $attribute => $instance->$attribute
        ]);

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as a boolean
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeBool(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw([
            $attribute => 'abc'
        ]);

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as a string
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeString(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw([
            $attribute => 123
         ]);

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    public function assertAttributeStringFormat(string $class,
                                                string $attribute): void
    {
        $attributes = factory($class)->raw([
            $attribute => 123
        ]);

        $this->assertHasValidationErrors($class, $attributes, 2);
    }

    /**
     * @description Test that the specified attribute is validated as an enum value
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     * @throws Exception
     */
    public function assertAttributeEnum(string $class, string $attribute): void
    {
        try
        {
            $model = factory($class)->create([
                $attribute => 'not an enum value'
            ]);

            $this->assertTrue(false);
        }
        catch (Exception $e)
        {
            if (!($e instanceof EnumException))
            {
                throw $e;
            }

            $this->assertTrue(true);
        }
    }

    /**
     * @description Test that the specified attribute is validated as an email
     * formatted string
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeEmail(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw();

        //test string
        $attributes[$attribute] = 1;
        $this->assertHasValidationErrors($class, $attributes, 1);

        //test email format
        $attributes[$attribute] = 'abc';
        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as numeric
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeNumeric(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw([
            $attribute => 'abc123'
        ]);

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as integer
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     */
    public function assertAttributeInteger(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw([
            $attribute => 3.14
        ]);

        $this->assertHasValidationErrors($class, $attributes, 1);
    }

    /**
     * @description Test that the specified attribute is validated as date
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     * @throws Exception
     */
    public function assertAttributeDate(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw([
            $attribute => 'Not a date'
        ]);

        try {
            //Test validation only (ie model does not cast dates)
            $this->assertHasValidationErrors($class, $attributes, 1);
        } catch (Exception $exception) {
            if (!($exception instanceof InvalidFormatException))
            {
                throw $exception;
            }

            $this->assertTrue(true);
        }
    }

    /**
     * @description Test that the specified attribute is validated as after or
     * equal to another date attribute
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     * @param string $otherAttribute The attribute being compared
     */
    public function assertAttributeAfter(string $class,
        string $attribute,
        string $otherAttribute): void
    {
        $attributes = factory($class)->raw();

        $attributes[$otherAttribute] = Carbon::today();
        $attributes[$attribute] = Carbon::yesterday();
        $this->assertHasValidationErrors($class, $attributes, 1);

        $attributes[$otherAttribute] = Carbon::today();
        $attributes[$attribute] = Carbon::today();
        $this->assertHasValidationErrors($class, $attributes, 1);

        $attributes[$otherAttribute] = Carbon::yesterday();
        $attributes[$attribute] = Carbon::today();
        $this->assertHasValidationErrors($class, $attributes, 0);
    }

    /**
     * @description Test that the specified attribute is validated as after or
     * equal to another date attribute
     * @param string $class The class being tested
     * @param string $attribute The attribute being tested
     * @param string $otherAttribute The attribute being compared
     */
    public function assertAttributeAfterOrEqual(string $class,
        string $attribute,
        string $otherAttribute): void
    {
        $attributes = factory($class)->raw();

        $attributes[$otherAttribute] = Carbon::today();
        $attributes[$attribute] = Carbon::yesterday();
        $this->assertHasValidationErrors($class, $attributes, 1);

        $attributes[$otherAttribute] = Carbon::today();
        $attributes[$attribute] = Carbon::today();
        $this->assertHasValidationErrors($class, $attributes, 0);

        $attributes[$otherAttribute] = Carbon::yesterday();
        $attributes[$attribute] = Carbon::today();
        $this->assertHasValidationErrors($class, $attributes, 0);
    }

	/**
	 * @description Test that the specified attribute is validated as min
	 * @param string $class The class being tested
	 * @param string $attribute The attribute being tested
     * @param int $size The min size of the field
	 */
	public function assertAttributeMin(string $class,
        string $attribute,
		int $size): void
	{
		$attributes = factory($class)->raw();

		if (is_string($attributes[$attribute]))
		{
			$attributes[$attribute] = StringHelper::randomToken(
				['a', 'b', 'c'],
				$size - 1
			);
		}
		else
		{
			$attributes[$attribute] = $size - 1;
		}

		$this->assertHasValidationErrors($class, $attributes, 1);
	}

	/**
	 * @description Test that the specified attribute is validated as max
	 * @param string $class The class being tested
	 * @param string $attribute The attribute being tested
     * @param int $size The maximum size of the field
	 */
	public function assertAttributeMax(string $class,
        string $attribute,
		int $size): void
	{
		$attributes = factory($class)->raw();

		if (is_string($attributes[$attribute]))
		{
			$attributes[$attribute] = StringHelper::randomToken(
				['a', 'b', 'c'],
				$size + 1
			);
		}
		else
		{
			$attributes[$attribute] = $size + 1;
		}

		$this->assertHasValidationErrors($class, $attributes, 1);
	}

	/**
	 * @description Test that the specified attribute is validated as array
	 * @param string $class The class being tested
	 * @param string $attribute The attribute being tested
	 */
    public function assertAttributeArray(string $class, string $attribute): void
    {
	    $attributes = factory($class)->raw();

	    $attributes[$attribute] = 'abc';

	    $this->assertHasValidationErrors($class, $attributes, 1);
    }

    public function assertAttributeJson(string $class, string $attribute): void
    {
        $attributes = factory($class)->raw();

        $attributes[$attribute] = 'not json';

        $this->assertHasValidationErrors($class, $attributes, 1);
    }
}
