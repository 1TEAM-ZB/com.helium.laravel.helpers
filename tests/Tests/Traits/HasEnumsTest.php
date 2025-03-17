<?php

namespace Tests\Tests\Traits;

use Helium\LaravelHelpers\Exceptions\EnumException;
use Tests\Enums\Color;
use Tests\Models\HasEnumsModel;
use Tests\TestCase;

class HasEnumsTest extends TestCase
{
	protected const TEST_CLASS = HasEnumsModel::class;

	protected const FAVORITE_COLOR_DEFAULT = Color::PURPLE;
	protected const FAVORITE_PRIMARY_COLOR_DEFAULT = Color::BLUE;

	protected function getInstance()
	{
		return factory(self::TEST_CLASS)->create([
			'favorite_color' => self::FAVORITE_COLOR_DEFAULT,
			'favorite_primary_color' => self::FAVORITE_PRIMARY_COLOR_DEFAULT
		]);
	}

	public function testIsEnum()
	{
		$model = $this->getInstance();

		$this->assertTrue($model->isEnum('favorite_color'));
		$this->assertTrue($model->isEnum('favorite_primary_color'));
		$this->assertFalse($model->isEnum('some_attribute'));
	}

	public function testValidateEnumClass()
	{
		$model = $this->getInstance();

		$model->validateEnum('favorite_color', self::FAVORITE_COLOR_DEFAULT);

		$this->assertThrowsException(function() use ($model) {
			$model->validateEnum('favorite_color', 'NotAColor');
		}, EnumException::class);
	}

	public function testValidateEnumArray()
	{
		$model = $this->getInstance();

		$model->validateEnum('favorite_primary_color', self::FAVORITE_PRIMARY_COLOR_DEFAULT);

		$this->assertThrowsException(function() use ($model) {
			$model->validateEnum('favorite_primary_color', self::FAVORITE_COLOR_DEFAULT);
		}, EnumException::class);
	}

	public function testCreateEnumAttribute()
	{
		$model = $this->getInstance();

		/**
		 * Test that value constrained by enum class successfully set
		 */
		$this->assertEquals($model->favorite_color, self::FAVORITE_COLOR_DEFAULT);

		/**
		 * Test that value constrained by array successfully set
		 */
		$this->assertEquals($model->favorite_primary_color, self::FAVORITE_PRIMARY_COLOR_DEFAULT);
	}

	public function testCreateInvalidEnumAttribute()
	{
		/**
		 * Test that value constrained by enum class successfully rejects
		 */
		$this->assertThrowsException(function() {
			factory(HasEnumsModel::class)->create([
				'favorite_color' => 'NotAColor'
			]);
		}, EnumException::class);

		/**
		 * Test that value constrained by array successfully rejects
		 */
		$this->assertThrowsException(function() {
			factory(HasEnumsModel::class)->create([
				'favorite_primary_color' => Color::PURPLE //Not in Color::PRIMARY
			]);
		}, EnumException::class);
	}

	public function testUpdateEnumAttribute()
	{
		$model = $this->getInstance();

		/**
		 * Test that value constrained by enum class successfully set via update
		 */
		$newFavoriteColor = Color::GREEN;

		$model->update([
			'favorite_color' => $newFavoriteColor
		]);

		$this->assertEquals($model->favorite_color, $newFavoriteColor);

		/**
		 * Test that value constrained by enum class successfully set via set attribute
		 */
		$newFavoriteColor = Color::ORANGE;

		$model->favorite_color = $newFavoriteColor;

		$this->assertEquals($model->favorite_color, $newFavoriteColor);

		/**
		 * Test that value constrained by array successfully set via update
		 */
		$newFavoritePrimaryColor = Color::RED;

		$model->update([
			'favorite_primary_color' => $newFavoritePrimaryColor
		]);

		$this->assertEquals($model->favorite_primary_color, $newFavoritePrimaryColor);

		/**
		 * Test that value constrained by array successfully set via set attribute
		 */
		$newFavoritePrimaryColor = Color::YELLOW;

		$model->favorite_primary_color = $newFavoritePrimaryColor;

		$this->assertEquals($model->favorite_primary_color, $newFavoritePrimaryColor);
	}

	public function testUpdateInvalidEnumAttribute()
	{
		/**
		 * Test that value constrained by enum class successfully rejects via update
		 */
		$this->assertThrowsException(function() {
			$model = $this->getInstance();
			
			$model->update([
				'favorite_color' => 'NotAColor'
			]);
		}, EnumException::class);

		/**
		 * Test that value constrained by enum class successfully rejects via set attribute
		 */
		$this->assertThrowsException(function() {
			$model = $this->getInstance();

			$model->favorite_color = 'NotAColor';
		}, EnumException::class);
		
		/**
		 * Test that value constrained by array successfully rejects via update
		 */
		$this->assertThrowsException(function() {
			$model = $this->getInstance();

			$model->update([
				'favorite_primary_color' => Color::PURPLE //Not in Color::PRIMARY
			]);
		}, EnumException::class);

		/**
		 * Test that value constrained by array successfully rejects via set attribute
		 */
		$this->assertThrowsException(function() {
			$model = $this->getInstance();

			$model->favorite_primary_color = Color::PURPLE; //Not in Color::PRIMARY
		}, EnumException::class);
	}
}