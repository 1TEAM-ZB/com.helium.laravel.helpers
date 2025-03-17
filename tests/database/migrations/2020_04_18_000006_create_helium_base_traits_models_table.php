<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateHeliumBaseTraitsModelsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('helium_base_traits_models', function (Blueprint $table) {
	        $table->string('id')->primary();
	        $table->timestamps();
	        $table->string('favorite_color');
	        $table->string('favorite_primary_color');
	        $table->string('string');
	        $table->integer('int');
	        $table->boolean('bool');
	        $table->string('foreign_key');
	        $table->string('capital_string');
	        $table->string('lowercase_string');

	        $table->foreign('foreign_key')
		        ->references('id')
		        ->on('generates_primary_key_models');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('helium_base_traits_models');
    }
}
