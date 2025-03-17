<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateFillableOnCreateModelsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('fillable_on_create_models', function (Blueprint $table) {
	        $table->id('id');
	        $table->timestamps();
	        $table->string('not_fillable_attribute');
	        $table->string('fillable_attribute');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('fillable_on_create_models');
    }
}
