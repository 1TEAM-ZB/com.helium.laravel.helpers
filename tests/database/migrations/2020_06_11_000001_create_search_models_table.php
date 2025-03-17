<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateSearchModelsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('search_models', function (Blueprint
        $table) {
	        $table->id('id');
	        $table->timestamps();
	        $table->integer('age');
	        $table->unsignedBigInteger('parent_id')->nullable();

	        $table->foreign('parent_id')
                ->references('id')
                ->on('search_models');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('search_models');
    }
}
