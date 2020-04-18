<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateTestSelfValidatesModelsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('test_self_validates_models', function (Blueprint $table) {
            $table->id();
            $table->timestamps();
            $table->string('string');
            $table->integer('int');
            $table->boolean('bool');
            $table->string('foreign_key');

            $table->foreign('foreign_key')
	            ->references('id')
	            ->on('test_generates_primary_key_models');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('test_self_validates_models');
    }
}
