<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateHasPhoneNumbersModelsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('has_phone_numbers_models', function (Blueprint
        $table) {
	        $table->id('id');
	        $table->timestamps();
	        $table->string('phone');
	        $table->string('phone_custom');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('has_phone_numbers_models');
    }
}
