<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateHasAttributeEventsModelsTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('has_attribute_events_models', function (Blueprint $table) {
            $table->id();
            $table->timestamps();
            $table->string('string');
	        $table->string('capital_string_internal');
	        $table->string('lowercase_string_internal');
	        $table->string('capital_string_external');
	        $table->string('lowercase_string_external');
	        $table->string('capital_string_both');
	        $table->string('lowercase_string_both');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('has_attribute_events_models');
    }
}
