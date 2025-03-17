<?php

use Helium\LaravelHelpers\Database\Seeds\Base\OneTimeSeeder;
use Illuminate\Support\Facades\DB;

class StatesSeeder extends OneTimeSeeder
{
    public function run()
    {
        $json = file_get_contents(__DIR__ . '/../data/states.json');
        $data = json_decode($json, true);

        foreach ($data as $key => $value) {
            DB::table('states')->insert([
                'id' => $key,
                'iso_3166_2' => $value['iso_3166_2'],
                'name' => $value['name'],
                'country_code' => $value['country_code']
            ]);
        }
    }
}