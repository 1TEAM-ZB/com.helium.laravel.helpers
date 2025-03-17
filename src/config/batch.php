<?php

return [
	'limits' => [
		'data_mb' => env('DB_BATCH_LIMIT_MB', 250),
		'data_rows' => env('DB_BATCH_LIMIT_ROWS', 10000)
	]
];