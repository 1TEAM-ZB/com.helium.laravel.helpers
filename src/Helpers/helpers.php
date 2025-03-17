<?php

function println(...$args)
{
	$output = implode(PHP_EOL, $args);

	echo $output . PHP_EOL;

	if (ob_get_level() > 0) {
		ob_flush();
	}
}