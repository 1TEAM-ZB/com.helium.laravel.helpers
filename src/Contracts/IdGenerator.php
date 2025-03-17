<?php

namespace Helium\LaravelHelpers\Contracts;

abstract class IdGenerator
{
	/**
	 * @description Generate a string value for the model primary key
	 * @return string
	 */
	public abstract function generate(): string;
}