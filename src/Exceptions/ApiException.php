<?php

namespace Helium\LaravelHelpers\Exceptions;

use Exception;
use Throwable;

class ApiException extends Exception
{
	public $httpStatusCode;

	public function __construct(string $message = "", int $httpStatusCode = 500,
		Throwable $previous = null)
	{
		$this->httpStatusCode = $httpStatusCode;
		parent::__construct($message, 0, $previous);

		//TODO: I18n translate message automatically
	}
}