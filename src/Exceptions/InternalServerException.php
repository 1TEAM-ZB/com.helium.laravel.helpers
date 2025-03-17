<?php

namespace Helium\LaravelHelpers\Exceptions;

use Illuminate\Support\Facades\Lang;
use Throwable;

class InternalServerException extends ApiException
{
	public function __construct(Throwable $previous = null)
	{
		$message = Lang::has('error.general') ?
			trans('error.general') : trans('heliumHelpers::error.general');

		parent::__construct($message, 500, $previous);
	}
}