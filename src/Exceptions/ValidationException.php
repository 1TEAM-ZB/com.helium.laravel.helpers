<?php

namespace Helium\LaravelHelpers\Exceptions;

use Illuminate\Support\Collection;
use Illuminate\Validation\ValidationException as IlluminateValidationException;

class ValidationException extends ApiException
{
    protected $attributes = [];
	protected $errors = [];

	public function __construct(IlluminateValidationException $previous, ?array $attributes = [])
	{
		$this->attributes = $attributes ?? $previous->validator->getData();
		$this->errors = $previous->validator->errors()->toArray();

		$debug = config('app.debug', false);
		$messages = array_map(function ($errors) {
			return implode(PHP_EOL, $errors);
		}, $this->toArray($debug));
		$message = implode(PHP_EOL, $messages);

		parent::__construct($message, 400, $previous);
	}

	/**
	 * @description Get all validation errors as an Array
	 * @return array
	 */
	public function toArray($debug = false): array
	{
		if ($debug)
		{
			$errorMessages = [];

			foreach ($this->errors as $key => $errors) {
                $value = $this->attributes[$key] ?? 'null';
                if (is_array($value)) {
                    $value = '(array)';
                }

				$errorMessages[$key] = array_map(function ($error) use ($key, $value) {
					return "{$error} (got value: {$value})";
				}, $errors);
			}

			return $errorMessages;
		}

		return $this->errors;
	}
}