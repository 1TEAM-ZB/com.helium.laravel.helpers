<?php

namespace Helium\LaravelHelpers\Resources;

use Helium\LaravelHelpers\Exceptions\ValidationException;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @property \Throwable $resource
 */
class ApiErrorResource extends JsonResource
{
	public function __construct($resource)
	{
		parent::__construct($resource);

		self::withoutWrapping();
	}

	public function toArray($request)
	{
		$data = [
			'message' => $this->resource->getMessage()
		];

		$debug = config('app.debug', false);

		if (method_exists($this->resource, 'toArray'))
		{
			$data['messages'] = $this->resource->toArray($debug);
			$data['errors'] = $data['messages'];
		}

		if ($debug)
		{
			$data['exception_class'] = get_class($this->resource);
			$data['stack_trace'] = $this->resource->getTrace();
		}

		return $data;
	}
}