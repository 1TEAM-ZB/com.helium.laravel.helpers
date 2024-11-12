<?php

namespace Helium\LaravelHelpers\Handlers;

use Helium\LaravelHelpers\Exceptions\ApiException;
use Helium\LaravelHelpers\Exceptions\InternalServerException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Http\Response;
use Illuminate\Validation\UnauthorizedException;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Throwable;
use Illuminate\Support\Arr;
use Illuminate\Http\JsonResponse; // Ensure this import is here


class ApiExceptionHandler extends Handler
{
    
    protected $excludeKeys = ['APP_KEY', 'DB_PASSWORD', 'API_SECRET']; // Add sensitive keys here

    protected function reportThrowable(Throwable $e): void
    {
        \Log::info("In Api Exception Handler...");
    }
    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Throwable  $e
     * @return \Illuminate\Http\JsonResponse
     */
    public function render($request, Throwable $e)
    {
        // echo 1;die;
        \Log::info("Handling exception in ApiExceptionHandler...");

        // Transform specific exceptions if necessary
        if ($e instanceof ValidationException) {
            $e = new HeliumValidationException($e);
        }

        // Determine HTTP status code based on exception type
        $statusCode = $this->getStatusCode($e);

        // Prepare error message and details, removing sensitive strings if detected
		$errors_message = $this->sanitizeMessage($e->getMessage());
        $errors = config('app.debug') ? $this->excludeKeys($e->getTrace(), $this->excludeKeys) : [];

        // Determine if we should show a generic error message
        if(in_array(env('APP_ENV'), ['production','staging']) && $statusCode == 500) {
            $responseMessage = 'Something went wrong';
        } else{
            $responseMessage = $errors_message;
        }
       
        // Log sanitized exception details
        \Log::error("Exception encountered:", $this->sanitizeExceptionLog([
            'exception' => get_class($e),
            'message' => $errors_message,
            'trace' => $e->getTraceAsString(),
        ]));

        // Return the JSON response in the specified format
        return response()->json([
            'status' => false,
			'code' => $statusCode,
            'message' => $responseMessage,
            'errors' => $errors,
        ], $statusCode);
    }
    
    /**
     * Get the appropriate HTTP status code for the exception.
     */
    protected function getStatusCode(Throwable $e): int
    {
        return match (true) {
            $e instanceof HttpException => $e->getStatusCode(),
            $e instanceof AuthenticationException, $e instanceof AuthorizationException, $e instanceof UnauthorizedException => Response::HTTP_UNAUTHORIZED,
            $e instanceof ModelNotFoundException => Response::HTTP_NOT_FOUND,
            $e instanceof ApiException => $e->httpStatusCode,
            default => Response::HTTP_INTERNAL_SERVER_ERROR,
        };
    }

    /**
     * Recursively remove specified keys from an array.
     *
     * @param array $array
     * @param array $keys
     * @return array
     */
    private function excludeKeys(array $array, array $keys): array
    {
        foreach ($keys as $key) {
            if (array_key_exists($key, $array)) {
                unset($array[$key]);
            }
        }

        foreach ($array as $k => &$value) {
            if (is_array($value)) {
                $value = $this->excludeKeys($value, $keys);
            }
        }

        return $array;
    }

    /**
     * Sanitize exception details to exclude sensitive information from logs.
     */
    protected function sanitizeExceptionLog(array $logData): array
    {
        return Arr::except($logData, $this->excludeKeys);
    }

    /**
     * Sanitize the exception message to exclude base64-encoded strings.
     *
     * @param string $message
     * @return string
     */
    private function sanitizeMessage(string $message): string
    {
        // Detect and replace sensitive string
        $patterns = config('redaction.patterns');
        foreach ($patterns as $pattern => $replacement) {
            $message = preg_replace($pattern, $replacement, $message);
        }
    
        return $message;
    }
}
