<?php

namespace Helium\LaravelHelpers\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Router;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

/**
 * When used, this trait will automatically intercept all response objects as they return
 * from the controller function you implement. If that response object is set to eventually
 * return as JSON, all keys will be converted to camelCase (e.g. "some_attribute" -> "someAttribute")
 * Upon conflict when both camelCase and snake_case are given for a particular attribute (such as
 * "someAttribute" and "some_attribute"), no change is made for that key.
 * If a key is already given in camelCase, no change is made for that key.
 */
trait RespondCamelCase
{
    /**
     * Laravel function that, when present, is called from the router instead of directly
     * calling the controller method. This function is responsible for forwarding requests
     * to the appropriate controller method, but may also impose custom logic.
     * @param $method
     * @param $parameters
     * @return Response
     */
    public function callAction($method, $parameters)
    {
        return $this->attemptCamelCaseJson($this->{$method}(...array_values($parameters)));
    }

    /**
     * For a given response object, attempt to convert all data keys to camelCase.
     * If the response is not JSON data, then do nothing.
     * @param $rawResponse
     * @return Response
     */
    public function attemptCamelCaseJson($rawResponse): Response
    {
        /**
         * Convert the response (which could be anything) to a Response class object.
         * Router::toResponse will automatically determine whether a given response
         * should be returned as JSON (such as a Model instance), and if so, will return
         * an instance of JsonResponse. Otherwise, a different subclass of Response is
         * returned.
         */
        $response = Router::toResponse(request(), $rawResponse);

        /**
         * If the response should be JSON, overwrite the existing response data with
         * data that uses camelCase for its keys.
         */
        if ($response instanceof JsonResponse)
        {
            $response->setData($this->recursiveCamelKeys($response->getData(true)));
        }

        return $response;
    }

    /**
     * Recursively parse through a data array and modify keys to use camelCase
     * @param mixed $json
     * @return mixed
     */
    protected function recursiveCamelKeys($json)
    {
        /**
         * All recursive functions must have an exit condition. If $json is not
         * an array, then it is a primitive value (string, bool, number, etc), and
         * is simply returned.
         *
         * If it is an array, then attempt to modify all keys to camelCase
         */
        if (is_array($json)) {
            /**
             * Create a new copy of the data
             */
            $newJson = [];

            /**
             * Loop through the existing data
             */
            foreach ($json as $key => $value) {
                /**
                 * Recurse on any sub-arrays
                 */
                $newValue = $this->recursiveCamelKeys($value);

                /**
                 * If the key is a string (ie not an integer) and the camelCase version of
                 * this key is not already set, then add this data to the new array using
                 * the camelCase version of this key.
                 * Otherwise, simply pass this data through to the new array.
                 *
                 * If both camelCase and snake_case for a given name (such as someAttribute
                 * and some_attribute), then both will be in the final array.
                 * If camelCase only is already used for a given name (such as someAttribute),
                 * then it will simply pass through to the final array.
                 */
                if (is_string($key) && !array_key_exists(Str::camel($key), $json)) {
                    $newJson[Str::camel($key)] = $newValue;
                } else {
                    $newJson[$key] = $newValue;
                }
            }

            return $newJson;
        }

        return $json;
    }
}