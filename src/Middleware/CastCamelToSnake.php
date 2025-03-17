<?php

namespace Helium\LaravelHelpers\Middleware;

use Closure;
use Illuminate\Support\Str;

/**
 * This middleware intercepts all incoming requests and creates a snake_case copy
 * of all camelCase keys.
 */
class CastCamelToSnake
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        /**
         * Merge in snake_case copies of all camelCase keys in the request data.
         * If the snake_case version is already present, it will not be overwritten.
         * CamelCase versions are also kept in case the controller is expecting camelCase.
         */
        $request->merge($this->castCamelToSnakeRecursive($request->all()));

        return $next($request);
    }

    protected function castCamelToSnakeRecursive($data)
    {
        /**
         * All recursive functions must have an exit condition. If $data is not
         * an array, then it is a primitive value (string, bool, number, etc), and
         * is simply returned.
         *
         * If it is an array, then attempt to modify all keys to camelCase
         */
        if (is_array($data)) {
            /**
             * Create a new copy of the data
             */
            $newData = [];

            /**
             * Loop through the existing data
             */
            foreach ($data as $key => $value) {
                /**
                 * Recurse on any sub-arrays
                 */
                $newValue = $this->castCamelToSnakeRecursive($value);

                /**
                 * If the key is a string (ie not an integer) and the snake_case version of
                 * this key is not already set, then add this data to the new array using
                 * the snake_case version of this key.
                 *
                 * If the snake_case version of the key is already set, then do nothing.
                 */
                if (is_string($key) && !array_key_exists(Str::snake($key), $data)) {
                    $newData[Str::snake($key)] = $newValue;
                }
            }

            return $newData;
        }

        return $data;
    }
}
