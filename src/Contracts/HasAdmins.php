<?php

namespace Helium\LaravelHelpers\Contracts;

interface HasAdmins
{
	/**
	 * @description Determines whether the current instance is an admin
	 * @return bool
	 */
	public function isAdmin(): bool;
}