<?php

namespace Helium\LaravelHelpers\Helpers;

use Helium\LaravelHelpers\Contracts\HasAdmins;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;

class PolicyHelper
{
	/**
	 * @description Determines whether the current user is the same as the
	 * specified user
	 * @param Authenticatable $user
	 * @return bool
	 */
	public static function isSelf(Authenticatable $user): bool
	{
		return $user->getAuthIdentifier() == Auth::user()->getAuthIdentifier();
	}

	/**
	 * @description Determines whether the current user is an admin
	 * @return bool
	 */
	public static function isAdmin(): bool
	{
		$user = Auth::user();

		if ($user instanceof HasAdmins)
		{
			return $user->isAdmin();
		}

		return false;
	}

	/**
	 * @description Determines whether the current user is an admin or the same as
	 * the specified user
	 * @param $user
	 * @return bool
	 */
	public static function isAdminOrSelf(Authenticatable $user): bool
	{
		return self::isSelf($user) || self::isAdmin();
	}
}