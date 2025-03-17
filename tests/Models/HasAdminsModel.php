<?php

namespace Tests\Models;

use Helium\LaravelHelpers\Contracts\HasAdmins;
use Illuminate\Foundation\Auth\User;

class HasAdminsModel extends User implements HasAdmins
{
	protected $guarded = [];

	public function isAdmin(): bool
	{
		return $this->admin;
	}
}