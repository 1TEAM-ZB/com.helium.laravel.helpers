<?php

namespace Tests\Tests\Helpers;

use Helium\LaravelHelpers\Helpers\PolicyHelper;
use Illuminate\Support\Facades\Auth;
use Tests\Models\HasAdminsModel;
use Tests\TestCase;

class PolicyHelperTest extends TestCase
{
	protected const TEST_CLASS = HasAdminsModel::class;

	protected function getUser($args = [])
	{
		$user = factory(self::TEST_CLASS)->create($args);

		$this->be($user);

		return $user;
	}

	public function testIsAdmin()
	{
		$user = $this->getUser(['admin' => true]);

		$this->assertEquals($user->isAdmin(), PolicyHelper::isAdmin());

		$user = $this->getUser(['admin' => false]);

		$this->assertEquals($user->isAdmin(), PolicyHelper::isAdmin());
	}

	public function testIsSelf()
	{
		$user1 = $this->getUser();

		$this->assertTrue(PolicyHelper::isSelf($user1));

		$user2 = $this->getUser();

		$this->assertFalse(PolicyHelper::isSelf($user1));
	}

	public function testIsAdminOrSelf()
	{
		$user1 = $this->getUser();
		$user2 = $this->getUser(['admin' => false]);

		$this->assertFalse(PolicyHelper::isAdminOrSelf($user1));
		$this->assertTrue(PolicyHelper::isAdminOrSelf($user2));

		$user1 = $this->getUser();
		$user2 = $this->getUser(['admin' => true]);

		$this->assertTrue(PolicyHelper::isAdminOrSelf($user1));
		$this->assertTrue(PolicyHelper::isAdminOrSelf($user2));
	}
}