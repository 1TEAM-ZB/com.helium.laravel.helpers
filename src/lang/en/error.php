<?php

return [
	'general' => 'Oops... Something went wrong. Please try again in a few minutes.',
    'password' => [
        'not_contains' => 'The password must not include the pattern ":pattern".',
        'contains' => 'The password must contain the pattern :pattern at least :count times.',
        'length' => 'The password must be at least :minLength characters long.',
        'uppercase' => 'The password must contain at least :count uppercase characters.',
        'lowercase' => 'The password must contain at least :count lowercase characters.',
        'number' => 'The password must contain at least :count numbers.',
        'special' => 'The password must contain at least :count special characters (:characters).',
        'incorrect' => 'Incorrect password.',
        'hashed' => 'The password must not already be hashed.',
        'model' => 'The class :class must be an Eloquent model.',
        'interface' => 'The class :class must implement the PasswordNotifiable interface.',
    ]
];