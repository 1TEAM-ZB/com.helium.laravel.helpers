<?php

namespace Helium\LaravelHelpers\Traits;

use Carbon\Carbon;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

trait HandlesPhoto
{
    public function setPhotoUrlAttribute($value)
    {
        $path = Storage::putFile("users/{$this->getKey()}/profile", $value);
        $this->attributes['photo_url'] = $path;
    }

    public function getPhotoUrlAttribute($value)
    {
        if ($savedUrl = $this->attributes['photo_url']) {
            return Storage::temporaryUrl($savedUrl, Carbon::now()->addMinute());
        } elseif (method_exists(get_parent_class($this), 'getPhotoUrlAttribute')) {
            return parent::getPhotoUrlAttribute($value);
        } else {
            return empty($value) ? 'https://www.gravatar.com/avatar/'.md5(Str::lower($this->email)).'.jpg?s=200&d=mm' : url($value);
        }
    }
}