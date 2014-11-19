oauth-validator-php
===================
*A library for validating OAuth signatures in PHP.*

Copyright (C) 2014 Jublo Solutions <support@jublo.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

### Requirements

- PHP 5.3.0 or higher


## Validating an OAuth signature

To validate an OAuth signature, provide the consumer key and secret,
as well as the token.

```php
require_once 'oauth-validator.php';

\Jublo\Oauth_Validator::setConsumerKey('******', '******');
$ov = \Jublo\Oauth_Validator::getInstance();
$ov->setToken("******", "******");

$params = array(
    'status' => 'Hashtags are cool, when they work. http://www.example.com/gear#id=3&type=store'
);

$authorization = 'OAuth oauth_consumer_key="******", oauth_nonce="6f8b2bc8", oauth_signature="DRicJWVJQFOxdnRgh7hsyvqd8sQ%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1416406562", oauth_token="******", oauth_version="1.0"';

$reply = $ov->validate($authorization, 'POST', 'https://api.twitter.com/1.1/statuses/update.json', $params);
var_dump($reply);
```
