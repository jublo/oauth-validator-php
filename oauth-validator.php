<?php

namespace Jublo;

/**
 * A library for validating OAuth signatures in PHP.
 *
 * @package   oauth-validator
 * @version   1.0.1
 * @author    Jublo Solutions <support@jublo.net>
 * @copyright 2014 Jublo Solutions <support@jublo.net>
 * @license   http://opensource.org/licenses/GPL-3.0 GNU General Public License 3.0
 * @link      https://github.com/jublonet/oauth-validator-php
 */

/**
 * A library for validating OAuth signatures in PHP.
 *
 * @package oauth-validator
 * @subpackage oauth-validator-php
 */
class Oauth_Validator
{
  /**
   * The current singleton instance
   */
  private static $_instance = null;

  /**
   * The OAuth consumer key of your registered app
   */
  protected static $_oauth_consumer_key = null;

  /**
   * The corresponding consumer secret
   */
  protected static $_oauth_consumer_secret = null;

  /**
   * The Request or access token. Used to sign requests
   */
  protected $_oauth_token = null;

  /**
   * The corresponding request or access token secret
   */
  protected $_oauth_token_secret = null;

  /**
   * The current OAuth Validator version
   */
  protected $_version = '1.0.1';

  /**
   * Returns singleton class instance
   * Always use this method unless you're working with multiple authenticated users at once
   *
   * @return Codebird The instance
   */
  public static function getInstance()
  {
    if (self::$_instance === null) {
      self::$_instance = new self;
    }
    return self::$_instance;
  }

  /**
   * Sets the OAuth consumer key and secret (App key)
   *
   * @param string $key    OAuth consumer key
   * @param string $secret OAuth consumer secret
   *
   * @return void
   */
  public static function setConsumerKey($key, $secret)
  {
    self::$_oauth_consumer_key  = $key;
    self::$_oauth_consumer_secret = $secret;
  }

  /**
   * Gets the current OAuth validator version
   *
   * @return string The version number
   */
  public function getVersion()
  {
    return $this->_version;
  }

  /**
   * Sets the OAuth request or access token and secret (User key)
   *
   * @param string $token  OAuth request or access token
   * @param string $secret OAuth request or access token secret
   *
   * @return void
   */
  public function setToken($token, $secret)
  {
    $this->_oauth_token        = $token;
    $this->_oauth_token_secret = $secret;
  }

  /**
   * Validate OAuth signature of an API call
   *
   * @param string  $authorization Signature to validate
   * @param string  $httpmethod    HTTP method used for making the request
   * @param string  $url           API URL called
   * @param array   $params        Parameters sent along
   * @param bool    $multipart     Whether multipart/form-data was used
   *
   * @return bool $is_valid_signature
   */
  public function validate(
    $authorization, $httpmethod, $url, $params = array(), $multipart = false
  )
  {
    // parse parameters
    $apiparams = $this->_parseApiParams($params);

    // stringify null and boolean parameters
    $apiparams = $this->_stringifyNullBoolParams($apiparams);

    // check whether OAuth was used
    if (! is_string($authorization) || substr($authorization, 0, 6) !== 'OAuth ') {
      trigger_error('Invalid authorization string supplied.');
      return false;
    }

    // split authorization parameters
    $authorization_params = $this->splitAuthorizationParams($authorization);

    // check for required OAuth parameters
    if (! $this->_checkAuthorizationParams($authorization_params)) {
      return false;
    }

    // extract timestamp and nonce from authorization
    $timestamp = $authorization_params['timestamp'];
    $nonce     = $authorization_params['nonce'];

    $correct_authorization = null;
    if ($httpmethod === 'GET' || ! $multipart) {
      $correct_authorization = $this->_sign(
        $httpmethod, $url, $params, $timestamp, $nonce
      );
    } else {
      $correct_authorization = $this->_sign(
        $httpmethod, $url, array(), $timestamp, $nonce
      );
    }

    return $correct_authorization === $authorization;
  }

  /**
   * Split authorization string into parameters array
   *
   * @param string $authorization OAuth authorization string
   *
   * @return array $authorization_params
   */
  public function splitAuthorizationParams($authorization)
  {
    $authorization_params = array();
    $authorization        = substr($authorization, 6);
    $temp = explode(', ', $authorization);

    if (! is_array($temp)) {
      return $authorization_params;
    }

    for ($i = 0; $i < count($temp); $i++) {
      $param = explode('=', $temp[$i], 2);
      if (! is_array($param) || count($param) < 2) {
        continue;
      }

      list ($key, $value) = $param;

      // strip "oauth_" prefix
      if (substr($key, 0, 6) === 'oauth_') {
        $key = substr($key, 6);
      }

      if (substr($value, 0, 1) === '"'
        && substr($value, -1) === '"'
      ) {
        $value = substr($value, 1, strlen($value) - 2);
      }

      $authorization_params[$key] = $value;
    }

    return $authorization_params;
  }

  /**
   * Parse given params, detect query-style params
   *
   * @param array|string $params Parameters to parse
   *
   * @return array $apiparams
   */
  protected function _parseApiParams($params)
  {
    $apiparams = array();
    if (count($params) === 0) {
      return $apiparams;
    }

    if (is_array($params)) {
      // given parameters are array
      return $params;
    }

    // user gave us query-style params
    parse_str($params[0], $apiparams);
    if (! is_array($apiparams)) {
      $apiparams = array();
    }

    if (! get_magic_quotes_gpc()) {
      return $apiparams;
    }

    // remove auto-added slashes recursively if on magic quotes steroids
    foreach($apiparams as $key => $value) {
      if (is_array($value)) {
        $apiparams[$key] = array_map('stripslashes', $value);
      } else {
        $apiparams[$key] = stripslashes($value);
      }
    }

    return $apiparams;
  }

  /**
   * Replace null and boolean parameters with their string representations
   *
   * @param array $apiparams Parameter array to replace in
   *
   * @return array $apiparams
   */
  protected function _stringifyNullBoolParams($apiparams)
  {
    foreach ($apiparams as $key => $value) {
      if (! is_scalar($value)) {
        // no need to try replacing arrays
        continue;
      }
      if (is_null($value)) {
        $apiparams[$key] = 'null';
      } elseif (is_bool($value)) {
        $apiparams[$key] = $value ? 'true' : 'false';
      }
    }

    return $apiparams;
  }

  /**
   * Check for required OAuth authorization parameters
   *
   * @param array $authorization_params Param array to check
   *
   * @return bool $is_valid Whether all required parameters are present
   */
  protected function _checkAuthorizationParams($authorization_params)
  {
    static $required_params = array(
      'consumer_key', 'nonce', 'signature', 'signature_method',
      'timestamp', 'version'
    );

    $keys = array_keys($authorization_params);

    foreach ($required_params as $param) {
      if (! in_array($param, $keys)) {
        trigger_error(
          'Required authorization parameter missing: '
          . $param . '.'
        );
        return false;
      }
    }

    // check for details
    if ($authorization_params['signature_method'] !== 'HMAC-SHA1') {
      trigger_error('OAuth signature method must be HMAC-SHA1.');
      return false;
    }

    $time_difference = abs(time() - $authorization_params['timestamp']);
    if ($time_difference > 180) {
      trigger_error(
        'Too much difference between client and server time ('
        . $time_difference . ' seconds).'
      );
      return false;
    }
    if ($authorization_params['version'] !== '1.0') {
      trigger_error('OAuth version must be 1.0.');
      return false;
    }

    return true;
  }

  /**
   * Signing helpers
   */

  /**
   * URL-encodes the given data
   *
   * @param mixed $data
   *
   * @return mixed The encoded data
   */
  protected function _url($data)
  {
    if (is_array($data)) {
      return array_map(array(
        $this,
        '_url'
      ), $data);
    } elseif (is_scalar($data)) {
      return str_replace(array(
        '+',
        '!',
        '*',
        "'",
        '(',
        ')'
      ), array(
        ' ',
        '%21',
        '%2A',
        '%27',
        '%28',
        '%29'
      ), rawurlencode($data));
    } else {
      return '';
    }
  }

  /**
   * Gets the base64-encoded SHA1 hash for the given data
   *
   * @param string $data The data to calculate the hash from
   *
   * @return string The hash
   */
  protected function _sha1($data)
  {
    if (self::$_oauth_consumer_secret === null) {
      throw new \Exception('To generate a hash, the consumer secret must be set.');
    }
    if (!function_exists('hash_hmac')) {
      throw new \Exception('To generate a hash, the PHP hash extension must be available.');
    }
    return base64_encode(hash_hmac(
      'sha1',
      $data,
      self::$_oauth_consumer_secret
      . '&'
      . ($this->_oauth_token_secret != null
        ? $this->_oauth_token_secret
        : ''
      ),
      true
    ));
  }

  /**
   * Generates an OAuth signature
   *
   * @param string $httpmethod Usually either 'GET' or 'POST' or 'DELETE'
   * @param string $method     API method to call
   * @param array  $params     API call parameters, associative
   * @param int    $timestamp  Authorization timestamp
   * @param string $nonce      Nonce used
   *
   * @return string Authorization HTTP header
   */
  protected function _sign($httpmethod, $method, $params, $timestamp, $nonce)
  {
    $signBaseParams = $this->getSignBaseParams($params, $timestamp, $nonce);
    $signBaseString = $this->getSignBaseString($params, $signBaseParams);
    $signature = $this->getSignature($httpmethod, $method);
    $params = $signBaseParams;
    $params['oauth_signature'] = $signature;
    $keys = $params;
    ksort($keys);
    $authorization = 'OAuth ';
    foreach ($keys as $key => $value) {
      $authorization .= $key . "=\"" . $this->_url($value) . "\", ";
    }
    return substr($authorization, 0, -2);
  }

  public function getSignature($httpmethod, $method, $timestamp = null, $nonce = null, $params = []) {
    if (self::$_oauth_consumer_key === null) {
      throw new \Exception('To generate a signature, the consumer key must be set.');
    }
    if(isset($this->signBaseString)) {
      return $this->_sha1($httpmethod . '&' . $this->_url($method) . '&' . $this->_url($this->signBaseString));
    }
    if(!($timestamp && $nonce)) {
      throw new \Exception('To generate a signature, you must provide a timestamp and nonce.');
    }
    $signBaseParams = $this->getSignBaseParams($params, $timestamp, $nonce);
    $signBaseString = $this->getSignBaseString($params, $signBaseParams);
    $sha = $this->_sha1($httpmethod . '&' . $this->_url($method) . '&' . $this->_url($signBaseString));
    return $this->_url($sha);
  }

  private function getSignBaseParams($params, $timestamp, $nonce) {
    if(isset($this->signBaseParams)) {
      return $this->signBaseParams;
    }
    $sign_params    = array(
      'consumer_key'     => self::$_oauth_consumer_key,
      'version'          => '1.0',
      'timestamp'        => $timestamp,
      'nonce'            => $nonce,
      'signature_method' => 'HMAC-SHA1'
    );
    $sign_base_params = array();
    foreach ($sign_params as $key => $value) {
      $sign_base_params['oauth_' . $key] = $this->_url($value);
    }
    if ($this->_oauth_token != null) {
      $sign_base_params['oauth_token'] = $this->_url($this->_oauth_token);
    }
    return $sign_base_params;
  }

  private function getSignBaseString($params, $sign_base_params) {
    if(isset($this->signBaseString)) {
      return $this->signBaseString;
    }
    foreach ($params as $key => $value) {
      $sign_base_params[$key] = $this->_url($value);
    }
    ksort($sign_base_params);
    $sign_base_string = '';
    foreach ($sign_base_params as $key => $value) {
      $sign_base_string .= $key . '=' . $value . '&';
    }
    $this->signBaseString = substr($sign_base_string, 0, -1);
    return $this->signBaseString;
  }
}
