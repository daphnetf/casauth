<?php
/**
*
* @package phpBB Extension - CAS Auth
* @copyright (c) 2016, University of Freiburg, Chair of Algorithms and Data Structures.
* @license https://opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
*
*/

if (!defined('IN_PHPBB'))
{
	exit;
}

if (empty($lang) || !is_array($lang))
{
	$lang = array();
}

$lang = array_merge($lang, array(
	'CAS'							=> 'Central Authentication Service',
	'CAS_EMAIL_ATTRIBUTE'			=> 'Email',
	'CAS_EMAIL_ATTRIBUTE_EXPLAIN'	=> 'Attribute name used for setting user email.',
	'CAS_NO_CURL_EXTENSION'			=> 'Curl not installed!',
	'CAS_PORT'						=> 'Port',
	'CAS_PORT_EXPLAIN'				=> 'Port on which the CAS server is listening to. Mostly 443.',
	'CAS_SERVER'					=> 'Server',
	'CAS_SERVER_EXPLAIN'			=> 'CAS server name, such as: cas.foo.biz',
	'CAS_URI'						=> 'URI',
	'CAS_URI_EXPLAIN'				=> 'Base URI of the cas server. Such as: /login, /cas...',
	'CAS_VALIDATE'					=> 'Validate',
	'CAS_VALIDATE_EXPLAIN'			=> 'Enable/Disable the validation of the CAS server SSL certificate',
));
