<?php
/**
*
* @package phpBB Extension - CAS Auth
* @copyright (c) 2016, University of Freiburg, Chair of Algorithms and Data Structures.
* @license https://opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
*
*/

namespace daphnetf\casauth\auth\provider;

class cas extends \phpbb\auth\provider\base
{
	/**
	* phpBB passwords manager
	*
	* @var \phpbb\passwords\manager
	*/
	protected $passwords_manager;
	protected $is_setup;

	/**
	 * CAS Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface		$db		Database object
	 * @param	\phpbb\config\config		$config		Config object
	 * @param	\phpbb\passwords\manager	$passwords_manager		Passwords manager object
	 * @param	\phpbb\user			$user		User object
	 */
	public function __construct(\phpbb\db\driver\driver_interface $db, \phpbb\config\config $config, \phpbb\passwords\manager $passwords_manager, \phpbb\user $user)
	{
		require_once(dirname(__FILE__).'/../../vendor/phpCAS/CAS.php');
		$this->db = $db;
		$this->config = $config;
		$this->passwords_manager = $passwords_manager;
		$this->user = $user;
		$this->is_setup = false;
		$this->setupCas();
	}

	protected function setupCas()
	{
		if ($this->is_setup)
		{
			return true;
		}

		global $request;
		$request->enable_super_globals();
		if (strlen((string) $this->config['cas_server']) < 1) {
			return false;
		}
		\phpCAS::client(CAS_VERSION_2_0, (string) $this->config['cas_server'], (int) $this->config['cas_port'], (string) $this->config['cas_uri']);

		if ($this->config['force_server_vars'])
		{
			$service = $this->config['server_protocol'].$this->config['server_name'].$this->config['script_path'];
			\phpCAS::setFixedServiceURL($service);
		}

		/*if ($this->config['cas_validate'] == 0)
			\phpCAS::setNoCasServerValidation();*/
		\phpCAS::setNoCasServerValidation();

		if (defined('IN_LOGIN') && request_var('mode', '') == 'login')
		{
			\phpCAS::forceAuthentication();
		}
		$request->disable_super_globals();
		$this->is_setup = true;
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function init()
	{
		if (!@extension_loaded('curl'))
		{
			return $this->user->lang['CAS_NO_CURL_EXTENSION'];
		}

		return false;
	}

	/**
	 * {@inheritdoc}
	 */
	public function login($username, $password)
	{
		global $request;
		// do not allow empty password
		if (!$password)
		{
			return array(
				'status'	=> LOGIN_ERROR_PASSWORD,
				'error_msg'	=> 'NO_PASSWORD_SUPPLIED',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}

		if (!$username)
		{
			return array(
				'status'	=> LOGIN_ERROR_USERNAME,
				'error_msg'	=> 'LOGIN_ERROR_USERNAME',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}

		if (!@extension_loaded('curl'))
		{
			return array(
				'status'		=> LOGIN_ERROR_EXTERNAL_AUTH,
				'error_msg'		=> 'CAS_NO_CURL_EXTENSION',
				'user_row'		=> array('user_id' => ANONYMOUS),
			);
		}

		$user_row = array('user_id' => ANONYMOUS);
		$status = LOGIN_ERROR_USERNAME;
		$error_msg = 'LOGIN_ERROR_USERNAME';
		if($this->setupCas())
		{
			$request->enable_super_globals();
			if (!\phpCAS::isAuthenticated())
			{
				$user->session_kill();
				$user->session_begin();
			}
			\phpCAS::forceAuthentication();

			if (\phpCAS::isAuthenticated()) {
				$user_row = $this->get_user_row(\phpCAS::getUser(), $password);
				if ($user_row['user_id'] != ANONYMOUS) {
					$error_msg = false;
					$status = LOGIN_SUCCESS;
				}
			}
			$request->disable_super_globals();
		}

		return array('status' => $status, 'error_msg' => $error_msg, 'user_row' => $user_row);
	}

	/**
	 * {@inheritdoc}
	 */
	public function autologin()
	{
		global $request;
		$result = array();
		if($this->setupCas())
		{
			$request->enable_super_globals();
			if (!defined('IN_LOGIN') && !\phpCAS::isAuthenticated())
				\phpCAS::checkAuthentication();
			if (\phpCAS::isAuthenticated())
				$result = $this->get_user_row(\phpCAS::getUser());
			$request->disable_super_globals();
		}
		return $result;
	}

	/**
	 * {@inheritdoc}
	 */
	public function logout($data, $new_session)
	{
		global $request;
		if($this->setupCas())
		{
			$request->enable_super_globals();
			\phpCAS::logout();
			$request->disable_super_globals();
		}
	}

	/**
	 * {@inheritdoc}
	 */
	public function validate_session($user)
	{
		global $request;
		$result = false;
		if($this->setupCas())
		{
			$request->enable_super_globals();
			if (!defined('IN_LOGIN') or request_var('mode', '') != 'login')
				$result = \phpCAS::isAuthenticated();
			$request->disable_super_globals();
		}
		return $result;
	}

	/**
	 * {@inheritdoc}
	 */
	public function acp()
	{
		// These are fields required in the config table
		return array(
			'cas_server', 'cas_port', 'cas_uri', 'cas_validate', 'cas_email_attribute',
		);
	}

	/**
	* {@inheritdoc}
	*/
	public function get_acp_template($new_config)
	{
		return array(
			'TEMPLATE_FILE'	=> '@daphnetf_casauth/auth_provider_cas.html',
			'TEMPLATE_VARS'	=> array(
				'AUTH_CAS_SERVER'			=> $new_config['cas_server'],
				'AUTH_CAS_PORT'				=> $new_config['cas_port'],
				'AUTH_CAS_URI'				=> $new_config['cas_uri'],
				'AUTH_CAS_VALIDATE'			=> $new_config['cas_validate'],
				'AUTH_CAS_EMAIL_ATTRIBUTE'	=> $new_config['cas_email_attribute'],
			),
		);
	}

	protected function get_user_row($username, $password='')
	{
		global $db, $phpbb_root_path, $phpEx;
		$username_clean = utf8_clean_string($username);
		$user_row = array('user_id' => ANONYMOUS);
		$sql ='SELECT *
			FROM ' . USERS_TABLE . "
			WHERE username_clean = '" . $db->sql_escape($username_clean) . "'";
		$result = $db->sql_query($sql);
		$row = $db->sql_fetchrow($result);
		$db->sql_freeresult($result);

		if ($row)
		{
			if ( !($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) )
				$user_row = $row;
		}
		else
		{
			// retrieve default group id
			$sql = 'SELECT group_id
				FROM ' . GROUPS_TABLE . "
				WHERE group_name = '" . $db->sql_escape('REGISTERED') . "'
					AND group_type = " . GROUP_SPECIAL;
			$result = $db->sql_query($sql);
			$row = $db->sql_fetchrow($result);
			$db->sql_freeresult($result);

			if (!$row)
			{
				trigger_error('NO_GROUP');
			}

			// generate user account data
			$user_row = array(
				'username'			=> $username,
				'username_clean'	=> $username_clean,
				'user_password'		=> $this->passwords_manager->hash($password),
				'user_email'		=> '',
				'group_id'			=> (int) $row['group_id'],
				'user_type'			=> USER_NORMAL,
				'user_ip'			=> $this->user->ip,
				'user_new'			=> ($this->config['new_member_post_limit']) ? 1 : 0,
			);
			// we are going to use the user_add function so include functions_user.php if it wasn't defined yet
			if (!function_exists('user_add'))
			{
				include($phpbb_root_path . 'includes/functions_user.' . $phpEx);
			}
			user_add($user_row);
			// reload user data
			$sql ='SELECT *
				FROM ' . USERS_TABLE . "
				WHERE username_clean = '" . $db->sql_escape(utf8_clean_string($username)) . "'";
			$result = $db->sql_query($sql);
			$user_row = $db->sql_fetchrow($result);
			$db->sql_freeresult($result);
		}
		if ( isset($user_row['user_id']) && $user_row['user_id'] != ANONYMOUS ) {
			$this->setupCas();
			$attributes = \phpCAS::getAttributes();
			$attributes[$this->config['cas_email_attribute']] = strtolower($attributes[$this->config['cas_email_attribute']]);
			$update = '';
			// Update user email to match value provided by cas
			if ( $user_row['user_email'] != $attributes[$this->config['cas_email_attribute']] ) {
				$user_row['user_email'] = $attributes[$this->config['cas_email_attribute']];
				$user_row['user_email_hash'] = phpbb_email_hash($user_row['user_email']);
				$update .= "user_email='".$user_row['user_email']."', ";
				$update .= "user_email_hash='".$user_row['user_email_hash']."', ";
			}
			if ( strlen($password) ) {
				$user_row['user_password'] = $this->passwords_manager->hash($password);
				$update .= "user_password='".$user_row['user_password']."', ";
			}
			if ( strlen($update) ) {
				$sql = 'UPDATE ' . USERS_TABLE . "
					SET " . substr($update, 0, -2). "
					WHERE user_id = " . $user_row['user_id'];
				$result = $db->sql_query($sql);
			}
		}
		return $user_row;
	}
}