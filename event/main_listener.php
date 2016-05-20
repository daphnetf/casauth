<?php
/**
*
* @package phpBB Extension - CAS Auth
* @copyright (c) 2016, University of Freiburg, Chair of Algorithms and Data Structures.
* @license https://opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
*
*/

namespace daphnetf\casauth\event;

/**
* Event listener
*/
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class main_listener implements EventSubscriberInterface
{
	/** @var \phpbb\template\template */
	protected $template;
	/** @var \phpbb\user */
	protected $user;
	/**
	* Constructor
	*
	* @param \phpbb\template\template       $template           Template object
	* @param \phpbb\user                    $user               User object
	* @access public
	*/
	public function __construct(\phpbb\template\template $template, \phpbb\user $user)
	{
		$this->template = $template;
		$this->user = $user;
	}

	static public function getSubscribedEvents()
	{
		return array(
			'core.page_header'	=> 'insert_template_values',
			'core.user_setup'	=> 'load_language_on_setup',
		);
	}

	public function insert_template_values($event)
	{
			$this->template->assign_var('U_USERNAME', $this->user->data["username"]);
	}

	public function load_language_on_setup($event)
	{
		$lang_set_ext = $event['lang_set_ext'];
		$lang_set_ext[] = array(
			'ext_name' => 'daphnetf/casauth',
			'lang_set' => 'cas_auth_acp',
		);
		$event['lang_set_ext'] = $lang_set_ext;
	}
}