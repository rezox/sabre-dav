<?php

namespace Sabre\DAV\Auth\Backend;

/**
 * Active Directory authentification backend class
 * This class can be used to authenticate for SabreDAV using Active Directory.
 */
class ActiveDirectory extends AbstractBasic {
	/**
	 * Usage of Active Directory authentification
	 *
	 * assuming that this file ActiveDirectory.php is saved in the directory /vendor/sabre/dav/lib/DAV/Auth/Backend/,
	 * you can add in the server.php this new Active Directory authentification backend. Add the following code:
	 *
	 * $params = array(... your Active Directory settings ...);
	 * $authBackend = new \Sabre\DAV\Auth\Backend\ActiveDirectory($params);
	 *
	 * The Active Directory authentification delivers true or false depending on the provided information.
	 * Currently there are no error messages if there is something wrong.
	 *
	 * @param array $params
	 * @return bool
	 */

	/**
	 * Example: Active Directory @ srv.domain.lan:636, TLS communication, custom search filter
	 * Add the following code to the server.php:
	 *
	 * $params = array(
	 *     'host'     => 'srv.domain.lan',
	 *     'port'     => 636,
	 *     'tls'      => true,
	 *     'basedn'   => "OU=Users,OU=DOMAIN,dc=domain,dc=lan",
	 *     'memberof' => '(&(objectCategory=user)(CN=Domain Users,CN=Users,DC=domain,DC=lan))'
	 * );
	 * $authBackend       = new \Sabre\DAV\Auth\Backend\ActiveDirectory($params);
	 */
	protected $host;
	protected $port;
	protected $basedn;
	protected $domain;
	protected $tls;
	protected $memberof;

	function __construct($params) {
		$defaults = array(
			'tls' => true,
			'port' => 636
		);
		$array = array_merge($defaults, $params);
		foreach ($array as $key => $value) {
			$this->{$key} = $value;
		}
	}

	protected function validateUserPass($username, $password) {
		if (strlen($password) == 0) {
			return false;
		}

		// Check connection first ( http://bugs.php.net/bug.php?id=15637 )
		$sock = @fsockopen($this->host, $this->port, $errno, $errstr, 1);
		@fclose($sock);
		if ($errno != 0) {
			return false;
		}

		$result = false;

		$conn = ldap_connect((($this->tls) ? 'ldaps://' : '') . $this->host, $this->port);
		if ($conn) {
			ldap_set_option($conn, LDAP_OPT_PROTOCOL_VERSION, 3);
			ldap_set_option($conn, LDAP_OPT_REFERRALS, 0);
			$login = "{$username}@{$this->domain}";
			$bind = ldap_bind($conn, $login, $password);
			if ($bind) {
				$result = true;
				if (!empty($this->memberof)) {
					$sr = ldap_search($conn, $this->basedn, "(&(objectCategory=user)(memberOf={$this->memberof})(sAMAccountName={$username}))");
					$info = ldap_get_entries($conn, $sr);
					$result = (!empty($info['count']));
				}
				ldap_unbind($conn);
			}
		}
		return $result;
	}

}
