<?php
/* Adds LDAP authentication to zenphoto
 * For more information read the REAMDE that can be found under https://github.com/spelth/zenLdap/blob/master/README.md
 * This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 3.0 Unported License.
 */

/* Zenphoto stuff */
$plugin_description = "LDAP Logon properties";
$plugin_author = "Lukas Leidinger";
$plugin_version = "2.2";
$plugin_URL = "https://github.com/spelth/zenLdap";
$plugin_is_filter = 2|CLASS_PLUGIN;
$option_interface = "ldapLogon";

zp_register_filter('','ldapLogon::checkLogon');
zp_register_filter('','ldapLogon::getLogon');

class ldapLogon {
	function __construct(){
		setOptionDefault('ldapEnabled', 1);
		setOptionDefault('ldapServer', '192.168.1.14');
		setOptionDefault('ldapServerPort','389');
		setOptionDefault('ldapSearchBase','cn=users,cn=accounts,dc=example,dc=com');
		setOptionDefault('ldapSearchBaseGroup','cn=groups,cn=accounts,dc=example,dc=com');
		setOptionDefault('ldapLoginAttribute','cn');
		setOptionDefault('ldapAuthAttribute','cn');
		setOptionDefault('ldapUserFilter','');
		setOptionDefault('ldapReaderDn','cn=reader,dc=example,dc=com');
		setOptionDefault('ldapReaderPass','test');
		setOptionDefault('ldapZenDefaultTemplate','extern');
		setOption('zp_plugin_ldapLogon','4096');
	}
	function getOptionsSupported(){
		$options = 	array(
			gettext('Enable LDAP Logon') => array('key' => 'ldapEnabled', 
								'type' => OPTION_TYPE_CHECKBOX,
								'order' => 0,
								'desc' => gettext("Set the checkbox to enable the LDAP logon functionality")
							),
			gettext('LDAP Server IP/Hostname') => array('key' => 'ldapServer',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 1,
								'desc' => gettext("Set the LDAP server IP")
							),
			gettext('LDAP Server Port') => array('key' => 'ldapServerPort',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 2,
								'desc' => gettext("Set the LDAP server port")
							),
			gettext('LDAP Search Base') => array('key' => 'ldapSearchBase',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 3,
								'desc' => gettext("Set the LDAP search base for users"),
							),
			gettext('LDAP Search Base for Groups') => array('key' => 'ldapSearchBaseGroup',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 4,
								'desc' => gettext("Set the LDAP search base for groups"),
							),
			gettext('LDAP Login Attribute') => array('key' => 'ldapLoginAttribute',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 5,
								'desc' => gettext("Set the LDAP attribute the users must enter on ZenPhoto to login (e.g. mail to login with mailaddress, uid to login with username, etc.)"),
							),
			gettext('LDAP Auth Attribute') => array('key' => 'ldapAuthAttribute',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 6,
								'desc' => gettext("Set the LDAP attribute used to authenticate against LDAP (e.g. the first part of a fully distinguished name)"),
							),
			gettext('LDAP User Filter') => array('key' => 'ldapUserFilter',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 7,
								'desc' => gettext("Set an additional filter for users (e.g.: (memberOf=cn=zenphoto-user,cn=groups,cn=accounts,dc=example,dc=com) to only allow users that are members of the zenphoto-user LDAP group to log in)"),
							),
			gettext('LDAP Reader DN') => array('key' => 'ldapReaderDn',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 8,
								'desc' => gettext("Set the DN of an LDAP-user with read permissions for the user and group objects"),
							),
			gettext('LDAP Reader Password') => array('key' => 'ldapReaderPass',
								'type' => OPTION_TYPE_PASSWORD,
								'order' => 9,
								'desc' => gettext("Password of the LDAP-User with read permissions for the user and group objects"),
							),
			gettext('Default template') => array('key' => 'ldapZenDefaultTemplate',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 10,
								'desc' => gettext("Template that should be used when no ldap zen-group is available")
							)
		);
		return $options;
	}
	function handleOption($option, $currentValue) {
  	}

	/*
	 * returns a LDAP connection
	 */
	static function getLdapConnection($ldapServer, $ldapServerPort) {
		if($ldapServer == NULL || $ldapServerPort == NULL) {
			debugLog('LDAP: function getLdapConnection() called with at least one invalid argument!');
			return false;
		}
		$ldapC = ldap_connect($ldapServer, $ldapServerPort) or die ('Could not connect to '.$ldapServer);
		ldap_set_option($ldapC, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($ldapC, LDAP_OPT_REFERRALS, 0);
		if ($ldapC) {
			return $ldapC;
		} else {
			return false;
		}
	}

	/*
	 * Returns the array uids of a cn
	 *
	 * @param ldapServer
	 * @param ldapServerPort
	 * @param ldapDc in format 'dc=domain' or 'dc=domain,dc=tld'
	 * @param ldapCn in format 'cn=user'
	 */
	static function getLdapUidsOfCn($ldapServer,$ldapServerPort,$ldapDc,$ldapCn) {
		if($ldapServer == NULL || $ldapServerPort == NULL || $ldapDc == NULL || $ldapCn == NULL) {
			debugLog('LDAP: function getLdapUidsOfCn() called with at least one invalid argument!');
			return false;
		}
		if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
			if(@ldap_bind($ldapC, getOption('ldapRdrDn'), getOption('ldapRdrPass'))) {
				$res = ldap_search($ldapC,$ldapDc, $ldapCn);
				$user = ldap_get_entries($ldapC,$res);
				unset($user[0]['uid']['count']);
				ldap_close($ldapC);
				return $user[0]['uid'];
			} else {
				debugLog("Cannot bind to LDAP-server:".ldap_error($ldapC));
                                ldap_close($ldapC);
				return false;
			}
		} else {
			debugLog("Cannot connect to LDAP-server:".ldap_error($ldapC));
			return false;
		}
	}
	
	/*
	 * Returns an array of CNs of a given uid
	 *
	 * @param ldapServer
	 * @param ldapServerPort
	 * @param ldapDc in format 'dc=domain' or 'dc=domain,dc=tld'
	 * @param ldapUid in format 'memberUid=user'
	 * @param ldapAttr
	 */
	static function getLdapGroupCnsOfUid($ldapServer,$ldapServerPort,$ldapDc,$ldapUid , $ldapAttr = "") {
		if($ldapServer == NULL || $ldapServerPort == NULL || $ldapDc == NULL || $ldapUid == NULL || $ldapAttr == NULL) {
			debugLog('LDAP: function getLdapZenUsers() called with at least one invalid argument!');
			return false;
		}
		if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
			if(@ldap_bind($ldapC, getOption('ldapRdrDn'), getOption('ldapRdrPass'))) {
				$groups = array();
				$res = ldap_search($ldapC,$ldapDc, $ldapUid, $ldapAttr);
				$user = ldap_get_entries($ldapC,$res);
				for($i=0;$i < count($user); $i++) {
						if(!empty($user[$i]['cn']['0'])) {
								$groups[$i] = $user[$i]['cn']['0'];
						}
				}
				ldap_close($ldapC);
				return $groups;
			} else {
				debugLog("Cannot bind to LDAP-server:".ldap_error($ldapC));
                                ldap_close($ldapC);
				return false;
			}
		} else {
			debugLog("Cannot connect to LDAP-server:".ldap_error($ldapC));
			return false;
		}
	}	

	/*
         * Return an Array with the group of a given user
         * @param ldapServer
         * @param ldapServerPort
         * @param ldapDc in format 'dc=domain' or 'dc=domain,dc=tld'
         * @param ldapCn in format 'cn=user'
         * @param ldapFilter is the ldap-filter attribute, typically "memberof"
         */
	static function getAdUserGroups($ldapServer, $ldapServerPort, $ldapDc, $ldapCn,$ldapFilter = array('memberof')) {
                if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
                        if(@ldap_bind($ldapC, getOption('ldapRdrDn'), getOption('ldapRdrPass'))) {
	                        $res = ldap_search($ldapC,$ldapDc, $ldapCn,$ldapFilter) or die(ldap_error($ldapC));
	                        $groups = ldap_get_entries($ldapC,$res);
	                        ldap_close($ldapC);
				if(array_key_exists('memberof',$groups[0]) ){
		                        $tmp=$groups[0]['memberof'];
		                        $groups=array();
	        	                unset($tmp['count']);
	                	        foreach($tmp as $member) {
	                        	        $t=explode(",",$member);
	                                	$t=explode("=",$t[0]);
		                                array_push($groups,$t[1]);
		                        }
	        	                return $groups;
				} else {
					debugLog("Groups cannot be retrieved, check your LDAP-Settings, especially the DC, Reader, Readerpassword; Search called with: ldap_search($ldapC,$ldapDc, $ldapCn,$ldapFilter)");
					
					return array();
				}
			} else { 
				debugLog("Cannot bind to LDAP-server:".ldap_error($ldapC));
				ldap_close($ldapC);
				return false;
			}
                } else {
			debugLog("Cannot connect to LDAP-server:".ldap_error($ldapC));
                        return false;
                }
        }
	
	/*
	 * Return an Array that is used by the external_auth.php script
	 * @param ldapServer
	 * @param ldapServerPort
	 * @param ldapDc in format 'dc=domain' or 'dc=domain,dc=tld'
	 * @param user is the string from the login-textbox
	 * @param defaultZenGroup is the default template that should be used when no group matches
	 */
	static function getExternalAuthArray($ldapServer,$ldapServerPort,$ldapDc, $user, $defaultZenGroup) {
		if($ldapServer == NULL || $ldapServerPort == NULL || $ldapDc == NULL || $user == NULL) {
			debugLog('LDAP: function getExternalAuthArray() called with at least one invalid argument!');
			return false;
		}
		$result=array();
		$i=0;
		$result['groups']=array();
		if(getOption('ldapType') == 'ldapTypeOL' && $ldapUids = self::getLdapUidsOfCn($ldapServer,$ldapServerPort,$ldapDc,'cn='.$user)) { // OpenLDAP is used
			foreach($ldapUids as $uid) {
				if(count(self::getLdapGroupCnsOfUid($ldapServer,$ldapServerPort,$ldapDc,'memberUid='.$uid, array('cn')))) {
					$result['groups'] = array_merge($result['groups'],self::getLdapGroupCnsOfUid($ldapServer,$ldapServerPort,$ldapDc,'memberUid='.$uid, array('cn')));
				}
			}
		} else if (($groups = self::getAdUserGroups($ldapServer,$ldapServerPort,$ldapDc,'cn='.$user)) && getOption('ldapType') == 'ldapTypeAD') {  //MS AD is used
			$result['groups'] = array_merge($result['groups'],$groups);
		}
		if(getOption('ldapType')){ 
			$result['user'] = $user;
        	        $result['id'] = '';
                	$result['defaultgroup'] = $defaultZenGroup;
			return $result;
		} else {
			return NULL;
		}
	}
	
	/*
	 * Make an LDAP-bind to authenticate
	 * @param ldapServer
	 * @param ldapServerPort
	 * @param ldapRdn
	 * @ldapPass
	 */
	static function authenticateLdapUser($ldapServer,$ldapServerPort,$ldapRdn,$ldapPass) {
		if($ldapServer == NULL || $ldapServerPort == NULL || $ldapRdn == NULL) {
			debugLog('LDAP: function autenticateLdapUser() called with at least one invalid argument! (ldapPass is allowed to be empty)');
			return false;
		}
		if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
			if (DEBUG_LOGIN) { debugLog('LDAP Bind: ldap_bind('.$ldapC.', '.$ldapRdn.' ,'.$ldapPass.')'); }
			$ldapB = @ldap_bind($ldapC, $ldapRdn ,$ldapPass);
			if($ldapB) {
				if (DEBUG_LOGIN) { debugLog('LDAP authentication for \''. $ldapRdn.'\' successfull'); }
				return ($ldapC);
			} else {
				if (DEBUG_LOGIN) { debugLog('LDAP bind failed for \''. $ldapRdn); }
				ldap_close($ldapC);
				return false;
			}
		} else {
			if (DEBUG_LOGIN) { debugLog('LDAP Server \''. $ldapServer.'\' cannot be reached!'); }
			return false;
		}
	}

	/**
	 * getLogon is used to return the userobj without authentication, used for cookie-stuf
	 * 
	 * @param id of the user, should be -1 if using ldap-logon
	 */
	static function getLogon($id) {
		global $_zp_current_admin_obj;
		if ($id == -1 ){
                        if (DEBUG_LOGIN) { debugLog("Using LDAP Authorization, getting LDAP-Cookie: User=".zp_getCookie('zp_user_auth_ldap')); }
                        if($_zp_current_admin_obj = self::checkLogon(zp_getCookie('zp_user_auth_ldap'))) {
                                return $_zp_current_admin_obj->getRights();
                        }
                }
	}
	
	/**
	 * checkLogon for LDAP
	 * 
	 * @param user is the username
	 * @param pass can be null if no authentication should be done
	 */
	static function checkLogon($user, $pass=NULL){
		$auth = 'external';
		$searchfor = array('`user`=' => $user,  '`valid`=' => 1);
		$userobj = Zenphoto_Authority::getAnAdmin($searchfor);
		if (!$userobj ) {
			$result = ldapLogon::getExternalAuthArray(getOption('ldapServer'),getOption('ldapServerPort'),getOption('ldapDc'),$user,getOption('ldapZenDefaultTemplate'));
			if($result){
				unset($result['id']);
				unset($result['user']);
				$authority = '';
				$userobj = new Zenphoto_Administrator('', 1);
				$userobj->setUser($user);
				$userobj->setRights(NO_RIGHTS);
				$properties = array_keys($result);
				array_unshift($properties, $auth);
				$userobj->setCredentials($properties);
				$member = false; 
				foreach ($result as $key=>$value) {
					switch ($key) {
						case 'authority':
							$authority = '::'.$value;
							unset($result['authority']);
							break;
						case 'groups':
							$rights = NO_RIGHTS;
							$objects = array();
							$groups = $value;
							foreach ($groups as $key=>$group) {
								if (DEBUG_LOGIN){ debugLog("LDAP: Adding Group: $group"); }
								$groupobj = Zenphoto_Authority::getAnAdmin(array('`user`=' => $group,'`valid`=' => 0));
								if ($groupobj) {
									$member = true;
									$rights = $groupobj->getRights() | $rights;
									$objects = array_merge($groupobj->getObjects(), $objects);
									if ($groupobj->getName() == 'template') {
										unset($groups[$key]);
									}
								} else {
									unset($groups[$key]);
								}
							}
							if ($member) {
								$userobj->setGroup(implode(',',$groups));
								$userobj->setRights($rights);
								$userobj->setObjects($objects);
							}
							break;
						case 'defaultgroup':
							if (!$member && isset($result['defaultgroup'])) {
								$group = $result['defaultgroup'];
								$groupobj = Zenphoto_Authority::getAnAdmin(array('`user`=' => $group,'`valid`=' => 0));
								if ($groupobj) {
									$rights = $groupobj->getRights();
									$objects = $groupobj->getObjects();
									if ($groupobj->getName() != 'template') {
										$group = NULL;
									}
									$userobj->setGroup($group);
									$userobj->setRights($rights);
									$userobj->setObjects($objects);
								}
							}
							break;
						case 'objects':
							$userobj->setObjects($objects);
							break;
						case 'album':
							$userobj->createPrimealbum(false, $value);
							break;
						default:
							$userobj->set($key,$value);
							break;
					}
				}
				$properties = array_keys($result);
				array_unshift($properties, $auth.$authority);
				$userobj->setCredentials($properties);
			} else {
				$userobj = NULL;
			}
		} else {
			$userobj = NULL;	// User exists in local DB, it should be authenticated before, some error?
		}	
		if (isset($result['logout_link'])) {
			$userobj->logout_link = $result['logout_link'];
		}
		if ($pass != NULL && $userobj) {
			$ldapRdn = 'cn='.$userobj->get('user').','.getOption('ldapOu').','.getOption('ldapDc');
			if(!ldapLogon::authenticateLdapUser(getOption('ldapServer'), getOption('ldapServerPort'), $ldapRdn, $pass)) {
				$userobj = NULL;
			}
		}
		return $userobj;
	}	
}
?>
