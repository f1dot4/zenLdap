<?php
/* Adds a ldap properties to zenphoto*/

/* Zenphoto stuff */
$plugin_description = "LDAP Logon properties";
$plugin_author = "Lukas Leidinger";
$plugin_version = "2.1";
$plugin_URL = "";
$plugin_is_filter = 2|CLASS_PLUGIN;
$option_interface = "ldapLogon";

zp_register_filter('','ldapLogon::getLdapZenUsers');
zp_register_filter('','ldapLogon::authenticateLdapUser');
zp_register_filter('','ldapLogon::checkUserIsInGroup');
zp_register_filter('','ldapLogon::load');

class ldapLogon {
  function ldapLogon(){
		setOptionDefault('ldapEnabled', 1);
		setOptionDefault('ldapType', 0);
		setOptionDefault('ldapServer', '192.168.1.14');
		setOptionDefault('ldapServerPort','389');
		setOptionDefault('ldapDc','dc=domain');
		setOptionDefault('ldapOu','ou=Users');
		setOptionDefault('ldapRdrDn','cn=reader,dc=loww');
		setOptionDefault('ldapRdrPass','test');
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
			gettext('Type of directory') => array('key' => 'ldapType',
                                                                'type' => OPTION_TYPE_RADIO,
								'buttons' => array(getText('Microsoft Active Directory') => "ldapTypeAD",getText("OpenLDAP") => "ldapTypeOL"),
                                                                'order' => 1,
                                                                'desc' => gettext("Set LDAP type: Microsoft AD or OpenLDAP")
                                                        ),
			gettext('LDAP Server IP/Hostname') => array('key' => 'ldapServer',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 2,
								'desc' => gettext("Set the LDAP server IP")
							),
			gettext('LDAP Server Port') => array('key' => 'ldapServerPort',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 3,
								'desc' => gettext("Set the LDAP server port")
							),
			gettext('LDAP DC') => array('key' => 'ldapDc',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 4,
								'desc' => gettext("Set the LDAP DC e.g. dc=domain (--> the complete User-DN is dc=Test,ou=Users,dc=domain)")
							),
			gettext('LDAP OU') => array('key' => 'ldapOu',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 5,
								'desc' => gettext("Set the LDAP OU e.g. ou=Users (--> the complete User-DN is dc=Test,ou=Users,dc=domain), for MS AD you have to use cn=Users!")
							),
			gettext('LDAP Reader DN') => array('key' => 'ldapRdrDn',
                                                                'type' => OPTION_TYPE_TEXTBOX,
                                                                'order' => 6,
                                                                'desc' => gettext("Set the DN of an LDAP-user with read permissions for the memberOf group-attributes, e.g.: cn=reader,dc=loww, for MS AD the regular login can be used e.g. user@domain.tld")
                                                        ),
			gettext('LDAP Reader Password') => array('key' => 'ldapRdrPass',
                                                                'type' => OPTION_TYPE_PASSWORD,
                                                                'order' => 7,
                                                                'desc' => gettext("Password of the LDAP-User with read permissions to acces the memberOf group-attribute")
                                                        ),
			gettext('Default template') => array('key' => 'ldapZenDefaultTemplate',
								'type' => OPTION_TYPE_TEXTBOX,
								'order' => 8,
								'desc' => gettext("Template that should be used when no ldap zen-group is available")
							)


		);
		return $options;
	}
	function handleOption($option, $currentValue) {
  	}

	static function load(){
		debugLog('LDAP load() called');
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
			if(ldap_bind($ldapC, getOption('ldapRdrDn'), getOption('ldapRdrPass'))) {
				$res = ldap_search($ldapC,$ldapDc, $ldapCn);
				$user = ldap_get_entries($ldapC,$res);
				//debugLog('LDAP return cn=\''.$user[0]['cn'][0].'\' uid=\''.$ldapUid.'\'');
				unset($user[0]['uid']['count']);
				ldap_close($ldapC);
				return $user[0]['uid'];
			} else {
				return false;
			}
		} else {
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
	 */
	static function getLdapGroupCnsOfUid($ldapServer,$ldapServerPort,$ldapDc,$ldapUid , $ldapAttr = "") {
		if($ldapServer == NULL || $ldapServerPort == NULL || $ldapDc == NULL || $ldapUid == NULL || $ldapAttr == NULL) {
			debugLog('LDAP: function getLdapZenUsers() called with at least one invalid argument!');
			return false;
		}
		if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
			if(ldap_bind($ldapC, getOption('ldapRdrDn'), getOption('ldapRdrPass'))) {
				$groups = array();
				//$ldapAttr = array('cn');
				$res = ldap_search($ldapC,$ldapDc, $ldapUid, $ldapAttr);
				$user = ldap_get_entries($ldapC,$res);
				//debugLog('LDAP return cn=\''.$user[0]['cn'][0].'\' uid=\''.$ldapUid.'\'');
				for($i=0;$i < count($user); $i++) {
						if(!empty($user[$i]['cn']['0'])) {
								$groups[$i] = $user[$i]['cn']['0'];
						}
				}
				ldap_close($ldapC);
				return $groups;
			} else {
				return false;
			}
		} else {
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
		//echo "getAdUserGroups($ldapServer, $ldapServerPort, $ldapDc, $ldapCn,$ldapFilter)";
                if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
                        if(ldap_bind($ldapC, getOption('ldapRdrDn'), getOption('ldapRdrPass'))) {
	                        $res = ldap_search($ldapC,$ldapDc, $ldapCn,$ldapFilter) or die(ldap_error($ldapC));
	                        $groups = ldap_get_entries($ldapC,$res);
	                        ldap_close($ldapC);
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
				return false;
			}
                } else {
                        return false;
                }
        }
	
	/*
	 * Return an Array that is used by the external_auth.php script
	 * @param ldapServer
	 * @param ldapServerPort
	 * @param ldapDc in format 'dc=domain' or 'dc=domain,dc=tld'
	 * @param ldapCn in format 'cn=user'
	 * @param user is the string from the login-textbox
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
					//foreach(self::getLdapGroupCnsOfUid($ldapServer,$ldapServerPort,$ldapDc,'memberUid='.$uid, array('cn')) as $a){ echo "<pre>"; debugLog('GROUP='.$a); echo "</pre>";}
					$result['groups'] = array_merge($result['groups'],self::getLdapGroupCnsOfUid($ldapServer,$ldapServerPort,$ldapDc,'memberUid='.$uid, array('cn')));
				}
			}
			$result['user'] = $user;
			$result['id'] = '';
			$result['defaultgroup'] = $defaultZenGroup;
			return $result;
		} else if (($groups = self::getAdUserGroups($ldapServer,$ldapServerPort,$ldapDc,'cn='.$user)) && getOption('ldapType') == 'ldapTypeAD') {  //MS AD is used
			$result['groups'] = array_merge($result['groups'],$groups);
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
		//debugLog('LDAP: called function authtenticateLdapUser('.$ldapServer.','.$ldapServerPort.','.$ldapRdn.',PASS_NOT_SHOWN)');
		if($ldapC = self::getLdapConnection($ldapServer,$ldapServerPort)) {
			if (DEBUG_LOGIN) { debugLog('LDAP Bind: ldap_bind('.$ldapC.', '.$ldapRdn.' ,'.$ldapPass.')'); }
			 debugLog('LDAP Bind: ldap_bind('.$ldapC.', '.$ldapRdn.' ,'.$ldapPass.')');
			$ldapB = @ldap_bind($ldapC, $ldapRdn ,$ldapPass);
			if($ldapB) {
				if (DEBUG_LOGIN) { debugLog('LDAP authentication for \''. $ldapRdn.'\' successfull'); }
				debugLog('LDAP authentication for \''. $ldapRdn.'\' successfull'); 
				return ($ldapC);
			} else {
				if (DEBUG_LOGIN) { debugLog('LDAP bind failed for \''. $ldapRdn); }
				debugLog('LDAP bind failed for \''. $ldapRdn);
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
			unset($result['id']);
			unset($result['user']);
			$authority = '';
			//      create a transient user
			$userobj = new Zenphoto_Administrator('', 1);
			$userobj->setUser($user);
			$userobj->setRights(NO_RIGHTS); //      just incase none get set
			//      Flag as external credentials for completeness
			$properties = array_keys($result);      //      the list of things we got from the external authority
			array_unshift($properties, $auth);
			$userobj->setCredentials($properties);
			//      populate the user properties
			$member = false;        //      no group membership (yet)
			//echo "<pre>"; print_r($result); echo "</pre>";exitZP();
			foreach ($result as $key=>$value) {
				switch ($key) {
					case 'authority':
						$authority = '::'.$value;
						unset($result['authority']);
						break;
					case 'groups':
						//      find the corresponding Zenphoto group (if it exists)
						$rights = NO_RIGHTS;
						$objects = array();
						$groups = $value;
						foreach ($groups as $key=>$group) {
							debugLog("Adding Group: $group");
							$groupobj = Zenphoto_Authority::getAnAdmin(array('`user`=' => $group,'`valid`=' => 0));
							if ($groupobj) {
								$member = true;
								$rights = $groupobj->getRights() | $rights;
								$objects = array_merge($groupobj->getObjects(), $objects);
								debugLog("Group Name:". $groupobj->getName());
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
							//      No Zenphoto group, use the default group
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
			$properties = array_keys($result);      //      the list of things we got from the external authority
			array_unshift($properties, $auth.$authority);
			$userobj->setCredentials($properties);
		} else {
			$userobj = NULL;	// User exists in local DB, should be authenticated before
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
