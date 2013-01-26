zenLdap
=======
This is a Zenphoto-plugin that allows an LDAP-authentication against Microsoft Active Directory and OpenLDAP.
The login-function checks first if there is a local-db user available (for the given login-data), if not, it tries to authenticate against the LDAP-directory

Setup
=====
Install the php-ldap extension, if you have apt:<br>
 "apt-get install php5-ldap"<br>
The plugin php script ldap_logon.php must be placed in "<zenphoto-directory>/plugins/ldap_logon.php".
In addition the lib-auth.php must be replaced - to do this create a folder named "alt" in the plugins directory<br>
 "mkdir <zenphoto-directory>/alt/plugins/alt/"<br>
and place the alternative lib-auth.php in the alt-folder.

How it works
============
Basically you have to use zenphoto-groups (with the zenplugin user_groups).
The same groups have to exist in the LDAP-Directory too (same group-name only).
During the login, the plugin receives the groups of the user. If there is a match between LDAP-group and Zenphoto-group, the zenphoto-group rights will be merged into the LDAP-user.
If there is no match, a default-template can be defined on the plugins-Option page, than those rights will be used for the user.

Known limitations
=================
There is a problem when editing anything on the admin-page with an ldap-user. 
Every action is recognized as cross-site scripting and will be blocked.
