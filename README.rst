ldap-groups
%%%%%%%%%%%

A python/django Active Directory group management abstraction that uses python-ldap as a backend for cross-platform compatibility.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:Version:           2.5.1
:Dependencies:      Python 2.7, python-ldap>=2.4.13
:Home page:         https://bitbucket.org/kavanaugh_development/ldap-groups
:Author:            Alex Kavanaugh <kavanaugh.development@outlook.com>
:License:           GNU LGPL (http://www.gnu.org/licenses/lgpl.html)


Installation
============

Run ``pip install ldap-groups``

Add *ldap-groups* to ``INSTALLED_APPS``

.. code:: python

    INSTALLED_APPS = (
        ...
        'ldap_groups',
        ...
    )


Django Settings
===============

There are a few settings that must be configured before ldap-groups will run.

*Mandatory*

* ``LDAP_GROUPS_SERVER_URI`` - The ldap server's uri, e.g. 'ldap://example.com'
* ``LDAP_GROUPS_BASE_DN`` - The base search dn, e.g. 'DC=example,DC=com'

*Optional*

* ``LDAP_GROUPS_BIND_DN`` - The bind user's DN
* ``LDAP_GROUPS_BIND_PASSWORD`` - The bind user's password

NOTE: while a bind user is optional, many servers' security settings will deny anonymous access.

* ``LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE`` - The attribute by which to search when looking up users (should be unique). Defaults to ``'sAMAccountName'``.
* ``LDAP_GROUPS_ATTRIBUTE_LIST`` - A list of attributes returned for each member while pulling group members. An empty list should return all attributes. Defaults to ``['displayName', 'sAMAccountName', 'distinguishedName']``.


Usage
=====

In its current state, ldap-groups can perform the following functions:

* Add a member to a group
* Remove a member from a group
* Get all members of a group (and their attributes) [only retrieves user object classes at this point]
* Get all attributes of a group in dictionary form
* Get a specific attribute of a group
* Get all children of a group (groups and organizational units)
* Traverse to a specific child of a group
* Traverse to a group's parent
* Traverse to a group's ancestor


An ADGroup instance only requires one argument to function: a group's distinguished name.
Once the ADGroup is instantiated, the rest is fairly simple:

.. code:: python

    from ldap_groups import ADGroup
    
    GROUP_DN = "ou=users,dc=example,dc=com"
    ACCOUNT_NAME = "jdoe"
    NAME_ATTRIBUTE = "name"
    TYPE_ATTRIBUTE = "objectClass"
    
    class ADGroupModifier(object):
    
        def __init__(self):
            self.ad_group_instance = ADGroup(GROUP_DN)
        
        def add_member(self):            
            self.ad_group_instance.add_member(ACCOUNT_NAME)
        
        def remove_member(self):            
            self.ad_group_instance.remove_member(ACCOUNT_NAME)
        
        def get_group_member_info(self):
            return self.ad_group_instance.get_member_info()


    class ADGroupInfo(object):
    
        def __init__(self):
            self.ad_group_instance = ADGroup(GROUP_DN)
        
        def get_attributes(self):            
            return self.ad_group_instance.get_attributes()
        
        def get_name(self):            
            return self.ad_group_instance.get_attribute(NAME_ATTRIBUTE)
        
        def get_type(self):
            return self.ad_group_instance.get_attribute(TYPE_ATTRIBUTE)

Documentation
==================================

.. code:: python

    def add_member(account_name):
        """ Attempts to add a member to the AD group.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory. (inherited from get_user_dn)
        :raises: **AccountAlreadyExists** if the account already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

    def remove_member(account_name):
        """ Attempts to remove a member from the AD group.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory. (inherited from get_user_dn)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

    def get_member_info():
        """ Retrieves member information from the AD group object.

        :returns: A dictionary of information on members of the AD group based on the LDAP_GROUPS_ATTRIBUTE_LIST setting or attr_list argument.

        """

    def get_attribute(attribute_name):
        """ Gets the passed attribute of this group.

        :param attribute_name: The name of the attribute to get.
        :type attribute_name: str

        :returns: The attribute requested or None if the attribute is not set.

        """

    def get_attributes():
        """ Returns a dictionary of this group's attributes."""

    def get_children():
        """ Returns a list of this group's children."""

    def child(group_name):
        """ Returns the child ADGroup that matches the provided group_name.

        :param group_name: The name of the child group. NOTE: A name does not contain 'CN=' or 'OU='
        :type group_name: str

        """

    def parent():
        """ Returns this group's parent (up to the DC)"""

    def ancestor(generation):
        """ Returns an ancestor of this group given a generation (up to the DC).

        :param generation: Determines how far up the path to go. Example: 0 = self, 1 = parent, 2 = grandparent ...
        :type generation: int

        """


Running ldap-groups without Django
==================================

If ldap-groups is not used in a django project, the ADGroup object can be initialized with the following parameters:

.. code:: python

    ADGroup(group_dn, server_uri, base_dn[, user_lookup_attr[, attr_list[, bind_dn, bind_password]]])


* ``group_dn`` - The distinguished name of the group to manage.
* ``server_uri`` - The ldap server's uri, e.g. 'ldap://example.com'
* ``base_dn`` - The base search dn, e.g. 'DC=example,DC=com'
* ``user_lookup_attr`` - The attribute by which to search when looking up users (should be unique). Defaults to ``'sAMAccountName'``.
* ``group_attr_list`` - A list of attributes returned for each member while pulling group members. An empty list should return all attributes. Defaults to ``['displayName', 'sAMAccountName', 'distinguishedName']``.
* ``bind_dn`` - The bind user's DN
* ``bind_password`` - The bind user's password
