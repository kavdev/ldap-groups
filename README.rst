ldap-groups
%%%%%%%%%%%

A python/django Active Directory group management abstraction that uses python3-ldap as a backend for cross-platform compatibility.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:Version:           4.0.0
:Dependencies:      Python 2.7+, 3.2+, python3-ldap>=0.9.6
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
* ``LDAP_GROUPS_USER_SEARCH_BASE_DN`` - The base dn to use when looking up users. Defaults to ``LDAP_GROUPS_BASE_DN``.
* ``LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE`` - The attribute by which to search when looking up groups (should be unique). Defaults to ``'name'``.
* ``LDAP_GROUPS_GROUP_SEARCH_BASE_DN`` - The base dn to use when looking up groups. Defaults to ``LDAP_GROUPS_BASE_DN``.
* ``LDAP_GROUPS_ATTRIBUTE_LIST`` - A list of attributes returned for each member while pulling group members. An empty list should return all attributes. Defaults to ``['displayName', 'sAMAccountName', 'distinguishedName']``.


Usage
=====

In its current state, ldap-groups can perform the following functions:


* Get a specific attribute of a group
* Get all attributes of a group in dictionary form
* Get all members of a group and their attributes (users)
* Add a member to a group (user)
* Remove a member from a group (user)
* Add a child to a group (nested group)
* Remove a child from a group (nested group)
* Get all descendants of a group (groups and organizational units)
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


    def get_attribute(attribute_name, no_cache=False):
        """ Gets the passed attribute of this group.

        :param attribute_name: The name of the attribute to get.
        :type attribute_name: str
        :param no_cache (optional): Set to True to pull the attribute directly from an LDAP search instead of from the cache. Default False.
        :type no_cache: boolean

        :returns: The attribute requested or None if the attribute is not set.

        """

    def get_attributes(no_cache=False):
        """ Returns a dictionary of this group's attributes. This method caches the attributes after the first search unless no_cache is specified.

        :param no_cache (optional): Set to True to pull attributes directly from an LDAP search instead of from the cache. Default False
        :type no_cache: boolean

        """

    def _get_group_members(page_size=500):
        """ Searches for a group and retrieve its members.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

    def get_member_info(page_size=500):
        """ Retrieves member information from the AD group object.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        :returns: A dictionary of information on members of the AD group based on the LDAP_GROUPS_ATTRIBUTE_LIST setting or attr_list argument.

        """

    def add_member(user_lookup_attribute_value):
        """ Attempts to add a member to the AD group.

        :param user_lookup_attribute_value: The value for the LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE.
        :type user_lookup_attribute_value: str

        :raises: **AccountDoesNotExist** if the provided account doesn't exist in the active directory. (inherited from _get_user_dn)
        :raises: **EntryAlreadyExists** if the account already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

    def remove_member(user_lookup_attribute_value):
        """ Attempts to remove a member from the AD group.

        :param user_lookup_attribute_value: The value for the LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE.
        :type user_lookup_attribute_value: str

        :raises: **AccountDoesNotExist** if the provided account doesn't exist in the active directory. (inherited from _get_user_dn)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

    def add_child(group_lookup_attribute_value):
        """ Attempts to add a child to the AD group.

        :param group_lookup_attribute_value: The value for the LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE.
        :type group_lookup_attribute_value: str

        :raises: **GroupDoesNotExist** if the provided group doesn't exist in the active directory. (inherited from _get_group_dn)
        :raises: **EntryAlreadyExists** if the child already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

    def remove_child(group_lookup_attribute_value):
        """ Attempts to remove a child from the AD group.

        :param group_lookup_attribute_value: The value for the LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE.
        :type group_lookup_attribute_value: str

        :raises: **GroupDoesNotExist** if the provided group doesn't exist in the active directory. (inherited from _get_group_dn)
        :raises: **EntryAlreadyExists** if the child already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

    def get_descendants(page_size=500):
        """ Returns a list of all descendants of this group.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

    def get_children(page_size=500):
        """ Returns a list of this group's children.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

    def child(group_name, page_size=500):
        """ Returns the child ad group that matches the provided group_name or none if the child does not exist.

        :param group_name: The name of the child group. NOTE: A name does not contain 'CN=' or 'OU='
        :type group_name: str
        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

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

    ADGroup(group_dn, server_uri, base_dn[, user_lookup_attr[, group_lookup_attr[, attr_list[, bind_dn, bind_password[, user_search_base_dn[, group_search_base_dn]]]]]])


* ``group_dn`` - The distinguished name of the group to manage.
* ``server_uri`` - The ldap server's uri, e.g. 'ldap://example.com'
* ``base_dn`` - The base search dn, e.g. 'DC=example,DC=com'
* ``user_lookup_attr`` - The attribute by which to search when looking up users (should be unique). Defaults to ``'sAMAccountName'``.
* ``group_lookup_attr`` - The attribute by which to search when looking up groups (should be unique). Defaults to ``'name'``.
* ``attr_list`` - A list of attributes returned for each member while pulling group members. An empty list should return all attributes. Defaults to ``['displayName', 'sAMAccountName', 'distinguishedName']``.
* ``bind_dn`` - The bind user's DN
* ``bind_password`` - The bind user's password
* ``user_search_base_dn`` - The base dn to use when looking up users. Defaults to ``LDAP_GROUPS_BASE_DN``.
* ``group_search_base_dn`` - The base dn to use when looking up groups. Defaults to ``LDAP_GROUPS_BASE_DN``.

