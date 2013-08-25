ldap-groups
%%%%%%%%%%%

A django Active Directory group management abstraction that uses python-ldap as a backend for cross-platform compatability.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:Version:           1.0.0
:Dependencies:      Python 2.7, Django 1.5.2+
:Home page:         https://bitbucket.org/alex_kavanaugh/ldap-groups
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


Settings
========

There are a few settings that must be configured before ldap-groups will run.

*Mandatory*

``LDAP_GROUPS_SERVER_URI`` - The ldap server's uri, e.g. 'ldap://example.com'
``LDAP_GROUPS_BASE_DN`` - The base search dn, e.g. 'DC=example,DC=com'

*Optional*

``LDAP_GROUPS_BIND_DN`` - The bind user's DN
``LDAP_GROUPS_BIND_PASSWORD`` - The bind user's password

NOTE: while a bind user is optional, many servers' security settings will deny anonymous access.

``LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE`` - The attribute by which to search when looking up users (should be unique). Defaults to ``'sAMAccountName'``.
``LDAP_GROUPS_ATTRIBUTE_LIST`` - A list of attributes returned for each member while pulling group members. An empty list should return all attributes. Defaults to ``['displayName', 'sAMAccountName', 'distinguishedName']``.


Usage
=====

In its current state, ldap-groups can perform three functions:

* Add a member to a group
* Remove a member from a group
* Get all members of a group (and their attributes) [only retrieves user object classes at this point]

An ADGroup instance only requires one argument to function: a group's distinguished name.
Once the ADGroup is instantiated, the rest is fairly simple:

.. code:: python

    from ldap_groups import ADGroup
    
    GROUP_DN = "ou=users,dc=example,dc=com"
    ACCOUNT_NAME = "jdoe"
    
    class ADGroupModifier(object):
    
        def __init__(self):
            self.ad_group_instance = ADGroup(GROUP_DN)
        
        def add_member(self):            
            self.ad_group_instance.add_member(ACCOUNT_NAME)
        
        def remove_member(self):            
            self.ad_group_instance.remove_member(ACCOUNT_NAME)
        
        def get_group_member_info(self):
            return self.ad_group_instance.get_member_info()
