"""
.. module:: ldap_groups.groups
    :synopsis: LDAP Groups Group Objects.

    ldap-groups is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ldap-groups is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with ldap-groups. If not, see <http://www.gnu.org/licenses/>.

.. moduleauthor:: Alex Kavanaugh <kavanaugh.development@outlook.com>

"""

import ldap
import logging

from .exceptions import (AccountDoesNotExist, InvalidGroupDN, ImproperlyConfigured, InvalidCredentials,
                         LDAPServerUnreachable, ModificationFailed, AccountAlreadyExists, InsufficientPermissions)

logger = logging.getLogger(__name__)


class ADGroup:
    """
    An Active Directory group.

    This methods in this class can add members to, remove members from, and view members of an Active Directory group,
    as well as traverse the Active Directory tree.

    """

    def __init__(self, group_dn, server_uri=None, base_dn=None, user_lookup_attr=None, attr_list=None, bind_dn=None, bind_password=None):
        """ Create an AD group object and establish an ldap search connection.
            Any arguments other than group_dn are pulled from django settings
            if they aren't passed in.

        :param group_dn: The distinguished name of the active directory group to be modified.
        :type group_dn: str

        :param server_uri: (Required) The ldap server uri. Pulled from Django settings if None.
        :type server_uri: str
        :param base_dn: (Required) The ldap base dn. Pulled from Django settings if None.
        :type base_dn: str
        :param user_lookup_attr: The attribute used in user searches. Default is 'sAMAccountName'.
        :type user_lookup_attr: str
        :param attr_list: A list of attributes to be pulled for each member of the AD group.
        :type attr_list: list
        :param bind_dn: A user used to bind to the AD. Necessary for any group modifications.
        :type bind_dn: str
        :param bind_password: The bind user's password. Necessary for any group modifications.
        :type bind_password: str

        """

        # Attempt to grab settings from Django, fall back to init arguments if django is not used
        try:
            from django.conf import settings
        except ImportError:
            if not server_uri and not base_dn:
                raise ImproperlyConfigured("A server_uri and base_dn must be passed as arguments if django settings are not used.")
            else:
                self.server_uri = server_uri
                self.base_dn = base_dn

            self.user_lookup_attr = user_lookup_attr if user_lookup_attr else 'sAMAccountName'
            self.attr_list = attr_list if attr_list else ['displayName', 'sAMAccountName', 'distinguishedName']

            self.bind_dn = bind_dn
            self.bind_password = bind_password
        else:
            if not server_uri:
                if hasattr(settings, 'LDAP_GROUPS_SERVER_URI'):
                    self.server_uri = getattr(settings, 'LDAP_GROUPS_SERVER_URI')
                else:
                    raise ImproperlyConfigured("LDAP Groups required setting LDAP_GROUPS_SERVER_URI is not configured in django settings file.")
            else:
                self.server_uri = server_uri

            if not base_dn:
                if hasattr(settings, 'LDAP_GROUPS_BASE_DN'):
                    self.base_dn = getattr(settings, 'LDAP_GROUPS_BASE_DN') if not base_dn else base_dn
                else:
                    raise ImproperlyConfigured("LDAP Groups required setting LDAP_GROUPS_BASE_DN is not configured in django settings file.")
            else:
                self.base_dn = base_dn

            self.user_lookup_attr = getattr(settings, 'LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE', 'sAMAccountName') if not user_lookup_attr else user_lookup_attr
            self.attr_list = getattr(settings, 'LDAP_GROUPS_ATTRIBUTE_LIST', ['displayName', 'sAMAccountName', 'distinguishedName']) if not attr_list else attr_list
            self.bind_dn = getattr(settings, 'LDAP_GROUPS_BIND_DN', None) if not bind_dn else bind_dn
            self.bind_password = getattr(settings, 'LDAP_GROUPS_BIND_PASSWORD', None) if not bind_password else bind_password

        self.group_dn = group_dn

        # Initialize search objects
        self.ATTRIBUTES_SEARCH = {
            'base_dn': self.group_dn,
            'scope': ldap.SCOPE_BASE,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': []
        }

        self.USER_SEARCH = {
            'base_dn': self.base_dn,
            'scope': ldap.SCOPE_SUBTREE,
            'filter_string': "(&(objectClass=user)(" + self.user_lookup_attr + "=%s))",
            'attribute_list': []
        }

        self.GROUP_MEMBER_SEARCH = {
            'base_dn': self.base_dn,
            'scope': ldap.SCOPE_SUBTREE,
            'filter_string': "(&(objectCategory=user)(memberOf=%s))",
            'attribute_list': self.attr_list
        }

        self.GROUP_CHILDREN_SEARCH = {
            'base_dn': self.group_dn,
            'scope': ldap.SCOPE_ONELEVEL,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': []
        }

        self.GROUP_SINGLE_CHILD_SEARCH = {
            'base_dn': self.group_dn,
            'scope': ldap.SCOPE_ONELEVEL,
            'filter_string': "(&(|(objectClass=group)(objectClass=organizationalUnit))(name=%s))",
            'attribute_list': []
        }

        self.VALID_GROUP_TEST = {
            'base_dn': self.group_dn,
            'scope': ldap.SCOPE_BASE,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': []
        }

        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
        self.ldap_connection = ldap.initialize(self.server_uri)

        if self.bind_dn and self.bind_password:
            try:
                self.ldap_connection.simple_bind_s(self.bind_dn, self.bind_password)
            except ldap.SERVER_DOWN:
                raise LDAPServerUnreachable("The LDAP server is down or the SERVER_URI is invalid.")
            except ldap.INVALID_CREDENTIALS:
                raise InvalidCredentials("The SERVER_URI, BIND_DN, or BIND_PASSWORD provided is not valid.")
        else:
            logger.warning("LDAP Bind Credentials are not set. Group modification methods will most likely fail.")
            self.ldap_connection.simple_bind_s()

        # Make sure the group is valid
        valid, reason = self._get_valididty()

        if not valid:
            raise InvalidGroupDN("The AD Group distinguished name provided is invalid:\n\t%s" % reason)

    def __del__(self):
        """Closes the LDAP connection."""

        self.ldap_connection.unbind_s()

    def _get_valididty(self):
        """ Determines whether this AD Group is valid.

        :returns: True and "" if this group is valid or False and a string description with the reason why it isn't valid otherwise.

        """

        try:
            self.ldap_connection.search_s(self.VALID_GROUP_TEST['base_dn'], self.VALID_GROUP_TEST['scope'], self.VALID_GROUP_TEST['filter_string'], self.VALID_GROUP_TEST['attribute_list'])
        except ldap.OPERATIONS_ERROR, error_message:
            raise ImproperlyConfigured("The LDAP server most-likely does not accept anonymous connections: \n\t%s" % error_message[0]['info'])
        except (ldap.INVALID_DN_SYNTAX):
            return False, "Invalid DN Syntax: %s" % self.group_dn
        except (ldap.NO_SUCH_OBJECT):
            return False, "No such group: %s" % self.group_dn
        except (ldap.SIZELIMIT_EXCEEDED):
            return False, "This group has too many children for ldap-groups to handle: %s" % self.group_dn

        return True, ""

    def _get_user_dn(self, account_name):
        """ Searches for a user and retrieve his distinguished name.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory.

        """

        try:
            return self.ldap_connection.search_s(self.USER_SEARCH['base_dn'], self.USER_SEARCH['scope'], self.USER_SEARCH['filter_string'] % account_name, self.USER_SEARCH['attribute_list'])[0][0]
        except (TypeError, IndexError):
            raise AccountDoesNotExist("The account name provided does not exist in the Active Directory.")

    def _get_group_members(self):
        """ Searches for a group and retrieve its members."""

        return self.ldap_connection.search_s(self.GROUP_MEMBER_SEARCH['base_dn'], self.GROUP_MEMBER_SEARCH['scope'], self.GROUP_MEMBER_SEARCH['filter_string'] % self.group_dn, self.GROUP_MEMBER_SEARCH['attribute_list'])

    def _attempt_modification(self, account_name, modification):

        mod_type = modification[0][0]
        action_word = "adding" if mod_type == ldap.MOD_ADD else "removing"
        action_prep = "to" if mod_type == ldap.MOD_ADD else "from"

        message_base = "Error %(action)s user '%(user)s' %(prep)s group '%(group)s': " % {'action': action_word,
                                                                                          'user': account_name,
                                                                                          'prep': action_prep,
                                                                                          'group': self.group_dn}

        try:
            self.ldap_connection.modify_s(self.group_dn, modification)
        except ldap.ALREADY_EXISTS:
            raise AccountAlreadyExists(message_base + "The user already exists.")
        except ldap.INSUFFICIENT_ACCESS:
            raise InsufficientPermissions(message_base + "The bind user does not have permission to modify this group.")
        except ldap.LDAPError, error_message:
            raise ModificationFailed(message_base + str(error_message))

    def add_member(self, account_name):
        """ Attempts to add a member to the AD group.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory. (inherited from get_user_dn)
        :raises: **AccountAlreadyExists** if the account already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        add_member = [(ldap.MOD_ADD, 'member', self._get_user_dn(account_name))]
        self._attempt_modification(account_name, add_member)

    def remove_member(self, account_name):
        """ Attempts to remove a member from the AD group.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory. (inherited from get_user_dn)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        remove_member = [(ldap.MOD_DELETE, 'member', self._get_user_dn(account_name))]
        self._attempt_modification(account_name, remove_member)

    def get_member_info(self):
        """ Retrieves member information from the AD group object.

        :returns: A dictionary of information on members of the AD group based on the LDAP_GROUPS_ATTRIBUTE_LIST setting or attr_list argument.

        """

        member_info = []

        for member in self._get_group_members():
            if member[0]:
                info_dict = {}

                for attribute in self.GROUP_MEMBER_SEARCH['attribute_list']:
                    info_dict.update({attribute: member[-1][attribute][0]})

                member_info.append(info_dict)

        return member_info

    def get_attribute(self, attribute_name):
        """ Gets the passed attribute of this group.

        :param attribute_name: The name of the attribute to get.
        :type attribute_name: str

        :returns: The attribute requested or None if the attribute is not set.

        """

        result = self.ldap_connection.search_s(self.ATTRIBUTES_SEARCH['base_dn'], self.ATTRIBUTES_SEARCH['scope'], self.ATTRIBUTES_SEARCH['filter_string'], [attribute_name])[0]

        try:
            return result[1][attribute_name].pop()
        except (KeyError, IndexError):
            logger.debug("ADGroup %s does not have the attribute '%s'." % (self.group_dn, attribute_name))
            return None

    def get_attributes(self):
        """ Returns a dictionary of this group's attributes."""

        result = self.ldap_connection.search_s(self.ATTRIBUTES_SEARCH['base_dn'], self.ATTRIBUTES_SEARCH['scope'], self.ATTRIBUTES_SEARCH['filter_string'])

        if not result:
            return result
        else:
            return result[0][1]

    def get_children(self):
        """ Returns a list of this group's children."""

        children = []

        results = self.ldap_connection.search_s(self.GROUP_CHILDREN_SEARCH['base_dn'], self.GROUP_CHILDREN_SEARCH['scope'], self.GROUP_CHILDREN_SEARCH['filter_string'], self.GROUP_CHILDREN_SEARCH['attribute_list'])

        for result in results:
            if result[0]:
                children.append(ADGroup(result[0], self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password))

        return children

    def child(self, group_name):
        """ Returns the child ad group that matches the provided group_name.

        :param group_name: The name of the child group. NOTE: A name does not contain 'CN=' or 'OU='
        :type group_name: str

        """

        result = self.ldap_connection.search_s(self.GROUP_SINGLE_CHILD_SEARCH['base_dn'], self.GROUP_SINGLE_CHILD_SEARCH['scope'], self.GROUP_SINGLE_CHILD_SEARCH['filter_string'] % group_name, self.GROUP_SINGLE_CHILD_SEARCH['attribute_list'])[0]

        return ADGroup(result[0], self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password)

    def parent(self):
        """ Returns this group's parent (up to the DC)"""

        # Don't go above the DC
        if self.group_dn.split("DC")[0] == '':
            return self
        else:
            parent_dn = self.group_dn.split(",", 1).pop()
            return ADGroup(parent_dn, self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password)

    def ancestor(self, generation):
        """ Returns an ancestor of this group given a generation (up to the DC).

        :param generation: Determines how far up the path to go. Example: 0 = self, 1 = parent, 2 = grandparent ...
        :type generation: int

        """

        # Don't go below the current generation and don't go above the DC
        if generation < 1:
            return self
        else:
            ancestor_dn = self.group_dn

            for x in xrange(generation):
                if ancestor_dn.split("DC")[0] == '':
                    break
                else:
                    ancestor_dn = ancestor_dn.split(",", 1).pop()

            return ADGroup(ancestor_dn, self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password)

    def __repr__(self):
        return "<ADGroup: " + str(self.group_dn.split(",", 1)[0]) + ">"
