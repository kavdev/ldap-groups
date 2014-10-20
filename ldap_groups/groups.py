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

import logging
from string import whitespace

from ldap3 import Server, Connection, SEARCH_SCOPE_BASE_OBJECT, SEARCH_SCOPE_WHOLE_SUBTREE, MODIFY_DELETE, MODIFY_ADD, ALL_ATTRIBUTES, NO_ATTRIBUTES
from ldap3.core.exceptions import (LDAPException, LDAPExceptionError, LDAPInvalidServerError, LDAPInvalidCredentialsResult, LDAPOperationsErrorResult, LDAPInvalidDNSyntaxResult,
                                   LDAPNoSuchObjectResult, LDAPSizeLimitExceededResult, LDAPEntryAlreadyExistsResult, LDAPInsufficientAccessRightsResult, )

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
            'scope': SEARCH_SCOPE_BASE_OBJECT,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': ALL_ATTRIBUTES
        }

        self.USER_SEARCH = {
            'base_dn': self.base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(objectClass=user)({lookup_attribute}={{lookup_value}}))".format(lookup_attribute=self.user_lookup_attr),
            'attribute_list': NO_ATTRIBUTES
        }

        self.GROUP_MEMBER_SEARCH = {
            'base_dn': self.base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(objectCategory=user)(memberOf={group_dn}))",
            'attribute_list': self.attr_list
        }

        self.GROUP_CHILDREN_SEARCH = {
            'base_dn': self.base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(|(objectClass=group)(objectClass=organizationalUnit))(memberOf={group_dn}))".format(group_dn=self.group_dn),
            'attribute_list': NO_ATTRIBUTES
        }

        self.GROUP_SINGLE_CHILD_SEARCH = {
            'base_dn': self.base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(&(|(objectClass=group)(objectClass=organizationalUnit))(name={{child_group_name}}))(memberOf={parent_dn}))".format(parent_dn=self.group_dn),
            'attribute_list': NO_ATTRIBUTES
        }

        self.VALID_GROUP_TEST = {
            'base_dn': self.group_dn,
            'scope': SEARCH_SCOPE_BASE_OBJECT,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': NO_ATTRIBUTES
        }

        # ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)

        ldap_server = Server(self.server_uri)

        if self.bind_dn and self.bind_password:
            try:
                self.ldap_connection = Connection(ldap_server, auto_bind=True, user=self.bind_dn, password=self.bind_password, raise_exceptions=True)
            except LDAPInvalidServerError:
                raise LDAPServerUnreachable("The LDAP server is down or the SERVER_URI is invalid.")
            except LDAPInvalidCredentialsResult:
                raise InvalidCredentials("The SERVER_URI, BIND_DN, or BIND_PASSWORD provided is not valid.")
        else:
            logger.warning("LDAP Bind Credentials are not set. Group modification methods will most likely fail.")
            self.ldap_connection = Connection(ldap_server, auto_bind=True, raise_exceptions=True)

        # Make sure the group is valid
        valid, reason = self._get_valididty()

        if not valid:
            raise InvalidGroupDN("The AD Group distinguished name provided is invalid:\n\t{reason}".format(reason=reason))

    def __del__(self):
        """Closes the LDAP connection."""

        self.ldap_connection.unbind()

    def _get_valididty(self):
        """ Determines whether this AD Group is valid.

        :returns: True and "" if this group is valid or False and a string description with the reason why it isn't valid otherwise.

        """

        try:
            self.ldap_connection.search(search_base=self.VALID_GROUP_TEST['base_dn'],
                                        search_filter=self.VALID_GROUP_TEST['filter_string'],
                                        search_scope=self.VALID_GROUP_TEST['scope'],
                                        attributes=self.VALID_GROUP_TEST['attribute_list'])
        except LDAPOperationsErrorResult as error_message:
            raise ImproperlyConfigured("The LDAP server most-likely does not accept anonymous connections: \n\t{error}".format(error=error_message[0]['info']))
        except LDAPInvalidDNSyntaxResult:
            return False, "Invalid DN Syntax: {group_dn}".format(group_dn=self.group_dn)
        except LDAPNoSuchObjectResult:
            return False, "No such group: {group_dn}".format(group_dn=self.group_dn)
        except LDAPSizeLimitExceededResult:
            return False, "This group has too many children for ldap-groups to handle: {group_dn}".format(group_dn=self.group_dn)

        return True, ""

    def _get_user_dn(self, account_name):
        """ Searches for a user and retrieve his distinguished name.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory.

        """
        self.ldap_connection.search(search_base=self.USER_SEARCH['base_dn'],
                                    search_filter=self.USER_SEARCH['filter_string'].format(lookup_value=account_name),
                                    search_scope=self.USER_SEARCH['scope'],
                                    attributes=self.USER_SEARCH['attribute_list'])
        results = [result["dn"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        if not results:
            raise AccountDoesNotExist("The account name provided does not exist in the Active Directory.")

        if len(results) > 1:
            logger.debug("Search returned more than one result: {results}".format(results=results))

        if results:
            return results[0]
        else:
            return results

    def _get_group_members(self):
        """ Searches for a group and retrieve its members."""

        self.ldap_connection.search(search_base=self.GROUP_MEMBER_SEARCH['base_dn'],
                                    search_filter=self.GROUP_MEMBER_SEARCH['filter_string'].format(group_dn=self.group_dn),
                                    search_scope=self.GROUP_MEMBER_SEARCH['scope'],
                                    attributes=self.GROUP_MEMBER_SEARCH['attribute_list'])
        return [{"dn": result["dn"], "attributes": result["attributes"]} for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

    def _attempt_modification(self, account_name, modification):

        mod_type = list(modification.values())[0][0]
        action_word = "adding" if mod_type == MODIFY_ADD else "removing"
        action_prep = "to" if mod_type == MODIFY_ADD else "from"

        message_base = "Error {action} user '{user}' {prep} group '{group_dn}': ".format(action=action_word,
                                                                                      user=account_name,
                                                                                      prep=action_prep,
                                                                                      group_dn=self.group_dn)

        try:
            self.ldap_connection.modify(dn=self.group_dn, changes=modification)
        except LDAPEntryAlreadyExistsResult:
            raise AccountAlreadyExists(message_base + "The user already exists.")
        except LDAPInsufficientAccessRightsResult:
            raise InsufficientPermissions(message_base + "The bind user does not have permission to modify this group.")
        except (LDAPException, LDAPExceptionError) as error_message:
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

        add_member = {'member': (MODIFY_ADD, [self._get_user_dn(account_name)])}
        self._attempt_modification(account_name, add_member)

    def remove_member(self, account_name):
        """ Attempts to remove a member from the AD group.

        :param account_name: The user's active directory account name.
        :type account_name: str

        :raises: **AccountDoesNotExist** if the provided account name doesn't exist in the active directory. (inherited from get_user_dn)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        remove_member = {'member': (MODIFY_DELETE, [self._get_user_dn(account_name)])}
        self._attempt_modification(account_name, remove_member)

    def get_member_info(self):
        """ Retrieves member information from the AD group object.

        :returns: A dictionary of information on members of the AD group based on the LDAP_GROUPS_ATTRIBUTE_LIST setting or attr_list argument.

        """

        member_info = []

        for member in self._get_group_members():
            info_dict = {}

            for attribute_name in member["attributes"]:
                raw_attribute = member["attributes"][attribute_name]

                # Pop one-item lists
                if len(raw_attribute) == 1:
                    raw_attribute = raw_attribute.pop()

                info_dict.update({attribute_name: raw_attribute})

            member_info.append(info_dict)

        return member_info

    def get_attribute(self, attribute_name):
        """ Gets the passed attribute of this group.

        :param attribute_name: The name of the attribute to get.
        :type attribute_name: str

        :returns: The attribute requested or None if the attribute is not set.

        """

        self.ldap_connection.search(search_base=self.ATTRIBUTES_SEARCH['base_dn'],
                                    search_filter=self.ATTRIBUTES_SEARCH['filter_string'],
                                    search_scope=self.ATTRIBUTES_SEARCH['scope'],
                                    attributes=[attribute_name])

        results = [result["attributes"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        if len(results) != 1:
            logger.debug("Search returned {count} results: {results}".format(count=len(results), results=results))

        attributes = results[0]

        if attribute_name not in attributes:
            logger.debug("ADGroup {group_dn} does not have the attribute '{attribute}'.".format(group_dn=self.group_dn, attribute=attribute_name))
            return None
        else:
            raw_attribute = attributes[attribute_name]

            # Pop one-item lists
            if len(raw_attribute) == 1:
                raw_attribute = raw_attribute.pop()

            return raw_attribute

    def get_attributes(self):
        """ Returns a dictionary of this group's attributes."""

        self.ldap_connection.search(search_base=self.ATTRIBUTES_SEARCH['base_dn'],
                                    search_filter=self.ATTRIBUTES_SEARCH['filter_string'],
                                    search_scope=self.ATTRIBUTES_SEARCH['scope'],
                                    attributes=self.ATTRIBUTES_SEARCH['attribute_list'])

        results = [result["attributes"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        if len(results) != 1:
            logger.debug("Search returned {count} results: {results}".format(count=len(results), results=results))

        if results:
            return results[0]
        else:
            return results

    def get_children(self):
        """ Returns a list of this group's children."""

        children = []

        self.ldap_connection.search(search_base=self.GROUP_CHILDREN_SEARCH['base_dn'],
                                    search_filter=self.GROUP_CHILDREN_SEARCH['filter_string'],
                                    search_scope=self.GROUP_CHILDREN_SEARCH['scope'],
                                    attributes=self.GROUP_CHILDREN_SEARCH['attribute_list'])

        results = [result["dn"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        for result in results:
            children.append(ADGroup(result, self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password))

        return children

    def child(self, group_name):
        """ Returns the child ad group that matches the provided group_name.

        :param group_name: The name of the child group. NOTE: A name does not contain 'CN=' or 'OU='
        :type group_name: str

        """

        self.ldap_connection.search(search_base=self.GROUP_SINGLE_CHILD_SEARCH['base_dn'],
                                    search_filter=self.GROUP_SINGLE_CHILD_SEARCH['filter_string'].format(child_group_name=group_name),
                                    search_scope=self.GROUP_SINGLE_CHILD_SEARCH['scope'],
                                    attributes=self.GROUP_SINGLE_CHILD_SEARCH['attribute_list'])

        results = [result["dn"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        if len(results) != 1:
            logger.debug("Search returned {count} results: {results}".format(count=len(results), results=results))

        return ADGroup(results[0], self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password)

    def parent(self):
        """ Returns this group's parent (up to the DC)"""

        # Don't go above the DC
        if self.group_dn.split("DC")[0].translate(None, whitespace) == '':
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

            for x in range(generation):
                if ancestor_dn.split("DC")[0].translate(None, whitespace) == '':
                    break
                else:
                    ancestor_dn = ancestor_dn.split(",", 1).pop()

            return ADGroup(ancestor_dn, self.server_uri, self.base_dn, self.user_lookup_attr, self.attr_list, self.bind_dn, self.bind_password)

    def search(self, filter_string, base_dn=None, scope=None, attr_list=None):
        base_dn = self.base_dn if not base_dn else base_dn
        scope = self.scope if not scope else SEARCH_SCOPE_WHOLE_SUBTREE
        attr_list = self.attr_list if not attr_list else ALL_ATTRIBUTES

        return self.ldap_connection.search(search_base=base_dn, search_filter=filter_string, search_scope=scope, attributes=attr_list)

    def __repr__(self):
        try:
            return "<ADGroup: " + str(self.group_dn.split(",", 1)[0]) + ">"
        except AttributeError:
            return "<ADGroup: " + str(self.group_dn) + ">"
