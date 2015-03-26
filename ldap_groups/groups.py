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

from ldap3 import Server, Connection, SEARCH_SCOPE_BASE_OBJECT, SEARCH_SCOPE_WHOLE_SUBTREE, MODIFY_DELETE, MODIFY_ADD, ALL_ATTRIBUTES, NO_ATTRIBUTES, SEARCH_SCOPE_SINGLE_LEVEL
from ldap3.core.exceptions import (LDAPException, LDAPExceptionError, LDAPInvalidServerError, LDAPInvalidCredentialsResult, LDAPOperationsErrorResult, LDAPInvalidDNSyntaxResult,
                                   LDAPNoSuchObjectResult, LDAPSizeLimitExceededResult, LDAPEntryAlreadyExistsResult, LDAPInsufficientAccessRightsResult, LDAPInvalidFilterError)

from .exceptions import (AccountDoesNotExist, GroupDoesNotExist, InvalidGroupDN, ImproperlyConfigured, InvalidCredentials,
                         LDAPServerUnreachable, ModificationFailed, EntryAlreadyExists, InsufficientPermissions)

from .utils import escape_query

logger = logging.getLogger(__name__)


class ADGroup:
    """
    An Active Directory group.

    This methods in this class can add members to, remove members from, and view members of an Active Directory group,
    as well as traverse the Active Directory tree.

    """

    def __init__(self, group_dn, server_uri=None, base_dn=None, user_lookup_attr=None, group_lookup_attr=None, attr_list=None, bind_dn=None, bind_password=None, user_search_base_dn=None, group_search_base_dn=None):
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
        :param group_lookup_attr: The attribute used in group searches. Default is 'name'.
        :type group_lookup_attr: str
        :param attr_list: A list of attributes to be pulled for each member of the AD group.
        :type attr_list: list
        :param bind_dn: A user used to bind to the AD. Necessary for any group modifications.
        :type bind_dn: str
        :param bind_password: The bind user's password. Necessary for any group modifications.
        :type bind_password: str
        :param user_search_base_dn: The base dn to use when performing a user search. Defaults to base_dn.
        :type user_search_base_dn: str
        :param group_search_base_dn: The base dn to use when performing a group search. Defaults to base_dn. Currently unused.
        :type group_search_base_dn: str

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
            self.group_lookup_attr = group_lookup_attr if group_lookup_attr else 'name'
            self.attr_list = attr_list if attr_list else ['displayName', 'sAMAccountName', 'distinguishedName']

            self.bind_dn = bind_dn
            self.bind_password = bind_password
            self.user_search_base_dn = user_search_base_dn if user_search_base_dn else self.base_dn
            self.group_search_base_dn = group_search_base_dn if group_search_base_dn else self.base_dn
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
            self.group_lookup_attr = getattr(settings, 'LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE', 'name') if not group_lookup_attr else group_lookup_attr
            self.attr_list = getattr(settings, 'LDAP_GROUPS_ATTRIBUTE_LIST', ['displayName', 'sAMAccountName', 'distinguishedName']) if not attr_list else attr_list
            self.bind_dn = getattr(settings, 'LDAP_GROUPS_BIND_DN', None) if not bind_dn else bind_dn
            self.bind_password = getattr(settings, 'LDAP_GROUPS_BIND_PASSWORD', None) if not bind_password else bind_password
            self.user_search_base_dn = getattr(settings, 'LDAP_GROUPS_USER_SEARCH_BASE_DN', self.base_dn) if not user_search_base_dn else user_search_base_dn
            self.group_search_base_dn = getattr(settings, 'LDAP_GROUPS_GROUP_SEARCH_BASE_DN', self.base_dn) if not group_search_base_dn else group_search_base_dn

        self.group_dn = group_dn
        self.attributes = []

        # Initialize search objects
        self.ATTRIBUTES_SEARCH = {
            'base_dn': self.group_dn,
            'scope': SEARCH_SCOPE_BASE_OBJECT,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': ALL_ATTRIBUTES
        }

        self.USER_SEARCH = {
            'base_dn': self.user_search_base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(objectClass=user)({lookup_attribute}={{lookup_value}}))".format(lookup_attribute=escape_query(self.user_lookup_attr)),
            'attribute_list': NO_ATTRIBUTES
        }

        self.GROUP_SEARCH = {
            'base_dn': self.group_search_base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(objectClass=group)({lookup_attribute}={{lookup_value}}))".format(lookup_attribute=escape_query(self.group_lookup_attr)),
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
            'filter_string': "(&(|(objectClass=group)(objectClass=organizationalUnit))(memberOf={group_dn}))".format(group_dn=escape_query(self.group_dn)),
            'attribute_list': NO_ATTRIBUTES
        }

        self.OU_CHILDREN_SEARCH = {
            'base_dn': self.group_dn,
            'scope': SEARCH_SCOPE_SINGLE_LEVEL,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': NO_ATTRIBUTES
        }

        self.GROUP_SINGLE_CHILD_SEARCH = {
            'base_dn': self.base_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(&(&(|(objectClass=group)(objectClass=organizationalUnit))(name={{child_group_name}}))(memberOf={parent_dn}))".format(parent_dn=escape_query(self.group_dn)),
            'attribute_list': NO_ATTRIBUTES
        }

        self.OU_SINGLE_CHILD_SEARCH = {
            'base_dn': self.group_dn,
            'scope': SEARCH_SCOPE_SINGLE_LEVEL,
            'filter_string': "(&(|(objectClass=group)(objectClass=organizationalUnit))(name={child_group_name}))",
            'attribute_list': NO_ATTRIBUTES
        }

        self.DESCENDANT_SEARCH = {
            'base_dn': self.group_dn,
            'scope': SEARCH_SCOPE_WHOLE_SUBTREE,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': NO_ATTRIBUTES
        }

        self.VALID_GROUP_TEST = {
            'base_dn': self.group_dn,
            'scope': SEARCH_SCOPE_BASE_OBJECT,
            'filter_string': "(|(objectClass=group)(objectClass=organizationalUnit))",
            'attribute_list': NO_ATTRIBUTES
        }

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

    def __repr__(self):
        try:
            return "<ADGroup: " + str(self.group_dn.split(",", 1)[0]) + ">"
        except AttributeError:
            return "<ADGroup: " + str(self.group_dn) + ">"

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and self.group_dn == other.group_dn)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.group_dn < other.group_dn

    def __hash__(self):
        return hash(self.group_dn)

    ##############################################################################################################################################
    #                                                       Group Information Methods                                                            #
    ##############################################################################################################################################

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

    def get_attribute(self, attribute_name, no_cache=False):
        """ Gets the passed attribute of this group.

        :param attribute_name: The name of the attribute to get.
        :type attribute_name: str
        :param no_cache (optional): Set to True to pull the attribute directly from an LDAP search instead of from the cache. Default False.
        :type no_cache: boolean

        :returns: The attribute requested or None if the attribute is not set.

        """

        attributes = self.get_attributes(no_cache)

        if attribute_name not in attributes:
            logger.debug("ADGroup {group_dn} does not have the attribute '{attribute}'.".format(group_dn=self.group_dn, attribute=attribute_name))
            return None
        else:
            raw_attribute = attributes[attribute_name]

            # Pop one-item lists
            if len(raw_attribute) == 1:
                raw_attribute = raw_attribute[0]

            return raw_attribute

    def get_attributes(self, no_cache=False):
        """ Returns a dictionary of this group's attributes. This method caches the attributes after the first search unless no_cache is specified.

        :param no_cache (optional): Set to True to pull attributes directly from an LDAP search instead of from the cache. Default False
        :type no_cache: boolean

        """

        if not self.attributes:
            self.ldap_connection.search(search_base=self.ATTRIBUTES_SEARCH['base_dn'],
                                        search_filter=self.ATTRIBUTES_SEARCH['filter_string'],
                                        search_scope=self.ATTRIBUTES_SEARCH['scope'],
                                        attributes=self.ATTRIBUTES_SEARCH['attribute_list'])

            results = [result["attributes"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

            if len(results) != 1:
                logger.debug("Search returned {count} results: {results}".format(count=len(results), results=results))

            if results:
                self.attributes = results[0]
            else:
                self.attributes = []

        return self.attributes

    def _get_user_dn(self, user_lookup_attribute_value):
        """ Searches for a user and retrieves his distinguished name.

        :param user_lookup_attribute_value: The value for the LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE
        :type user_lookup_attribute_value: str

        :raises: **AccountDoesNotExist** if the account doesn't exist in the active directory.

        """
        self.ldap_connection.search(search_base=self.USER_SEARCH['base_dn'],
                                    search_filter=self.USER_SEARCH['filter_string'].format(lookup_value=escape_query(user_lookup_attribute_value)),
                                    search_scope=self.USER_SEARCH['scope'],
                                    attributes=self.USER_SEARCH['attribute_list'])
        results = [result["dn"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        if not results:
            raise AccountDoesNotExist("The {user_lookup_attribute} provided does not exist in the Active Directory.".format(user_lookup_attribute=self.user_lookup_attr))

        if len(results) > 1:
            logger.debug("Search returned more than one result: {results}".format(results=results))

        if results:
            return results[0]
        else:
            return results

    def _get_group_dn(self, group_lookup_attribute_value):
        """ Searches for a group and retrieves its distinguished name.

        :param group_lookup_attribute_value: The value for the LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE
        :type group_lookup_attribute_value: str

        :raises: **GroupDoesNotExist** if the group doesn't exist in the active directory.

        """
        self.ldap_connection.search(search_base=self.GROUP_SEARCH['base_dn'],
                                    search_filter=self.GROUP_SEARCH['filter_string'].format(lookup_value=escape_query(group_lookup_attribute_value)),
                                    search_scope=self.GROUP_SEARCH['scope'],
                                    attributes=self.GROUP_SEARCH['attribute_list'])
        results = [result["dn"] for result in self.ldap_connection.response if result["type"] == "searchResEntry"]

        if not results:
            raise GroupDoesNotExist("The {group_lookup_attribute} provided does not exist in the Active Directory.".format(group_lookup_attribute=self.group_lookup_attr))

        if len(results) > 1:
            logger.debug("Search returned more than one result: {results}".format(results=results))

        if results:
            return results[0]
        else:
            return results

    def _get_group_members(self, page_size=500):
        """ Searches for a group and retrieve its members.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

        entry_list = self.ldap_connection.extend.standard.paged_search(search_base=self.GROUP_MEMBER_SEARCH['base_dn'],
                                                                       search_filter=self.GROUP_MEMBER_SEARCH['filter_string'].format(group_dn=escape_query(self.group_dn)),
                                                                       search_scope=self.GROUP_MEMBER_SEARCH['scope'],
                                                                       attributes=self.GROUP_MEMBER_SEARCH['attribute_list'],
                                                                       paged_size=page_size)
        return [{"dn": result["dn"], "attributes": result["attributes"]} for result in entry_list if result["type"] == "searchResEntry"]

    def get_member_info(self, page_size=500):
        """ Retrieves member information from the AD group object.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        :returns: A dictionary of information on members of the AD group based on the LDAP_GROUPS_ATTRIBUTE_LIST setting or attr_list argument.

        """

        member_info = []

        for member in self._get_group_members(page_size):
            info_dict = {}

            for attribute_name in member["attributes"]:
                raw_attribute = member["attributes"][attribute_name]

                # Pop one-item lists
                if len(raw_attribute) == 1:
                    raw_attribute = raw_attribute[0]

                info_dict.update({attribute_name: raw_attribute})

            member_info.append(info_dict)

        return member_info

    ##############################################################################################################################################
    #                                                      Group Modification Methods                                                            #
    ##############################################################################################################################################

    def _attempt_modification(self, target_type, target_identifier, modification):
        mod_type = list(modification.values())[0][0]
        action_word = "adding" if mod_type == MODIFY_ADD else "removing"
        action_prep = "to" if mod_type == MODIFY_ADD else "from"

        message_base = "Error {action} {target_type} '{target_id}' {prep} group '{group_dn}': ".format(action=action_word,
                                                                                                       target_type=target_type,
                                                                                                       target_id=target_identifier,
                                                                                                       prep=action_prep,
                                                                                                       group_dn=self.group_dn)

        try:
            self.ldap_connection.modify(dn=self.group_dn, changes=modification)
        except LDAPEntryAlreadyExistsResult:
            raise EntryAlreadyExists(message_base + "The {target_type} already exists.".format(target_type=target_type))
        except LDAPInsufficientAccessRightsResult:
            raise InsufficientPermissions(message_base + "The bind user does not have permission to modify this group.")
        except (LDAPException, LDAPExceptionError) as error_message:
            raise ModificationFailed(message_base + str(error_message))

    def add_member(self, user_lookup_attribute_value):
        """ Attempts to add a member to the AD group.

        :param user_lookup_attribute_value: The value for the LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE.
        :type user_lookup_attribute_value: str

        :raises: **AccountDoesNotExist** if the provided account doesn't exist in the active directory. (inherited from _get_user_dn)
        :raises: **EntryAlreadyExists** if the account already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        add_member = {'member': (MODIFY_ADD, [self._get_user_dn(user_lookup_attribute_value)])}
        self._attempt_modification("member", user_lookup_attribute_value, add_member)

    def remove_member(self, user_lookup_attribute_value):
        """ Attempts to remove a member from the AD group.

        :param user_lookup_attribute_value: The value for the LDAP_GROUPS_USER_LOOKUP_ATTRIBUTE.
        :type user_lookup_attribute_value: str

        :raises: **AccountDoesNotExist** if the provided account doesn't exist in the active directory. (inherited from _get_user_dn)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        remove_member = {'member': (MODIFY_DELETE, [self._get_user_dn(user_lookup_attribute_value)])}
        self._attempt_modification("member", user_lookup_attribute_value, remove_member)

    def add_child(self, group_lookup_attribute_value):
        """ Attempts to add a child to the AD group.

        :param group_lookup_attribute_value: The value for the LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE.
        :type group_lookup_attribute_value: str

        :raises: **GroupDoesNotExist** if the provided group doesn't exist in the active directory. (inherited from _get_group_dn)
        :raises: **EntryAlreadyExists** if the child already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        add_child = {'member': (MODIFY_ADD, [self._get_group_dn(group_lookup_attribute_value)])}
        self._attempt_modification("child", group_lookup_attribute_value, add_child)

    def remove_child(self, group_lookup_attribute_value):
        """ Attempts to remove a child from the AD group.

        :param group_lookup_attribute_value: The value for the LDAP_GROUPS_GROUP_LOOKUP_ATTRIBUTE.
        :type group_lookup_attribute_value: str

        :raises: **GroupDoesNotExist** if the provided group doesn't exist in the active directory. (inherited from _get_group_dn)
        :raises: **EntryAlreadyExists** if the child already exists in this group. (subclass of ModificationFailed)
        :raises: **InsufficientPermissions** if the bind user does not have permission to modify this group. (subclass of ModificationFailed)
        :raises: **ModificationFailed** if the modification could not be performed for an unforseen reason.

        """

        remove_child = {'member': (MODIFY_DELETE, [self._get_group_dn(group_lookup_attribute_value)])}
        self._attempt_modification("child", group_lookup_attribute_value, remove_child)

    ##############################################################################################################################################
    #                                                        Group Traversal Methods                                                             #
    ##############################################################################################################################################

    def get_descendants(self, page_size=500):
        """ Returns a list of all descendants of this group.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

        entry_list = self.ldap_connection.extend.standard.paged_search(search_base=self.DESCENDANT_SEARCH['base_dn'],
                                                                       search_filter=self.DESCENDANT_SEARCH['filter_string'],
                                                                       search_scope=self.DESCENDANT_SEARCH['scope'],
                                                                       attributes=self.DESCENDANT_SEARCH['attribute_list'],
                                                                       paged_size=page_size)

        return [ADGroup(group_dn=entry["dn"], server_uri=self.server_uri, base_dn=self.base_dn, user_lookup_attr=self.user_lookup_attr, group_lookup_attr=self.group_lookup_attr, attr_list=self.attr_list, bind_dn=self.bind_dn, bind_password=self.bind_password, user_search_base_dn=self.user_search_base_dn, group_search_base_dn=self.user_search_base_dn) for entry in entry_list if entry["type"] == "searchResEntry"]

    def get_children(self, page_size=500):
        """ Returns a list of this group's children.

        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

        children = []

        object_class = self.get_attribute("objectClass")
        group_type = object_class[-1] if object_class else None

        if group_type == "group":
            connection_dict = self.GROUP_CHILDREN_SEARCH
        elif group_type == "organizationalUnit":
            connection_dict = self.OU_CHILDREN_SEARCH
        else:
            logger.debug("Unable to process children of group {group_dn} with type {group_type}.".format(group_dn=self.group_dn, group_type=group_type))
            return []

        try:
            entry_list = self.ldap_connection.extend.standard.paged_search(search_base=connection_dict['base_dn'],
                                                                           search_filter=connection_dict['filter_string'],
                                                                           search_scope=connection_dict['scope'],
                                                                           attributes=connection_dict['attribute_list'],
                                                                           paged_size=page_size)
        except LDAPInvalidFilterError:
            print(connection_dict['filter_string'])
            logger.debug("Invalid Filter!: {filter}".format(filter=connection_dict['filter_string']))

            return []
        else:
            results = [result["dn"] for result in entry_list if result["type"] == "searchResEntry"]

            for result in results:
                children.append(ADGroup(group_dn=result, server_uri=self.server_uri, base_dn=self.base_dn, user_lookup_attr=self.user_lookup_attr, group_lookup_attr=self.group_lookup_attr, attr_list=self.attr_list, bind_dn=self.bind_dn, bind_password=self.bind_password, user_search_base_dn=self.user_search_base_dn, group_search_base_dn=self.user_search_base_dn))

            return children

    def child(self, group_name, page_size=500):
        """ Returns the child ad group that matches the provided group_name or none if the child does not exist.

        :param group_name: The name of the child group. NOTE: A name does not contain 'CN=' or 'OU='
        :type group_name: str
        :param page_size (optional): Many servers have a limit on the number of results that can be returned. Paged searches circumvent that limit. Adjust the page_size to be below the server's size limit. (default: 500)
        :type page_size: int

        """

        object_class = self.get_attribute("objectClass")
        group_type = object_class[-1] if object_class else None

        if group_type == "group":
            connection_dict = self.GROUP_SINGLE_CHILD_SEARCH
        elif group_type == "organizationalUnit":
            connection_dict = self.OU_SINGLE_CHILD_SEARCH
        else:
            logger.debug("Unable to process child {child} of group {group_dn} with type {group_type}.".format(child=group_name, group_dn=self.group_dn, group_type=group_type))
            return []

        entry_list = self.ldap_connection.extend.standard.paged_search(search_base=connection_dict['base_dn'],
                                                                       search_filter=connection_dict['filter_string'].format(child_group_name=escape_query(group_name)),
                                                                       search_scope=connection_dict['scope'],
                                                                       attributes=connection_dict['attribute_list'],
                                                                       paged_size=page_size)

        results = [result["dn"] for result in entry_list if result["type"] == "searchResEntry"]

        if len(results) != 1:
            logger.debug("Search returned {count} results: {results}".format(count=len(results), results=results))

        if results:
            return ADGroup(group_dn=results[0], server_uri=self.server_uri, base_dn=self.base_dn, user_lookup_attr=self.user_lookup_attr, group_lookup_attr=self.group_lookup_attr, attr_list=self.attr_list, bind_dn=self.bind_dn, bind_password=self.bind_password, user_search_base_dn=self.user_search_base_dn, group_search_base_dn=self.user_search_base_dn)
        else:
            return None

    def parent(self):
        """ Returns this group's parent (up to the DC)"""

        # Don't go above the DC
        if ''.join(self.group_dn.split("DC")[0].split()) == '':
            return self
        else:
            parent_dn = self.group_dn.split(",", 1).pop()
            return ADGroup(group_dn=parent_dn, server_uri=self.server_uri, base_dn=self.base_dn, user_lookup_attr=self.user_lookup_attr, group_lookup_attr=self.group_lookup_attr, attr_list=self.attr_list, bind_dn=self.bind_dn, bind_password=self.bind_password, user_search_base_dn=self.user_search_base_dn, group_search_base_dn=self.user_search_base_dn)

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
                if ''.join(ancestor_dn.split("DC")[0].split()) == '':
                    break
                else:
                    ancestor_dn = ancestor_dn.split(",", 1).pop()

            return ADGroup(group_dn=ancestor_dn, server_uri=self.server_uri, base_dn=self.base_dn, user_lookup_attr=self.user_lookup_attr, group_lookup_attr=self.group_lookup_attr, attr_list=self.attr_list, bind_dn=self.bind_dn, bind_password=self.bind_password, user_search_base_dn=self.user_search_base_dn, group_search_base_dn=self.user_search_base_dn)
