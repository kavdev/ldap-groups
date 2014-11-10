"""
.. module:: ldap_groups.exceptions
    :synopsis: LDAP Groups Exceptions.

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

class EntryDoesNotExist(Exception):
    """The requested object does not exist."""
    pass


class AccountDoesNotExist(EntryDoesNotExist):
    """The requested user does not exist."""
    pass


class GroupDoesNotExist(EntryDoesNotExist):
    """The requested group does not exist."""
    pass


class InvalidGroupDN(Exception):
    """The Group DN provided is invalid."""
    pass


class ImproperlyConfigured(Exception):
    """LDAP Groups is somehow improperly configured."""
    pass


class InvalidCredentials(ImproperlyConfigured):
    """The bind dn and password provided are invalid."""
    pass


class LDAPServerUnreachable(Exception):
    """The LDAP server is unreachable."""
    pass


class ModificationFailed(Exception):
    """The AD Group could not be modified."""
    pass


class EntryAlreadyExists(ModificationFailed):
    """The account name provided already exists in a group being modified."""
    pass


class InsufficientPermissions(ModificationFailed):
    """The bind user does not have permission to modify a group."""
    pass
