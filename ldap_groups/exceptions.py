"""
.. module:: ldap_groups.exceptions
    :synopsis: LDAP Groups Exceptions.

.. moduleauthor:: Alex Kavanaugh (@kavdev)

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
