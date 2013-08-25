"""

LDAP Groups v1 - A django Active Directory group management abstraction
    that uses python-ldap as a backend for cross-platform compatability.

Dependencies:
    Django>=1.5.2,
    python-ldap==2.4.13

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

from groups import ADGroup

#
# Version Classification
# Major Updates, Minor Updates, Revision/Bugfix Updates
#
VERSION = ("1", "0", "0")
__version__ = ".".join(VERSION)
