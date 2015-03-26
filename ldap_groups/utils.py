"""
.. module:: ldap_groups.utils
   :synopsis: LDAP Groups Utilities.

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


def escape_query(query):
    """Escapes certain filter characters from an LDAP query."""

    return query.replace("\\", "\5C").replace("*", "\2A").replace("(", "\28").replace(")", "\29")
