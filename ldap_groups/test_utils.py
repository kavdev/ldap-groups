"""
.. module:: ldap_groups.test_utils
   :synopsis: LDAP Groups Utilities Tests.

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

from unittest.case import TestCase

from .utils import escape_query


class EscapeQueryTest(TestCase):

    def test_real_world_example(self):
        input_string = "CN=StateHRDept - IS-ITS-Engineering Services (133200 FacStf All)"
        expected_output = "CN=StateHRDept - IS-ITS-Engineering Services \28133200 FacStf All\29"

        self.assertEqual(expected_output, escape_query(input_string), "Parentheses were not correctly escaped.")

    def test_string_with_left_parenthesis(self):
        input_string = "("
        expected_output = "\28"

        self.assertEqual(expected_output, escape_query(input_string), "Left parenthesis was not correctly escaped.")

    def test_string_with_right_parenthesis(self):
        input_string = ")"
        expected_output = "\29"

        self.assertEqual(expected_output, escape_query(input_string), "Right parenthesis was not correctly escaped.")

    def test_string_with_backslash(self):
        input_string = "\\"
        expected_output = "\5C"

        self.assertEqual(expected_output, escape_query(input_string), "Literal backslash was not correctly escaped.")

    def test_string_with_asterisk(self):
        input_string = "*"
        expected_output = "\2A"

        self.assertEqual(expected_output, escape_query(input_string), "Asterisk was not correctly escaped.")

    def test_string_with_all_escaped_characters(self):
        input_string = "\\*()"
        expected_output = "\5C\2A\28\29"

        self.assertEqual(expected_output, escape_query(input_string), "All symbols were not correctly escaped.")

    def test_string_with_no_escaped_characters(self):
        input_string = "Hello World! I have no problem characters in me!"

        self.assertEqual(input_string, escape_query(input_string), "Regular characters were unexpectedly escaped.")
