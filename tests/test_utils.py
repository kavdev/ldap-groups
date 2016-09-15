"""
.. module:: tests.test_utils
   :synopsis: LDAP Groups Utilities Tests.

.. moduleauthor:: Alex Kavanaugh (@kavdev)

"""

from unittest.case import TestCase

from ldap_groups.utils import escape_query


class EscapeQueryTest(TestCase):

    def test_real_world_example(self):
        input_string = "CN=StateHRDept - IS-ITS-Engineering Services (133200 FacStf All)"
        expected_output = r"CN=StateHRDept - IS-ITS-Engineering Services \28133200 FacStf All\29"

        self.assertEqual(expected_output, escape_query(input_string), "Parentheses were not correctly escaped.")

    def test_string_with_left_parenthesis(self):
        input_string = "("
        expected_output = r"\28"

        self.assertEqual(expected_output, escape_query(input_string), "Left parenthesis was not correctly escaped.")

    def test_string_with_right_parenthesis(self):
        input_string = ")"
        expected_output = r"\29"

        self.assertEqual(expected_output, escape_query(input_string), "Right parenthesis was not correctly escaped.")

    def test_string_with_backslash(self):
        input_string = "\\"
        expected_output = r"\5C"

        self.assertEqual(expected_output, escape_query(input_string), "Literal backslash was not correctly escaped.")

    def test_string_with_asterisk(self):
        input_string = "*"
        expected_output = r"\2A"

        self.assertEqual(expected_output, escape_query(input_string), "Asterisk was not correctly escaped.")

    def test_string_with_all_escaped_characters(self):
        input_string = "\\*()"
        expected_output = r"\5C\2A\28\29"

        self.assertEqual(expected_output, escape_query(input_string), "All symbols were not correctly escaped.")

    def test_string_with_no_escaped_characters(self):
        input_string = "Hello World! I have no problem characters in me!"

        self.assertEqual(input_string, escape_query(input_string), "Regular characters were unexpectedly escaped.")
