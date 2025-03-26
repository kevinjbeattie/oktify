# tests/test_cli.py

import unittest
from unittest import mock
from io import StringIO
import sys

import run  # Imports your main CLI logic

class TestOktifyCLI(unittest.TestCase):

    @mock.patch("builtins.print")
    @mock.patch("run.get_all_users")
    @mock.patch("run.parse_role_changes")
    @mock.patch("run.export_role_changes_to_csv")
    def test_roles_command_prints_expected_output(self, mock_export, mock_parse, mock_get_users, mock_print):
        # Mock return values
        mock_get_users.return_value = [
            {"id": "user123", "profile": {"email": "test@example.com"}, "roleHistory": []}
        ]
        mock_parse.return_value = [
            {
                "user_id": "user123",
                "email": "test@example.com",
                "previous_role_id": "viewer",
                "new_role_id": "admin",
                "timestamp": "2024-01-01T00:00:00.000Z"
            }
        ]

        # Simulate CLI arguments
        test_args = ["run.py", "roles", "--start", "2024-01-01", "--end", "2024-12-31", "--show"]
        with mock.patch.object(sys, 'argv', test_args):
            run.main()

        # Validate output call
        mock_print.assert_any_call("✅ Found 1 role change(s). Exporting to CSV...")
        mock_export.assert_called_once()
        self.assertEqual(mock_parse.call_count, 1)

if __name__ == '__main__':
    unittest.main()
