#tests/test_cli.py
"""
Tests: Oktify CLI (run.py)

Validates CLI subcommand behavior:
✔ Verifies 'roles' subcommand executes with mocked inputs
✔ Confirms CSV export function is called
✔ Asserts expected print output in terminal

Tested Components:
- run.main()
- handle_roles()
- export_admin_role_changes_to_csv()
"""

import unittest, sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unittest import mock
from io import StringIO
import sys
import run  # Imports your main CLI logic

class TestOktifyCLI(unittest.TestCase):

    @mock.patch("builtins.print")
    @mock.patch("run.get_all_users")
    @mock.patch("run.fetch_admin_role_assignments")
    @mock.patch("run.export_admin_role_changes_to_csv")
    def test_roles_command_prints_expected_output(self, mock_export, mock_fetch_roles, mock_get_users, mock_print):
        # Simulate return value from get_all_users (even if it's unused in fetch_admin_role_assignments now)
        mock_get_users.return_value = []

        # Provide 2 mock role assignment results
        mock_fetch_roles.return_value = [
            {
                "user_id": "user1",
                "email": "placeholder@okta.com",
                "previous_role_id": "N/A",
                "new_role_id": "Admin Role Unassigned",
                "timestamp": "2025-03-26T15:51:11.653Z"
            },
            {
                "user_id": "user2",
                "email": "elena.kim@kjblabs.dev",
                "previous_role_id": "N/A",
                "new_role_id": "Admin Role Unassigned",
                "timestamp": "2025-03-27T17:38:07.201Z"
            }
        ]

        # Simulate CLI args
        test_args = ["run.py", "roles", "--start", "2025-01-01", "--end", "2025-12-31", "--show"]
        with mock.patch.object(sys, 'argv', test_args):
            run.main()

        # Assertions
        mock_print.assert_any_call("✅ Found 2 admin role change(s). Exporting to CSV...")
        mock_export.assert_called_once()
        mock_fetch_roles.assert_called_once()

if __name__ == '__main__':
    unittest.main()