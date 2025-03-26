# tests/test_okta_utils.py

import unittest
from datetime import datetime
from okta_utils import parse_role_changes

class TestParseRoleChanges(unittest.TestCase):

    def setUp(self):
        # Sample user data with fake role history
        self.users = [
            {
                "id": "user123",
                "profile": {"email": "test@example.com"},
                "roleHistory": [
                    {
                        "timestamp": "2024-06-01T12:00:00.000Z",
                        "previousRoleId": "viewer",
                        "newRoleId": "admin"
                    },
                    {
                        "timestamp": "2023-06-01T12:00:00.000Z",
                        "previousRoleId": "admin",
                        "newRoleId": "editor"
                    }
                ]
            }
        ]

    def test_filters_changes_within_range(self):
        start = datetime(2024, 1, 1).date()
        end = datetime(2024, 12, 31).date()
        changes = parse_role_changes(self.users, start, end)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['new_role_id'], "admin")

    def test_excludes_changes_outside_range(self):
        start = datetime(2025, 1, 1).date()
        end = datetime(2025, 12, 31).date()
        changes = parse_role_changes(self.users, start, end)
        self.assertEqual(len(changes), 0)

if __name__ == '__main__':
    unittest.main()
