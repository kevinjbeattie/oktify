# tests/test_app_assignments.py
"""
Tests: App Assignment Events

Validates parse_app_assignments() function:
✔ Detects app ASSIGNED and REVOKED actions
✔ Filters by valid timestamp within date range
✔ Ignores changes outside range or malformed data

Expected Output:
List of dicts with user_id, email, previous_role_id, new_role_id (formatted as "App ASSIGNED/REVOKED: app"), timestamp
"""

import unittest
from datetime import datetime
from okta_utils import parse_app_assignments

class TestAppAssignments(unittest.TestCase):

    def setUp(self):
        self.users = [
            {
                "id": "user1",
                "profile": {"email": "assigned@example.com"},
                "appHistory": [
                    {
                        "timestamp": "2024-04-10T12:00:00.000Z",
                        "action": "ASSIGNED",
                        "app": "Slack"
                    }
                ]
            },
            {
                "id": "user2",
                "profile": {"email": "revoked@example.com"},
                "appHistory": [
                    {
                        "timestamp": "2024-05-01T12:00:00.000Z",
                        "action": "REVOKED",
                        "app": "Zoom"
                    }
                ]
            },
            {
                "id": "user3",
                "profile": {"email": "outofrange@example.com"},
                "appHistory": [
                    {
                        "timestamp": "2023-03-01T12:00:00.000Z",
                        "action": "ASSIGNED",
                        "app": "GitHub"
                    }
                ]
            }
        ]

    def test_app_assignments_in_range(self):
        start = datetime(2024, 1, 1).date()
        end = datetime(2024, 12, 31).date()
        changes = parse_app_assignments(self.users, start, end)
        descriptions = [c["new_role_id"] for c in changes]

        self.assertIn("App ASSIGNED: Slack", descriptions)
        self.assertIn("App REVOKED: Zoom", descriptions)
        self.assertEqual(len(changes), 2)

    def test_app_assignments_out_of_range(self):
        start = datetime(2022, 1, 1).date()
        end = datetime(2022, 12, 31).date()
        changes = parse_app_assignments(self.users, start, end)
        self.assertEqual(len(changes), 0)

if __name__ == "__main__":
    unittest.main()