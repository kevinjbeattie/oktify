# tests/test_group_changes.py
"""
Tests: Group Membership Changes

Validates parse_group_membership_changes() function:
✔ Detects group ADD and REMOVE actions
✔ Filters changes by timestamp within provided date range
✔ Ignores changes outside of range

Expected Output:
List of dicts with user_id, email, previous_role_id, new_role_id (formatted as "Group ADD/REMOVE: group"), timestamp
"""

import unittest
from datetime import datetime
from okta_utils import parse_group_membership_changes

class TestGroupMembershipParsing(unittest.TestCase):

    def setUp(self):
        self.users = [
            {
                "id": "user1",
                "profile": {"email": "add@example.com"},
                "groupHistory": [
                    {
                        "timestamp": "2024-05-10T12:00:00.000Z",
                        "action": "ADD",
                        "group": "marketing"
                    }
                ]
            },
            {
                "id": "user2",
                "profile": {"email": "remove@example.com"},
                "groupHistory": [
                    {
                        "timestamp": "2024-06-01T12:00:00.000Z",
                        "action": "REMOVE",
                        "group": "finance"
                    }
                ]
            },
            {
                "id": "user3",
                "profile": {"email": "outofrange@example.com"},
                "groupHistory": [
                    {
                        "timestamp": "2023-01-01T12:00:00.000Z",
                        "action": "ADD",
                        "group": "sales"
                    }
                ]
            }
        ]

    def test_group_changes_in_range(self):
        start = datetime(2024, 1, 1).date()
        end = datetime(2024, 12, 31).date()
        changes = parse_group_membership_changes(self.users, start, end)

        descriptions = [c["new_role_id"] for c in changes]
        self.assertIn("Group ADD: marketing", descriptions)
        self.assertIn("Group REMOVE: finance", descriptions)
        self.assertEqual(len(changes), 2)

    def test_group_changes_out_of_range(self):
        start = datetime(2022, 1, 1).date()
        end = datetime(2022, 12, 31).date()
        changes = parse_group_membership_changes(self.users, start, end)
        self.assertEqual(len(changes), 0)

if __name__ == '__main__':
    unittest.main()
