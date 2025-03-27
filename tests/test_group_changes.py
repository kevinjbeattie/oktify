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
from unittest.mock import patch
from datetime import datetime, date
from okta_utils import parse_group_membership_changes

class TestGroupMembershipParsing(unittest.TestCase):

    def setUp(self):
        self.mock_log_response = [
            {
                "published": "2024-05-10T12:00:00.000Z",
                "eventType": "group.user_membership.add",
                "target": [
                    {
                        "id": "user1",
                        "type": "User",
                        "alternateId": "add@example.com"
                    },
                    {
                        "id": "group1",
                        "type": "UserGroup",
                        "displayName": "marketing"
                    }
                ]
            },
            {
                "published": "2024-06-01T12:00:00.000Z",
                "eventType": "group.user_membership.remove",
                "target": [
                    {
                        "id": "user2",
                        "type": "User",
                        "alternateId": "remove@example.com"
                    },
                    {
                        "id": "group2",
                        "type": "UserGroup",
                        "displayName": "finance"
                    }
                ]
            },
            {
                "published": "2023-01-01T12:00:00.000Z",
                "eventType": "group.user_membership.add",
                "target": [
                    {
                        "id": "user3",
                        "type": "User",
                        "alternateId": "outofrange@example.com"
                    },
                    {
                        "id": "group3",
                        "type": "UserGroup",
                        "displayName": "sales"
                    }
                ]
            }
        ]

    @patch("okta_utils.requests.get")
    def test_group_changes_in_range(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = self.mock_log_response
        mock_get.return_value.links = {}

        start = date(2024, 1, 1)
        end = date(2024, 12, 31)
        changes = parse_group_membership_changes(start, end)

        group_names = [c["group_name"] for c in changes]
        self.assertIn("marketing", group_names)
        self.assertIn("finance", group_names)
        self.assertEqual(len(changes), 2)

    @patch("okta_utils.requests.get")
    def test_group_changes_out_of_range(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = self.mock_log_response
        mock_get.return_value.links = {}

        start = date(2022, 1, 1)
        end = date(2022, 12, 31)
        changes = parse_group_membership_changes(start, end)
        self.assertEqual(len(changes), 0)

if __name__ == "__main__":
    unittest.main()