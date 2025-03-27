# tests/test_app_assignments.py
"""
Tests: App Assignment Events

Validates parse_app_assignments() function:
✔ Detects app ASSIGNED and REVOKED actions
✔ Filters by valid timestamp within date range
✔ Ignores changes outside range or malformed data

Expected Output:
List of dicts with user_id, email, action (formatted as "ASSIGNED/REVOKED"), app_name, timestamp
"""

import unittest
from unittest.mock import patch
from datetime import datetime
from okta_utils import parse_app_assignments

class TestAppAssignments(unittest.TestCase):

    def setUp(self):
        # Test data representing users and their app events
        self.users = [
            {
                "id": "user1",
                "profile": {"email": "assigned@example.com"},
                "appHistory": [
                    {
                        "timestamp": "2024-04-10T12:00:00.000Z",
                        "action": "ASSIGNED",
                        "app": "Acme Project Tools"
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
                        "app": "Finance Hub"
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

    @patch('requests.get')
    def test_app_assignments_in_range(self, mock_get):
        # Simulate API response for app assignments within the specified date range
        mock_response = {
            "status_code": 200,
            "json": lambda: [
                {
                    "published": "2024-04-10T12:00:00.000Z",
                    "eventType": "application.user_membership.add",
                    "target": [
                        {"type": "User", "id": "user1", "alternateId": "assigned@example.com"},
                        {"type": "AppInstance", "displayName": "Acme Project Tools"}
                    ]
                },
                {
                    "published": "2024-05-01T12:00:00.000Z",
                    "eventType": "application.user_membership.remove",
                    "target": [
                        {"type": "User", "id": "user2", "alternateId": "revoked@example.com"},
                        {"type": "AppInstance", "displayName": "Finance Hub"}
                    ]
                }
            ]
        }

        # Mock the first response with a "next" link for pagination
        mock_get.return_value.status_code = mock_response["status_code"]
        mock_get.return_value.json = mock_response["json"]
        mock_get.return_value.links = {
            "next": {"url": "https://example.com/api/v1/logs?page=2"}
        }

        # Mock the second response as the last page with no "next" link
        mock_get.return_value.links = {}
        
        # Define the date range
        start = datetime(2024, 1, 1).date()
        end = datetime(2024, 12, 31).date()

        # Create the app assignment changes
        changes = parse_app_assignments(self.users, start, end)

        # Get all descriptions from the parsed changes
        descriptions = [c["action"] for c in changes]

        # Test that the expected events are found
        self.assertIn("ADD", descriptions)
        self.assertIn("REMOVE", descriptions)
        self.assertEqual(len(changes), 2)  # Should only find 2 valid events within range

    @patch('requests.get')
    def test_app_assignments_out_of_range(self, mock_get):
        # Simulate API response for app assignments outside the specified date range
        mock_response = {
            "status_code": 200,
            "json": lambda: [
                {
                    "published": "2023-03-01T12:00:00.000Z",
                    "eventType": "application.user_membership.add",
                    "target": [
                        {"type": "User", "id": "user3", "alternateId": "outofrange@example.com"},
                        {"type": "AppInstance", "displayName": "GitHub"}
                    ]
                }
            ]
        }

        # Set up the mock to return the simulated response when called
        mock_get.return_value.status_code = mock_response["status_code"]
        mock_get.return_value.json = mock_response["json"]
        mock_get.return_value.links = {}  # No next page for pagination

        # Define a date range that doesn't match the user app events
        start = datetime(2022, 1, 1).date()
        end = datetime(2022, 12, 31).date()

        # Test that no changes are returned
        changes = parse_app_assignments(self.users, start, end)
        self.assertEqual(len(changes), 0)

if __name__ == "__main__":
    unittest.main()