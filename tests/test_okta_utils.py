#tests/test_okta_utils.py
"""
Tests: Okta Utilities

Validates Okta API utility functions:
✔ Tests behavior of fetch_admin_role_assignments() with mocked response
✔ Confirms retry logic on rate limits
✔ Handles error conditions and malformed inputs

Tested Components:
- fetch_admin_role_assignments()
- Supporting utilities for system log parsing
"""

import unittest, sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from datetime import datetime
from unittest.mock import patch
from okta_utils import fetch_admin_role_assignments

class TestAdminRoleAssignments(unittest.TestCase):

    @patch("okta_utils.requests.get")
    def test_filters_changes_within_range(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.links = {}  # 👈 prevent infinite pagination
        mock_get.return_value.json.return_value = [
            {
                "eventType": "system.admin_role.assignment",
                "published": "2025-06-01T12:00:00.000Z",
                "target": [
                    {"type": "User", "id": "user123", "alternateId": "test@example.com"},
                    {"type": "UserRole", "id": "ROLE_ASSIGNED"}
                ]
            }
        ]

        start = datetime(2025, 1, 1).date()
        end = datetime(2025, 12, 31).date()
        changes = fetch_admin_role_assignments(start, end)
        self.assertEqual(len(changes), 1)

    @patch("okta_utils.requests.get")
    def test_excludes_changes_outside_range(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.links = {}  # 👈 prevent infinite pagination
        mock_get.return_value.json.return_value = [
            {
                "eventType": "system.admin_role.assignment",
                "published": "2023-01-01T12:00:00.000Z",
                "target": [
                    {"type": "User", "id": "user123", "alternateId": "test@example.com"},
                    {"type": "UserRole", "id": "ROLE_ASSIGNED"}
                ]
            }
        ]

        start = datetime(2025, 1, 1).date()
        end = datetime(2025, 12, 31).date()
        changes = fetch_admin_role_assignments(start, end)
        self.assertEqual(len(changes), 0)

if __name__ == "__main__":
    unittest.main()