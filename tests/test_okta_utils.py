import unittest
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