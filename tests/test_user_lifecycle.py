# tests/test_user_lifecycle.py
"""
Tests: User Lifecycle Events

Validates parse_user_lifecycle_changes() function:
✔ Detects user creation events within a date range
✔ Detects user suspension/deprovisioning based on statusChanged timestamp
✔ Ignores users with malformed/missing date fields

Expected Output:
List of dicts with user_id, email, previous_role_id, new_role_id, timestamp
"""

import unittest, sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from datetime import datetime
from okta_utils import parse_user_lifecycle_changes

class TestUserLifecycleParsing(unittest.TestCase):

    def setUp(self):
        self.users = [
            {
                "id": "user1",
                "status": "ACTIVE",
                "created": "2024-05-01T12:00:00.000Z",
                "profile": {"email": "created@example.com"},
            },
            {
                "id": "user2",
                "status": "SUSPENDED",
                "created": "2023-01-01T12:00:00.000Z",
                "statusChanged": "2024-06-01T12:00:00.000Z",
                "profile": {"email": "suspended@example.com"},
            },
            {
                "id": "user3",
                "status": "DEPROVISIONED",
                "created": "2020-01-01T12:00:00.000Z",
                "statusChanged": "2024-07-01T12:00:00.000Z",
                "profile": {"email": "deprovisioned@example.com"},
            },
        ]

    def test_lifecycle_changes_in_range(self):
        start = datetime(2024, 1, 1).date()
        end = datetime(2024, 12, 31).date()
        events = parse_user_lifecycle_changes(self.users, start, end)

        emails = [e["email"] for e in events]

        self.assertIn("created@example.com", emails)
        self.assertIn("suspended@example.com", emails)
        self.assertIn("deprovisioned@example.com", emails)
        self.assertEqual(len(events), 3)

    def test_lifecycle_changes_out_of_range(self):
        start = datetime(2022, 1, 1).date()
        end = datetime(2022, 12, 31).date()
        events = parse_user_lifecycle_changes(self.users, start, end)
        self.assertEqual(len(events), 0)

    def test_malformed_or_missing_dates(self):
        malformed_users = [
            {
                "id": "bad1",
                "status": "ACTIVE",
                "created": "not-a-date",
                "profile": {"email": "bad_created@example.com"},
            },
            {
                "id": "bad2",
                "status": "SUSPENDED",
                "statusChanged": "not-a-date",
                "profile": {"email": "bad_suspended@example.com"},
            },
            {
                "id": "bad3",
                "status": "DEPROVISIONED",
                # missing statusChanged entirely
                "profile": {"email": "missing_status_changed@example.com"},
            },
        ]

        start = datetime(2024, 1, 1).date()
        end = datetime(2024, 12, 31).date()
        events = parse_user_lifecycle_changes(malformed_users, start, end)
        self.assertEqual(len(events), 0)

if __name__ == "__main__":
    unittest.main()