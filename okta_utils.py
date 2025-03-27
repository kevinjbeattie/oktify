# okta_utils.py
"""
Oktify Utilities – okta_utils.py

This file contains core functions for interacting with the Okta API and
extracting user, role, group, and app changes within a given time period.

Includes:
- Role assignment events via System Logs
- User lifecycle tracking
- Group membership changes
- App assignments/revocations
"""

import os
import time
import csv
import requests
from datetime import datetime, date
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load credentials from .env file
load_dotenv()
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
API_TOKEN = os.getenv("OKTA_API_TOKEN")

# --------------------------------------
# Fetch users from Okta (basic profile)
# --------------------------------------
def get_all_users() -> List[Dict[str, Any]]:
    if not OKTA_DOMAIN or not API_TOKEN:
        print("❌ Missing OKTA_DOMAIN or OKTA_API_TOKEN. Check your .env file.")
        return []

    if not OKTA_DOMAIN.startswith("http"):
        print("❌ Invalid OKTA_DOMAIN format. Must include 'https://'.")
        return []

    url = f"{OKTA_DOMAIN}/api/v1/users"
    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json"
    }

    users = []
    try:
        while url:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                users.extend(response.json())
                url = response.links.get('next', {}).get('url')
            else:
                print(f"❌ Failed to fetch users: {response.text}")
                break
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error while fetching users: {e}")
    return users

# --------------------------------------
# Track admin role assignments via system logs
# --------------------------------------
def fetch_admin_role_assignments(start_date: date, end_date: date) -> List[Dict[str, str]]:
    """
    Query Okta's System Log API for administrator role assignments and unassignments.
    """
    if not OKTA_DOMAIN or not API_TOKEN:
        print("❌ Missing OKTA_DOMAIN or OKTA_API_TOKEN. Check your .env file.")
        return []

    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json"
    }

    # Convert dates to ISO 8601 format with time
    since = f"{start_date.isoformat()}T00:00:00Z"
    until = f"{end_date.isoformat()}T23:59:59Z"

    url = f"{OKTA_DOMAIN}/api/v1/logs"
    params = {
        "since": since,
        "until": until,
        "filter": '(target.id eq "ROLE_ASSIGNED") or (target.id eq "ROLE_UNASSIGNED")',
        "limit": 1000
    }

    role_events = []
    retries = 0
    max_retries = 5

    while url:
        try:
            response = requests.get(url, headers=headers, params=params if '?' not in url else None)
            if response.status_code == 429:
                if retries < max_retries:
                    delay = 2 ** retries
                    print(f"⚠️ Rate limit hit. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    retries += 1
                    continue
                else:
                    print("❌ Max retries exceeded while hitting rate limit.")
                    break
            elif response.status_code != 200:
                print(f"❌ Error fetching role events: {response.status_code} - {response.text}")
                break

            logs = response.json()
            for event in logs:
                timestamp = event.get("published", "")
                try:
                    event_date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").date()
                    if not (start_date <= event_date <= end_date):
                        continue
                except Exception:
                    continue

                actor = event.get("actor", {})
                target = event.get("target", [])
                outcome = event.get("outcome", {}).get("result", "")

                for t in target:
                    if t.get("type") == "User":
                        role_event = {
                            "user_id": t.get("id", "unknown"),
                            "email": t.get("alternateId", "unknown"),
                            "previous_role_id": "N/A",
                            "new_role_id": "Admin Role Assigned" if event["eventType"] == "system.admin_role.assignment" else "Admin Role Unassigned",
                            "timestamp": timestamp
                        }
                        role_events.append(role_event)

            url = response.links.get("next", {}).get("url")
            params = None  # Only needed for first request

        except requests.exceptions.RequestException as e:
            print(f"❌ Network error while fetching logs: {e}")
            break

    return role_events

# --------------------------------------
# Detect user creation and suspension/deactivation
# --------------------------------------
# Detects user creation and suspension/deactivation events.
def parse_user_lifecycle_changes(users, start_date, end_date):
    lifecycle_events = []
    for user in users:
        email = user.get("profile", {}).get("email", "unknown")
        user_id = user.get("id", "unknown")
        status = user.get("status")

        # Handle user creation
        created_str = user.get("created")
        try:
            if created_str:
                created_date = datetime.strptime(created_str, "%Y-%m-%dT%H:%M:%S.%fZ").date()
                if start_date <= created_date <= end_date:
                    lifecycle_events.append({
                        "user_id": user_id,
                        "email": email,
                        "previous_role_id": "N/A",
                        "new_role_id": "Created",
                        "timestamp": created_str
                    })
        except ValueError:
            pass

        # Handle suspension/deactivation
        if status in ["SUSPENDED", "DEPROVISIONED"]:
            status_changed_str = user.get("statusChanged")
            try:
                if status_changed_str:
                    changed_date = datetime.strptime(status_changed_str, "%Y-%m-%dT%H:%M:%S.%fZ").date()
                    if start_date <= changed_date <= end_date:
                        lifecycle_events.append({
                            "user_id": user_id,
                            "email": email,
                            "previous_role_id": "Active",
                            "new_role_id": status,
                            "timestamp": status_changed_str
                        })
            except ValueError:
                pass

    return lifecycle_events

# --------------------------------------
# Parse group membership events from user data
# --------------------------------------
def parse_group_membership_changes(users: List[Dict[str, Any]], start_date: date, end_date: date) -> List[Dict[str, str]]:
    group_changes: List[Dict[str, str]] = []

    for user in users:
        email = user.get("profile", {}).get("email", "unknown")
        user_id = user.get("id", "unknown")
        group_history = user.get("groupHistory", [])

        for change in group_history:
            try:
                timestamp = change.get("timestamp")
                if not timestamp:
                    continue

                change_date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").date()
                if not (start_date <= change_date <= end_date):
                    continue

                action = change.get("action")
                group = change.get("group")
                if not action or not group:
                    continue

                group_changes.append({
                    "user_id": user_id,
                    "email": email,
                    "previous_role_id": "N/A",
                    "new_role_id": f"Group {action}: {group}",
                    "timestamp": timestamp
                })

            except (KeyError, ValueError) as e:
                print(f"⚠️ Skipping malformed group history entry for user {user_id}: {e}")
                continue

    return group_changes

# --------------------------------------
# Parse app assignment/revocation events from user data
# --------------------------------------
def parse_app_assignments(users: List[Dict[str, Any]], start_date: date, end_date: date) -> List[Dict[str, str]]:
    app_events: List[Dict[str, str]] = []

    for user in users:
        email = user.get("profile", {}).get("email", "unknown")
        user_id = user.get("id", "unknown")
        app_history = user.get("appHistory", [])

        for change in app_history:
            try:
                timestamp = change.get("timestamp")
                if not timestamp:
                    continue

                change_date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").date()
                if not (start_date <= change_date <= end_date):
                    continue

                action = change.get("action")
                app = change.get("app")
                if not action or not app:
                    continue

                app_events.append({
                    "user_id": user_id,
                    "email": email,
                    "previous_role_id": "N/A",
                    "new_role_id": f"App {action}: {app}",
                    "timestamp": timestamp
                })

            except (KeyError, ValueError) as e:
                print(f"⚠️ Skipping malformed app history entry for user {user_id}: {e}")
                continue

    return app_events

# --------------------------------------
# Export any role/lifecycle/app/group changes to CSV
# --------------------------------------
def export_role_changes_to_csv(role_changes: List[Dict[str, str]], filename: str = "role_changes.csv") -> None:
    fieldnames = ["user_id", "email", "previous_role_id", "new_role_id", "timestamp"]

    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for change in role_changes:
                writer.writerow(change)
        print(f"✅ CSV written to {filename}")
    except Exception as e:
        print(f"❌ Failed to write CSV: {e}")