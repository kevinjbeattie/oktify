# okta_utils.py
"""
Oktify Utilities – okta_utils.py

This file contains core functions for interacting with the Okta API and
extracting user, role, group, and app changes within a given time period.

Expected output: Lists of parsed event dicts for export to CSV or terminal.
"""

import os
import csv
import time
import requests
from datetime import datetime, date
from dotenv import load_dotenv
from typing import List, Dict, Any

load_dotenv()

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
API_TOKEN = os.getenv("OKTA_API_TOKEN")

# --------------------------------------
# Fetch all users from the Okta API with pagination
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
                url = response.links.get("next", {}).get("url")
            else:
                print(f"❌ Failed to fetch users: {response.text}")
                break
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error while fetching users: {e}")

    return users

# --------------------------------------
# Parse role history from user objects
# --------------------------------------
def parse_role_changes(users: List[Dict[str, Any]], start_date: date, end_date: date) -> List[Dict[str, str]]:
    role_changes: List[Dict[str, str]] = []

    for user in users:
        email = user.get("profile", {}).get("email", "unknown")
        user_id = user.get("id", "unknown")
        role_history = user.get("roleHistory", [])

        for change in role_history:
            try:
                timestamp = change.get("timestamp")
                if not timestamp:
                    continue
                change_date = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").date()
                if not (start_date <= change_date <= end_date):
                    continue

                prev_role = change.get("previousRoleId")
                new_role = change.get("newRoleId")
                if not prev_role or not new_role:
                    continue

                role_changes.append({
                    "user_id": user_id,
                    "email": email,
                    "previous_role_id": prev_role,
                    "new_role_id": new_role,
                    "timestamp": timestamp
                })
            except (KeyError, ValueError) as e:
                print(f"⚠️ Skipping malformed role history entry for user {user_id}: {e}")

    return role_changes

# --------------------------------------
# Detect user creation/suspension events
# --------------------------------------
def parse_user_lifecycle_changes(users: List[Dict[str, Any]], start_date: date, end_date: date) -> List[Dict[str, str]]:
    lifecycle_events: List[Dict[str, str]] = []
    for user in users:
        email = user.get("profile", {}).get("email", "unknown")
        user_id = user.get("id", "unknown")
        status = user.get("status")

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
        except ValueError as e:
            print(f"⚠️ Invalid created date for user {user_id}: {e}")

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
            except ValueError as e:
                print(f"⚠️ Invalid statusChanged date for user {user_id}: {e}")

    return lifecycle_events

# --------------------------------------
# Parse group join/leave history
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

    return group_changes

# --------------------------------------
# Fetch app assignments from Okta System Log
# --------------------------------------
def fetch_app_events_from_log(start_date: date, end_date: date) -> List[Dict[str, Any]]:
    events = []
    url = f"{OKTA_DOMAIN}/api/v1/logs"
    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json"
    }
    params = {
        "since": f"{start_date.isoformat()}T00:00:00Z",
        "until": f"{end_date.isoformat()}T23:59:59Z",
        "filter": 'eventType eq "application.user_membership.add" or eventType eq "application.user_membership.remove"',
        "limit": 1000
    }

    retry_count = 0
    max_retries = 5

    while url and retry_count < max_retries:
        try:
            response = requests.get(url, headers=headers, params=params if '?' not in url else None)
            if response.status_code == 200:
                events.extend(response.json())
                url = response.links.get("next", {}).get("url")
                retry_count = 0  # Reset retry count on success
            elif response.status_code == 429:
                retry_count += 1
                wait_time = 2 ** retry_count
                print(f"⏳ Rate limit hit. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                print(f"❌ Error fetching app events: {response.status_code} - {response.text}")
                break
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            break

    return events

# --------------------------------------
# Parse app assignment/revocation events
# --------------------------------------
def parse_app_assignments(users: List[Dict[str, Any]], start_date: date, end_date: date) -> List[Dict[str, str]]:
    app_events: List[Dict[str, str]] = []
    log_events = fetch_app_events_from_log(start_date, end_date)

    for event in log_events:
        try:
            user_id = event.get("actor", {}).get("id", "unknown")
            email = event.get("actor", {}).get("alternateId", "unknown")
            app = event.get("target", [{}])[0].get("displayName", "unknown")
            timestamp = event.get("published")
            action = event.get("eventType")

            if not timestamp or not action or not app:
                continue

            action_str = "ASSIGNED" if action.endswith("add") else "REVOKED"

            app_events.append({
                "user_id": user_id,
                "email": email,
                "previous_role_id": "N/A",
                "new_role_id": f"App {action_str}: {app}",
                "timestamp": timestamp
            })
        except Exception as e:
            print(f"⚠️ Skipping malformed app log event: {e}")

    return app_events

# --------------------------------------
# Export change list to CSV
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