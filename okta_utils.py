# okta_utils.py
"""
Oktify Utilities – okta_utils.py

This file contains core functions for interacting with the Okta API and
extracting user, role, group, and app changes within a given time period.

Expected output: Lists of parsed event dicts for export to CSV or terminal.
"""

import os
import csv
import requests
from datetime import datetime, date
from dotenv import load_dotenv
from typing import List, Dict, Any

load_dotenv()

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
API_TOKEN = os.getenv("OKTA_API_TOKEN")

# --------------------------------------
# Fetch all users from the Okta API
# --------------------------------------
def get_all_users():
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
            if response.status_code != 200:
                print(f"❌ Failed to fetch users: {response.text}")
                break
            users.extend(response.json())
            url = response.links.get('next', {}).get('url')
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error while fetching users: {e}")

    return users

# Parses role history for a list of users and extracts role changes.
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

# Detects user creation and suspension/deactivation events.
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

# Parses group membership change history.
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

# Pulls app assignment or revocation events from Okta system logs.
def parse_app_assignments(users: List[Dict[str, Any]], start_date: date, end_date: date) -> List[Dict[str, str]]:
    events: List[Dict[str, str]] = []

    if not OKTA_DOMAIN or not API_TOKEN:
        print("❌ Missing OKTA_DOMAIN or OKTA_API_TOKEN.")
        return []

    url = f"{OKTA_DOMAIN}/api/v1/logs"
    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json"
    }

    start_ts = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
    end_ts = end_date.strftime("%Y-%m-%dT23:59:59.999Z")
    filter_str = (
        f'eventType eq "application.user_assignment" or '
        f'eventType eq "application.user_unassignment" and '
        f'published ge "{start_ts}" and published le "{end_ts}"'
    )

    params = {
        "filter": filter_str,
        "limit": 1000
    }

    try:
        while url:
            resp = requests.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                print(f"❌ Error fetching app events: {resp.status_code} - {resp.text}")
                break

            for entry in resp.json():
                user_id = "unknown"
                email = "unknown"
                app_name = None
                for target in entry.get("target", []):
                    if target.get("type") == "User":
                        user_id = target.get("id")
                        email = target.get("alternateId")
                    elif target.get("type") == "AppInstance":
                        app_name = target.get("displayName")

                if app_name:
                    action = "ASSIGNED" if entry["eventType"] == "application.user_assignment" else "REVOKED"
                    events.append({
                        "user_id": user_id,
                        "email": email,
                        "previous_role_id": "N/A",
                        "new_role_id": f"App {action}: {app_name}",
                        "timestamp": entry.get("published")
                    })

            url = resp.links.get("next", {}).get("url")

    except Exception as e:
        print(f"❌ Error parsing app assignment events: {e}")

    return events

# Exports role change entries to a CSV file.
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
