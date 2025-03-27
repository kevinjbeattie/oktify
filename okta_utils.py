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

                user_id = "unknown"
                email = "unknown"
                role_name = "unknown"
                action = "Assigned" if event["eventType"] == "system.admin_role.assignment" else "Unassigned"

                role_name = "unknown"
                for t in event.get("target", []):
                    if t.get("type") == "User":
                        user_id = t.get("id", "unknown")
                        email = t.get("alternateId", "unknown")
                    elif t.get("type") == "ROLE":
                        role_name = t.get("displayName") or t.get("alternateId") or t.get("id") or "unknown"

                role_events.append({
                    "user_id": user_id,
                    "email": email,
                    "action": action,
                    "role_name": role_name,
                    "timestamp": timestamp
                })

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
                        "event_type": "Created",
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
def parse_group_membership_changes(start_date: date, end_date: date) -> List[Dict[str, str]]:
    """
    Queries Okta System Logs for user group membership events (add/remove) within the given time range.
    Returns list of group membership changes: add/remove per user.
    """
    if not OKTA_DOMAIN or not API_TOKEN:
        print("❌ Missing OKTA_DOMAIN or OKTA_API_TOKEN. Check your .env file.")
        return []

    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json"
    }

    since = f"{start_date.isoformat()}T00:00:00Z"
    until = f"{end_date.isoformat()}T23:59:59Z"

    url = f"{OKTA_DOMAIN}/api/v1/logs"
    params = {
        "since": since,
        "until": until,
        "filter": '(eventType eq "group.user_membership.add" or eventType eq "group.user_membership.remove")',
        "limit": 1000
    }

    group_events = []
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
                print(f"❌ Error fetching group events: {response.status_code} - {response.text}")
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

                targets = event.get("target", [])

                user_id = "unknown"
                email = "unknown"
                group = "unknown"

                for t in targets:
                    if t.get("type") == "User":
                        user_id = t.get("id", "unknown")
                        email = t.get("alternateId", "unknown")
                    if t.get("type") == "UserGroup":
                        group = (
                            t.get("displayName") or
                            t.get("alternateId") or
                            t.get("id") or
                            "unknown"
                        )

                action = event["eventType"].split(".")[-1].capitalize()
                group_events.append({
                    "user_id": user_id,
                    "email": email,
                    "group_name": group,
                    "action": action,
                    "timestamp": timestamp
                })

            url = response.links.get("next", {}).get("url")
            params = None  # Only needed on the first call

        except requests.exceptions.RequestException as e:
            print(f"❌ Network error while fetching logs: {e}")
            break

    return group_events

# --------------------------------------
# Parse app assignment/revocation events from user data
# --------------------------------------
def parse_app_assignments(users, start_date, end_date):
    """
    Queries Okta System Logs for app assignment and removal events.
    Returns list of app assignment/revocation events.
    """
    if not OKTA_DOMAIN or not API_TOKEN:
        print("❌ Missing OKTA_DOMAIN or OKTA_API_TOKEN. Check your .env file.")
        return []

    headers = {
        "Authorization": f"SSWS {API_TOKEN}",
        "Accept": "application/json"
    }

    since = f"{start_date.isoformat()}T00:00:00Z"
    until = f"{end_date.isoformat()}T23:59:59Z"

    url = f"{OKTA_DOMAIN}/api/v1/logs"
    params = {
        "since": since,
        "until": until,
        "filter": '(eventType eq "application.user_membership.add" or eventType eq "application.user_membership.remove")',
        "limit": 1000
    }

    app_events = []
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
                print(f"❌ Error fetching app events: {response.status_code} - {response.text}")
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

                targets = event.get("target", [])
                user_id = "unknown"
                email = "unknown"
                app = "unknown"

                for t in targets:
                    if t.get("type") == "User":
                        user_id = t.get("id", "unknown")
                        email = t.get("alternateId", "unknown")
                    if t.get("type") == "AppInstance":
                        app = t.get("displayName") or t.get("alternateId") or t.get("id")

                action = event["eventType"].split(".")[-1].upper()

                # Debugging: Print parsed data for each event
               # print(f"🔎 Parsed event: action={action}, app={app}")

                app_events.append({
                    "user_id": user_id,
                    "email": email,
                    "action": f"{action}",  # Use action (ADD/REMOVE)
                    "app_name": app,  # Use role_name as app name
                    "timestamp": timestamp
                })

            # Debugging: Check if events are being added correctly
            print(f"🔎 Total app events: {len(app_events)}")

            url = response.links.get("next", {}).get("url")
            params = None  # Only for first call

        except requests.exceptions.RequestException as e:
            print(f"❌ Network error while fetching logs: {e}")
            break

    return app_events

# --------------------------------------
# Export any role/lifecycle/app/group changes to CSV
# --------------------------------------
def export_group_changes_to_csv(group_changes: List[Dict[str, str]], filename: str = "group_changes.csv") -> None:
    fieldnames = ["user_id", "email", "group_name", "action", "timestamp"]

    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for change in group_changes:
                writer.writerow(change)
        print(f"✅ CSV written to {filename}")
    except Exception as e:
        print(f"❌ Failed to write CSV: {e}")

# --------------------------------------
# Writes admin role assignment/unassignment events to a CSV file.
# This function handles events related to the assignment and unassignment of admin roles.
# --------------------------------------
def export_admin_role_changes_to_csv(role_changes: List[Dict[str, str]], filename: str = "role_changes.csv") -> None:
    """
    Writes admin role assignment/unassignment events to a CSV file.
    """
    fieldnames = ["user_id", "email", "action", "role_name", "timestamp"]

    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for change in role_changes:
                writer.writerow(change)
        print(f"✅ CSV written to {filename}")
    except Exception as e:
        print(f"❌ Failed to write CSV: {e}")

# --------------------------------------
# Writes non-admin role events (such as user lifecycle changes or app assignments) to a CSV file.
# This function handles events like user creation, suspension, or app-related changes.
# --------------------------------------
def export_role_changes_to_csv(role_changes: List[Dict[str, str]], filename: str = "role_changes.csv") -> None:
    """
    Writes lifecycle or app changes (non-admin roles) to a CSV file.
    """
    fieldnames = ["user_id", "email", "event_type", "timestamp"]

    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for change in role_changes:
                writer.writerow(change)
        print(f"✅ CSV written to {filename}")
    except Exception as e:
        print(f"❌ Failed to write CSV: {e}")

# --------------------------------------
# Export user lifecycle or app changes to CSV
# --------------------------------------
def export_user_lifecycle_to_csv(lifecycle_events: List[Dict[str, str]], filename: str = "user_lifecycle.csv") -> None:
    """
    Writes user lifecycle events (creation, suspension, deprovisioning) to a CSV file.
    """
    fieldnames = ["user_id", "email", "status", "timestamp"]

    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for event in lifecycle_events:
                writer.writerow({
                    "user_id": event.get("user_id", ""),
                    "email": event.get("email", ""),
                    "status": event.get("new_role_id", ""),  # Legacy key we're keeping for now
                    "timestamp": event.get("timestamp", "")
                })
        print(f"✅ CSV written to {filename}")
    except Exception as e:
        print(f"❌ Failed to write CSV: {e}")

# --------------------------------------
# Export app assignment changes to CSV
# --------------------------------------
def export_app_changes_to_csv(app_changes: List[Dict[str, str]], filename: str = "app_changes.csv") -> None:
    """
    Writes app assignment/revocation events to a CSV file.
    """
    fieldnames = ["user_id", "email", "action", "app_name", "timestamp"]

    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for change in app_changes:
                writer.writerow(change)
        print(f"✅ CSV written to {filename}")
    except Exception as e:
        print(f"❌ Failed to write CSV: {e}")